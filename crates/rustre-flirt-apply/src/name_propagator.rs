//! Name propagation for FLIRT matches.
//!
//! When a FLIRT match renames a function, every call-site that previously used
//! a placeholder label (`sub_XXXXXXXX`, `loc_*`, etc.) is updated to reference
//! the resolved name.  This module walks a cross-reference map and applies the
//! renaming cascade.

use std::collections::{HashSet, VecDeque};
// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function names/addresses from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;

use crate::casts::usize_to_f64;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// NameBinding
// ---------------------------------------------------------------------------

/// A single name ↔ address association produced by a FLIRT match or derived
/// from cross-reference propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameBinding {
    /// Virtual address of the function.
    pub address: u64,
    /// Resolved library name (e.g. `"strlen"`).
    pub name: String,
    /// Library that provided the match (e.g. `"msvcrt"`).
    pub lib: String,
    /// Confidence of the underlying FLIRT match (0–100).
    pub confidence: u8,
    /// Whether this binding was directly matched or inferred by propagation.
    pub is_propagated: bool,
}

impl NameBinding {
    /// Create a direct (non-propagated) binding.
    #[must_use]
    pub const fn direct(address: u64, name: String, lib: String, confidence: u8) -> Self {
        Self {
            address,
            name,
            lib,
            confidence,
            is_propagated: false,
        }
    }

    /// Create a propagated binding derived from `parent`.
    #[must_use]
    pub fn propagated(address: u64, name: String, parent: &Self) -> Self {
        Self {
            address,
            name,
            lib: parent.lib.clone(),
            confidence: parent.confidence.saturating_sub(10),
            is_propagated: true,
        }
    }

    /// Returns `true` if this binding has enough confidence to be applied.
    #[must_use]
    pub const fn is_reliable(&self) -> bool {
        self.confidence >= 50
    }
}

// ---------------------------------------------------------------------------
// PropagationResult
// ---------------------------------------------------------------------------

/// Summary of a completed propagation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationResult {
    /// Bindings that were applied (either direct or propagated).
    pub applied: Vec<NameBinding>,
    /// Addresses that were skipped because of a naming conflict.
    pub conflicts: Vec<u64>,
    /// Total number of call-site renames attempted.
    pub rename_attempts: usize,
    /// Number of successful renames.
    pub renames_applied: usize,
}

impl PropagationResult {
    /// Create an empty result.
    const fn new() -> Self {
        Self {
            applied: Vec::new(),
            conflicts: Vec::new(),
            rename_attempts: 0,
            renames_applied: 0,
        }
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: Self) {
        self.applied.extend(other.applied);
        self.conflicts.extend(other.conflicts);
        self.rename_attempts += other.rename_attempts;
        self.renames_applied += other.renames_applied;
    }

    /// Success rate as a fraction in `[0.0, 1.0]`.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.rename_attempts == 0 {
            return 1.0;
        }
        usize_to_f64(self.renames_applied) / usize_to_f64(self.rename_attempts)
    }
}

// ---------------------------------------------------------------------------
// XrefGraph
// ---------------------------------------------------------------------------

/// A directed cross-reference graph: `callers[callee] = {set of callers}`.
///
/// Used by [`NamePropagator`] to walk from a newly named function towards all
/// call-sites that may benefit from the resolved name.
#[derive(Debug, Default, Clone)]
pub struct XrefGraph {
    /// `callee_addr` → set of caller addresses.
    callers: HashMap<u64, HashSet<u64>>,
    /// `caller_addr` → set of callee addresses.
    callees: HashMap<u64, HashSet<u64>>,
}

impl XrefGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a call edge: `caller` calls `callee_addr`.
    pub fn add_edge(&mut self, caller: u64, callee_addr: u64) {
        self.callers.entry(callee_addr).or_default().insert(caller);
        self.callees.entry(caller).or_default().insert(callee_addr);
    }

    /// All callers of `callee`.
    #[must_use]
    pub fn callers_of(&self, callee: u64) -> &HashSet<u64> {
        static EMPTY: std::sync::OnceLock<HashSet<u64>> = std::sync::OnceLock::new();
        self.callers
            .get(&callee)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// All callees of `caller`.
    #[must_use]
    pub fn callees_of(&self, caller: u64) -> &HashSet<u64> {
        static EMPTY: std::sync::OnceLock<HashSet<u64>> = std::sync::OnceLock::new();
        self.callees
            .get(&caller)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// Number of unique nodes (addresses) in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        let mut nodes: HashSet<u64> = HashSet::new();
        for (&k, v) in &self.callers {
            nodes.insert(k);
            nodes.extend(v.iter().copied());
        }
        nodes.len()
    }

    /// Number of call edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.callers.values().map(HashSet::len).sum()
    }
}

// ---------------------------------------------------------------------------
// NamePropagator
// ---------------------------------------------------------------------------

/// Propagates resolved FLIRT names through a cross-reference graph.
///
/// # Algorithm
///
/// 1. Start from the set of direct [`NameBinding`]s produced by the FLIRT
///    engine.
/// 2. For each newly named function, look up all call-sites in the
///    [`XrefGraph`].
/// 3. If a call-site has exactly one callee whose name is now resolved, and
///    the call-site itself has an auto-generated placeholder name, rename the
///    call-site wrapper (BFS, bounded depth).
/// 4. Detect conflicts when two different resolved names collide at the same
///    address and record them without applying either.
pub struct NamePropagator {
    xrefs: XrefGraph,
    /// Existing names at each address (before propagation).
    existing: HashMap<u64, String>,
    /// Maximum BFS depth for propagation.
    max_depth: usize,
    /// Minimum confidence required to propagate.
    min_confidence: u8,
}

impl NamePropagator {
    /// Create a propagator with default settings (depth = 3, `min_conf` = 50).
    #[must_use]
    pub fn new(xrefs: XrefGraph) -> Self {
        Self {
            xrefs,
            existing: HashMap::new(),
            max_depth: 3,
            min_confidence: 50,
        }
    }

    /// Register an existing (pre-propagation) name for an address.
    ///
    /// Auto-generated placeholders (`sub_*`, `loc_*`, `unk_*`) are identified
    /// by the placeholder detector; any other name is treated as user-assigned
    /// and will not be overwritten.
    pub fn set_existing_name(&mut self, address: u64, name: String) {
        self.existing.insert(address, name);
    }

    /// Set the BFS depth limit (default 3).
    pub const fn set_max_depth(&mut self, depth: usize) {
        self.max_depth = depth;
    }

    /// Set the minimum confidence threshold (default 50).
    pub const fn set_min_confidence(&mut self, conf: u8) {
        self.min_confidence = conf;
    }

    /// Run propagation starting from `direct_matches`.
    ///
    /// Returns a [`PropagationResult`] describing every binding that was
    /// applied and every conflict that was detected.
    ///
    /// # Panics
    ///
    /// Panics if an internal consistency check fails (address in conflict set
    /// not found in the resolved map after insertion).
    #[must_use]
    pub fn propagate(&self, direct_matches: &[NameBinding]) -> PropagationResult {
        let mut result = PropagationResult::new();
        // resolved: address → (name, confidence) — the best resolved name so far.
        let mut resolved: HashMap<u64, (String, u8)> = HashMap::new();

        // Seed with direct matches.
        for b in direct_matches {
            if b.confidence < self.min_confidence {
                continue;
            }
            match resolved.get(&b.address) {
                None => {
                    resolved.insert(b.address, (b.name.clone(), b.confidence));
                    result.applied.push(b.clone());
                }
                Some((existing_name, existing_conf)) => {
                    if &b.name != existing_name {
                        result.conflicts.push(b.address);
                    } else if b.confidence > *existing_conf {
                        *resolved.get_mut(&b.address).unwrap() = (b.name.clone(), b.confidence);
                    }
                }
            }
        }

        // BFS over callers — propagate wrapper names.
        // Queue: (callee_addr, depth, source_binding_idx_in_result.applied).
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
        for b in &result.applied {
            queue.push_back((b.address, 0));
        }

        while let Some((callee_addr, depth)) = queue.pop_front() {
            if depth >= self.max_depth {
                continue;
            }
            let (callee_name, callee_conf) = match resolved.get(&callee_addr) {
                Some(r) => r.clone(),
                None => continue,
            };
            // Check each caller of this callee.
            for &caller_addr in self.xrefs.callers_of(callee_addr) {
                // Skip if already resolved.
                if resolved.contains_key(&caller_addr) {
                    continue;
                }
                // Skip if this caller has a user-assigned (non-placeholder) name.
                if let Some(existing) = self.existing.get(&caller_addr)
                    && !is_placeholder(existing) {
                        continue;
                    }
                // Only propagate if this caller calls exactly one named callee
                // (so we can derive a meaningful wrapper name).
                let callee_set = self.xrefs.callees_of(caller_addr);
                if callee_set
                    .iter()
                    .copied()
                    .filter(|a| resolved.contains_key(a))
                    .count() == 1 {
                    let new_name = format!("{callee_name}_wrapper");
                    let new_conf = callee_conf.saturating_sub(10);
                    if new_conf < self.min_confidence {
                        continue;
                    }
                    result.rename_attempts += 1;
                    resolved.insert(caller_addr, (new_name.clone(), new_conf));
                    let binding = NameBinding {
                        address: caller_addr,
                        name: new_name,
                        lib: String::new(),
                        confidence: new_conf,
                        is_propagated: true,
                    };
                    result.applied.push(binding);
                    result.renames_applied += 1;
                    queue.push_back((caller_addr, depth + 1));
                }
            }
        }

        result
    }

    /// Apply the propagation result to `existing_names`, returning the final
    /// name map after all renames.
    #[must_use]
    pub fn apply_to_names(
        &self,
        existing_names: &HashMap<u64, String>,
        result: &PropagationResult,
    ) -> HashMap<u64, String> {
        let mut names = existing_names.clone();
        let conflict_set: HashSet<u64> = result.conflicts.iter().copied().collect();
        for b in &result.applied {
            if !conflict_set.contains(&b.address) && b.is_reliable() {
                names.insert(b.address, b.name.clone());
            }
        }
        names
    }
}

// ---------------------------------------------------------------------------
// Helper: is_placeholder
// ---------------------------------------------------------------------------

/// Returns `true` if `name` looks like an auto-generated placeholder.
///
/// Recognises patterns such as `sub_401000`, `loc_401234`, `unk_80001000`,
/// `nullsub_5`, `j_sub_401000` (IDA jump thunk).
#[must_use]
pub fn is_placeholder(name: &str) -> bool {
    let n = name.trim_start_matches("j_");
    n.starts_with("sub_")
        || n.starts_with("loc_")
        || n.starts_with("unk_")
        || n.starts_with("nullsub_")
        || n.starts_with("off_")
        || n.starts_with("asc_")
        || n.starts_with("byte_")
        || n.starts_with("word_")
        || n.starts_with("dword_")
        || n.starts_with("qword_")
}

// ---------------------------------------------------------------------------
// NameConflictResolver
// ---------------------------------------------------------------------------

/// Resolves naming conflicts when two FLIRT patterns claim the same address.
///
/// The resolver picks the "better" candidate according to a priority function:
/// 1. Higher confidence wins.
/// 2. Longer pattern (more concrete bytes) wins on a tie.
/// 3. Alphabetically earlier name wins as a final tiebreaker.
#[derive(Debug, Default)]
pub struct NameConflictResolver {
    /// Pending candidates per address.
    candidates: HashMap<u64, Vec<NameBinding>>,
}

impl NameConflictResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate binding.
    pub fn add_candidate(&mut self, binding: NameBinding) {
        self.candidates
            .entry(binding.address)
            .or_default()
            .push(binding);
    }

    /// Add all bindings from a slice.
    pub fn add_candidates(&mut self, bindings: &[NameBinding]) {
        for b in bindings {
            self.add_candidate(b.clone());
        }
    }

    /// Resolve all conflicts, returning one winning binding per address and a
    /// list of addresses where conflicts were detected.
    ///
    /// # Panics
    ///
    /// Panics if a candidate set is unexpectedly empty after a length check.
    #[must_use]
    pub fn resolve(&self) -> (Vec<NameBinding>, Vec<u64>) {
        let mut winners = Vec::new();
        let mut conflicts = Vec::new();

        for (&addr, candidates) in &self.candidates {
            if candidates.is_empty() {
                continue;
            }
            if candidates.len() == 1 {
                winners.push(candidates[0].clone());
                continue;
            }
            // Multiple candidates — conflict detected.
            conflicts.push(addr);
            // Pick the best one by priority: highest confidence, then highest
            // implied pattern length (use confidence as proxy), then name.
            let winner = candidates
                .iter()
                .max_by(|a, b| {
                    a.confidence
                        .cmp(&b.confidence)
                        .then(a.name.len().cmp(&b.name.len()))
                        .then(b.name.cmp(&a.name)) // lexicographically earlier = better
                })
                .unwrap();
            winners.push(winner.clone());
        }

        (winners, conflicts)
    }

    /// Number of addresses with more than one candidate.
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.candidates
            .values()
            .filter(|v| v.len() > 1)
            .count()
    }

    /// Total number of candidates registered.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.values().map(Vec::len).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_binding(addr: u64, name: &str, conf: u8) -> NameBinding {
        NameBinding::direct(addr, name.to_string(), "lib".to_string(), conf)
    }

    #[test]
    fn test_is_placeholder_sub() {
        assert!(is_placeholder("sub_401000"));
    }

    #[test]
    fn test_is_placeholder_loc() {
        assert!(is_placeholder("loc_4020ab"));
    }

    #[test]
    fn test_is_placeholder_j_sub() {
        assert!(is_placeholder("j_sub_401234"));
    }

    #[test]
    fn test_not_placeholder() {
        assert!(!is_placeholder("strlen"));
        assert!(!is_placeholder("WinMain"));
    }

    #[test]
    fn test_name_binding_direct() {
        let b = make_binding(0x1000, "strlen", 90);
        assert!(!b.is_propagated);
        assert!(b.is_reliable());
    }

    #[test]
    fn test_name_binding_propagated() {
        let parent = make_binding(0x1000, "strlen", 80);
        let p = NameBinding::propagated(0x2000, "strlen_wrapper".to_string(), &parent);
        assert!(p.is_propagated);
        assert_eq!(p.confidence, 70);
    }

    #[test]
    fn test_propagation_result_merge() {
        let mut r1 = PropagationResult::new();
        r1.renames_applied = 3;
        r1.rename_attempts = 5;
        let mut r2 = PropagationResult::new();
        r2.renames_applied = 2;
        r2.rename_attempts = 2;
        r1.merge(r2);
        assert_eq!(r1.renames_applied, 5);
        assert_eq!(r1.rename_attempts, 7);
    }

    #[test]
    fn test_propagation_result_success_rate() {
        let mut r = PropagationResult::new();
        r.rename_attempts = 4;
        r.renames_applied = 3;
        assert!((r.success_rate() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_xref_graph_add_edge() {
        let mut g = XrefGraph::new();
        g.add_edge(0x2000, 0x1000);
        assert!(g.callers_of(0x1000).contains(&0x2000));
        assert!(g.callees_of(0x2000).contains(&0x1000));
    }

    #[test]
    fn test_xref_graph_edge_count() {
        let mut g = XrefGraph::new();
        g.add_edge(0x2000, 0x1000);
        g.add_edge(0x3000, 0x1000);
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn test_propagator_no_xrefs() {
        let g = XrefGraph::new();
        let prop = NamePropagator::new(g);
        let matches = vec![make_binding(0x1000, "strlen", 90)];
        let result = prop.propagate(&matches);
        assert_eq!(result.applied.len(), 1);
        assert_eq!(result.renames_applied, 0);
    }

    #[test]
    fn test_propagator_wraps_caller() {
        // 0x2000 calls 0x1000 (and only 0x1000).
        let mut g = XrefGraph::new();
        g.add_edge(0x2000, 0x1000);

        let mut prop = NamePropagator::new(g);
        prop.set_existing_name(0x2000, "sub_2000".to_string());

        let matches = vec![make_binding(0x1000, "strlen", 90)];
        let result = prop.propagate(&matches);
        assert!(result.applied.iter().any(|b| b.address == 0x2000));
        assert_eq!(result.renames_applied, 1);
    }

    #[test]
    fn test_propagator_skips_user_named() {
        let mut g = XrefGraph::new();
        g.add_edge(0x2000, 0x1000);
        let mut prop = NamePropagator::new(g);
        prop.set_existing_name(0x2000, "MyFunction".to_string()); // not a placeholder
        let matches = vec![make_binding(0x1000, "strlen", 90)];
        let result = prop.propagate(&matches);
        // MyFunction should not be renamed.
        assert!(!result.applied.iter().any(|b| b.address == 0x2000));
    }

    #[test]
    fn test_conflict_resolver_single() {
        let mut r = NameConflictResolver::new();
        r.add_candidate(make_binding(0x1000, "strlen", 80));
        let (winners, conflicts) = r.resolve();
        assert_eq!(winners.len(), 1);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_conflict_resolver_picks_higher_confidence() {
        let mut r = NameConflictResolver::new();
        r.add_candidate(make_binding(0x1000, "strlenA", 60));
        r.add_candidate(make_binding(0x1000, "strlenB", 85));
        let (winners, conflicts) = r.resolve();
        assert_eq!(conflicts, vec![0x1000]);
        assert_eq!(winners[0].name, "strlenB");
    }

    #[test]
    fn test_apply_to_names() {
        let g = XrefGraph::new();
        let prop = NamePropagator::new(g);
        let mut existing = HashMap::new();
        existing.insert(0x1000u64, "sub_1000".to_string());
        let matches = vec![make_binding(0x1000, "strlen", 90)];
        let result = prop.propagate(&matches);
        let final_names = prop.apply_to_names(&existing, &result);
        assert_eq!(final_names[&0x1000], "strlen");
    }

    #[test]
    fn test_xref_graph_node_count() {
        let mut g = XrefGraph::new();
        g.add_edge(0xA000, 0xB000);
        g.add_edge(0xC000, 0xB000);
        // nodes: A000, B000, C000
        assert_eq!(g.node_count(), 3);
    }
}
