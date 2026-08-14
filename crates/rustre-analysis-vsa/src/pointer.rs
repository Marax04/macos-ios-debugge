//! Pointer analysis via VSA.
//!
//! This module extends the core VSA with:
//! * `PointerRegion` — abstract regions representing heap, stack, globals, etc.
//! * `AbstractPointer` — a value-set coupled with a set of possible base regions.
//! * `PointerEnvironment` — maps abstract variables to `AbstractPointer`s.
//! * `PointsToSet` — the result of a whole-program points-to analysis.
//! * Transfer functions for pointer arithmetic, loads, and stores.
//! * Widening operators for pointer sets.

use crate::{ValueSet, VsaError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// PointerRegion
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract memory region that a pointer may point into.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PointerRegion {
    /// The global data section (static variables, GOT, etc.).
    Global(u64),
    /// The call stack of a specific function (identified by entry address).
    Stack(u64),
    /// A heap allocation site (identified by the allocation call address).
    Heap(u64),
    /// A memory-mapped I/O region at a fixed base.
    Mmio(u64),
    /// A null pointer.
    Null,
    /// Any region not otherwise classified.
    Unknown,
}

impl std::fmt::Display for PointerRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global(base) => write!(f, "global({base:#x})"),
            Self::Stack(fn_addr) => write!(f, "stack(fn={fn_addr:#x})"),
            Self::Heap(site) => write!(f, "heap(site={site:#x})"),
            Self::Mmio(base) => write!(f, "mmio({base:#x})"),
            Self::Null => write!(f, "null"),
            Self::Unknown => write!(f, "?"),
        }
    }
}

impl PointerRegion {
    /// Returns `true` if dereferencing a pointer into this region is always safe
    /// (i.e. the region is not null and not unknown).
    #[must_use]
    pub const fn is_safe_to_deref(&self) -> bool {
        !matches!(self, Self::Null | Self::Unknown)
    }

    /// Returns `true` if this region represents a null pointer.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AbstractPointer
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract pointer: a set of possible base regions plus a byte offset.
///
/// The offset is represented as a `ValueSet` (the number of bytes from the
/// base of the region).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbstractPointer {
    /// The set of memory regions this pointer may point into.
    pub regions: HashSet<PointerRegion>,
    /// Byte offset within the region.
    pub offset: ValueSet,
}

impl AbstractPointer {
    /// Create a pointer to a specific region with a known offset.
    #[must_use]
    pub fn exact(region: PointerRegion, offset: u64) -> Self {
        let mut regions = HashSet::new();
        regions.insert(region);
        Self {
            regions,
            offset: ValueSet::singleton(offset),
        }
    }

    /// Create a null pointer.
    #[must_use]
    pub fn null() -> Self {
        Self::exact(PointerRegion::Null, 0)
    }

    /// Create a completely unknown pointer.
    #[must_use]
    pub fn unknown() -> Self {
        let mut regions = HashSet::new();
        regions.insert(PointerRegion::Unknown);
        Self {
            regions,
            offset: ValueSet::Top,
        }
    }

    /// Join two abstract pointers (union of regions, join of offsets).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut regions = self.regions.clone();
        regions.extend(other.regions.iter().cloned());
        Self {
            regions,
            offset: self.offset.join(&other.offset),
        }
    }

    /// Add a constant byte offset to this pointer.
    #[must_use]
    pub fn offset_by(&self, delta: &ValueSet) -> Self {
        Self {
            regions: self.regions.clone(),
            offset: self.offset.add(delta),
        }
    }

    /// Returns `true` if this pointer may be null.
    #[must_use]
    pub fn may_be_null(&self) -> bool {
        self.regions.contains(&PointerRegion::Null)
    }

    /// Returns `true` if this pointer is definitely safe to dereference.
    #[must_use]
    pub fn is_definitely_safe(&self) -> bool {
        !self.may_be_null() && !self.regions.contains(&PointerRegion::Unknown)
    }

    /// Whether this pointer points into exactly one region.
    #[must_use]
    pub fn is_precise(&self) -> bool {
        self.regions.len() == 1
    }

    /// Number of possible target regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerEnvironment
// ─────────────────────────────────────────────────────────────────────────────

/// Maps abstract variable names to their `AbstractPointer` interpretations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PointerEnvironment {
    map: HashMap<String, AbstractPointer>,
}

impl PointerEnvironment {
    /// Create an empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `var` to `ptr`.
    pub fn set(&mut self, var: impl Into<String>, ptr: AbstractPointer) {
        self.map.insert(var.into(), ptr);
    }

    /// Look up `var`.  Returns an unknown pointer if the variable is unbound.
    #[must_use]
    pub fn get(&self, var: &str) -> AbstractPointer {
        self.map
            .get(var)
            .cloned()
            .unwrap_or_else(AbstractPointer::unknown)
    }

    /// Merge two environments by joining each variable's pointer.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (var, ptr) in &other.map {
            let joined = result.get(var).join(ptr);
            result.set(var.clone(), joined);
        }
        result
    }

    /// Number of tracked variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if no variables are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointsToSet
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a flow-insensitive points-to analysis over a complete
/// program, computed from per-block `PointerEnvironment`s.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PointsToSet {
    /// Maps each variable to the set of regions it may point to across all
    /// program points.
    pub points_to: HashMap<String, HashSet<PointerRegion>>,
}

impl PointsToSet {
    /// Build a `PointsToSet` from a slice of per-block `PointerEnvironment`s.
    #[must_use]
    pub fn from_environments(envs: &[PointerEnvironment]) -> Self {
        let mut pts: HashMap<String, HashSet<PointerRegion>> = HashMap::new();
        for env in envs {
            for (var, ptr) in &env.map {
                pts.entry(var.clone())
                    .or_default()
                    .extend(ptr.regions.iter().cloned());
            }
        }
        Self { points_to: pts }
    }

    /// Get the set of regions variable `var` may point to.
    #[must_use]
    pub fn regions_of(&self, var: &str) -> &HashSet<PointerRegion> {
        static EMPTY: std::sync::OnceLock<HashSet<PointerRegion>> = std::sync::OnceLock::new();
        self.points_to
            .get(var)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }

    /// Number of distinct variables in the points-to set.
    #[must_use]
    pub fn variable_count(&self) -> usize {
        self.points_to.len()
    }

    /// All variables that may point to `region`.
    #[must_use]
    pub fn aliases_of(&self, region: &PointerRegion) -> Vec<&str> {
        self.points_to
            .iter()
            .filter(|(_, regions)| regions.contains(region))
            .map(|(var, _)| var.as_str())
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Widening operators
// ─────────────────────────────────────────────────────────────────────────────

/// Widen two consecutive value-sets in a fixpoint loop to guarantee termination.
///
/// * If `prev` is `Bottom`, returns `next`.
/// * If both are `Range` with the same stride, expands the bounds toward ±∞.
/// * Otherwise falls back to `ValueSet::Top`.
///
/// # Panics
///
/// Panics if both `prev` and `next` are `Concrete` empty sets (should not occur in practice).
#[must_use]
pub fn widen(prev: &ValueSet, next: &ValueSet) -> ValueSet {
    match (prev, next) {
        (ValueSet::Bottom, _) => next.clone(),
        (_, ValueSet::Bottom) => prev.clone(),
        (ValueSet::Top, _) | (_, ValueSet::Top) => ValueSet::Top,
        (ValueSet::Concrete(a), ValueSet::Concrete(b)) => {
            // If the sets are identical, no change.
            if a == b {
                return ValueSet::Concrete(a.clone());
            }
            // Concrete → widen to Range.
            let all: std::collections::BTreeSet<u64> = a.iter().chain(b.iter()).copied().collect();
            let lo = *all.iter().next().unwrap();
            let hi = *all.iter().next_back().unwrap();
            ValueSet::Range { lo, hi, stride: 1 }
        }
        (
            ValueSet::Range {
                lo: lo1,
                hi: hi1,
                stride: s1,
            },
            ValueSet::Range {
                lo: lo2,
                hi: hi2,
                stride: s2,
            },
        ) => {
            let lo = if *lo2 < *lo1 { 0 } else { *lo1 };
            let hi = if *hi2 > *hi1 { u64::MAX } else { *hi1 };
            // The stride must also absorb the OFFSET between the two lower
            // bounds. `gcd(s1, s2)` alone keeps the residue class of the
            // retained `lo`, so members of the other operand that sit in a
            // different class are silently dropped and the "widened" set is not
            // an upper bound of its inputs at all — e.g. widening {0,2,…,10}
            // with {1,3,…,11} lost every odd value.
            let off = lo1.abs_diff(*lo2);
            let stride = crate::gcd(crate::gcd(*s1, *s2), off);
            ValueSet::Range { lo, hi, stride }
        }
        // Mixed Concrete / Range.
        _ => {
            let j = prev.join(next);
            match j {
                ValueSet::Range { lo, hi, stride } => ValueSet::Range { lo, hi, stride },
                _ => ValueSet::Top,
            }
        }
    }
}

/// Widen two `PointerEnvironment`s.
#[must_use]
pub fn widen_envs(prev: &PointerEnvironment, next: &PointerEnvironment) -> PointerEnvironment {
    let mut result = PointerEnvironment::new();
    let all_vars: HashSet<&str> = prev
        .map
        .keys()
        .chain(next.map.keys())
        .map(String::as_str)
        .collect();
    for var in all_vars {
        let p = prev.get(var);
        let n = next.get(var);
        let widened_offset = widen(&p.offset, &n.offset);
        let mut regions = p.regions.clone();
        regions.extend(n.regions.iter().cloned());
        result.set(
            var,
            AbstractPointer {
                regions,
                offset: widened_offset,
            },
        );
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Pointer transfer functions
// ─────────────────────────────────────────────────────────────────────────────

/// Abstract pointer-arithmetic transfer function for `ptr + offset`.
#[must_use]
pub fn ptr_add(ptr: &AbstractPointer, offset: &ValueSet) -> AbstractPointer {
    ptr.offset_by(offset)
}

/// Abstract pointer-arithmetic transfer function for `ptr - offset`.
#[must_use]
pub fn ptr_sub(ptr: &AbstractPointer, offset: &ValueSet) -> AbstractPointer {
    ptr.offset_by(&crate::ValueSet::singleton(0).sub(offset))
}

/// Abstract pointer comparison: check if two pointers may alias.
#[must_use]
pub fn may_alias(a: &AbstractPointer, b: &AbstractPointer) -> bool {
    // Two pointers may alias if they share at least one region.
    a.regions.intersection(&b.regions).next().is_some()
}

/// Abstract pointer comparison: check if two pointers must alias.
#[must_use]
pub fn must_alias(a: &AbstractPointer, b: &AbstractPointer) -> bool {
    a.regions.len() == 1 && b.regions.len() == 1 && a.regions == b.regions && a.offset == b.offset
}

// ─────────────────────────────────────────────────────────────────────────────
// PointerAnalysisResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of running pointer analysis over a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointerAnalysisResult {
    /// Per-block pointer environments.
    pub environments: Vec<PointerEnvironment>,
    /// Aggregate points-to set.
    pub points_to: PointsToSet,
    /// Number of iterations until fixpoint.
    pub iterations: usize,
    /// Whether the analysis converged within the budget.
    pub converged: bool,
}

/// Configuration for pointer analysis.
#[derive(Debug, Clone)]
pub struct PointerAnalysisConfig {
    /// Maximum number of worklist iterations.
    pub max_iterations: usize,
    /// Widen after this many iterations to ensure termination.
    pub widen_threshold: usize,
}

impl Default for PointerAnalysisConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10_000,
            widen_threshold: 5,
        }
    }
}

/// Instruction for a simplified pointer-only IL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PtrInstr {
    /// `dst = &region[offset]` — address-of.
    AddrOf {
        dst: String,
        region: PointerRegion,
        offset: u64,
    },
    /// `dst = src` — copy a pointer.
    Copy { dst: String, src: String },
    /// `dst = *src` — load through a pointer.
    Load { dst: String, src: String },
    /// `*dst = src` — store through a pointer.
    Store { dst: String, src: String },
    /// `dst = src + delta` — pointer arithmetic.
    PtrAdd {
        dst: String,
        src: String,
        delta: ValueSet,
    },
    /// `dst = Φ(src1, src2, …)` — phi node.
    Phi { dst: String, srcs: Vec<String> },
}

/// A basic block for pointer analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtrBlock {
    pub id: usize,
    pub instrs: Vec<PtrInstr>,
}

/// A CFG for pointer analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtrCfg {
    pub blocks: Vec<PtrBlock>,
    pub successors: Vec<Vec<usize>>,
    pub entry: usize,
}

/// Run a flow-sensitive pointer analysis over `cfg`.
///
/// # Errors
/// Returns [`VsaError::EmptyProgram`] if `cfg` has no blocks, or
/// [`VsaError::NoConvergence`] if the iteration budget is exhausted.
pub fn run_pointer_analysis(
    cfg: &PtrCfg,
    config: &PointerAnalysisConfig,
) -> Result<PointerAnalysisResult, VsaError> {
    if cfg.blocks.is_empty() {
        return Err(VsaError::EmptyProgram);
    }
    let n = cfg.blocks.len();
    let mut envs: Vec<PointerEnvironment> = vec![PointerEnvironment::new(); n];

    // Pointer memory: for each region-offset pair, what value might be stored.
    let mut mem: HashMap<(String, u64), AbstractPointer> = HashMap::new();

    let mut worklist: std::collections::VecDeque<usize> = (0..n).collect();
    let mut in_wl = vec![true; n];
    let mut iters = 0usize;

    while let Some(bid) = worklist.pop_front() {
        in_wl[bid] = false;
        iters += 1;
        if iters > config.max_iterations {
            // Build points_to from the partial environments collected so far
            // so callers that ignore `converged` still get a sound over-approximation
            // rather than a misleadingly empty set (state-machine-on-error fix).
            let pts = PointsToSet::from_environments(&envs);
            return Ok(PointerAnalysisResult {
                environments: envs,
                points_to: pts,
                iterations: iters,
                converged: false,
            });
        }

        let new_env = transfer_ptr_block(&cfg.blocks[bid], &envs[bid], &mut mem);

        // Apply widening if we've been iterating a while.
        let new_env = if iters > config.widen_threshold {
            widen_envs(&envs[bid], &new_env)
        } else {
            new_env
        };

        // Check if anything changed.
        if new_env.map == envs[bid].map {
            continue;
        }
        envs[bid] = new_env.clone();

        for &succ in &cfg.successors[bid] {
            if succ >= n {
                continue;
            }
            let joined = envs[succ].join(&new_env);
            if joined.map != envs[succ].map {
                envs[succ] = joined;
                if !in_wl[succ] {
                    in_wl[succ] = true;
                    worklist.push_back(succ);
                }
            }
        }
    }

    let pts = PointsToSet::from_environments(&envs);
    Ok(PointerAnalysisResult {
        environments: envs,
        points_to: pts,
        iterations: iters,
        converged: true,
    })
}

fn transfer_ptr_block(
    block: &PtrBlock,
    env: &PointerEnvironment,
    mem: &mut HashMap<(String, u64), AbstractPointer>,
) -> PointerEnvironment {
    let mut e = env.clone();
    for instr in &block.instrs {
        match instr {
            PtrInstr::AddrOf {
                dst,
                region,
                offset,
            } => {
                e.set(dst.clone(), AbstractPointer::exact(region.clone(), *offset));
            }
            PtrInstr::Copy { dst, src } => {
                let p = e.get(src);
                e.set(dst.clone(), p);
            }
            PtrInstr::Load { dst, src } => {
                let src_ptr = e.get(src);
                // Look up in memory model.
                let mut result = AbstractPointer::unknown();
                for region in &src_ptr.regions {
                    if let Some(vals) = src_ptr.offset.concretize(16) {
                        for off in vals {
                            let key = (format!("{region}"), off);
                            if let Some(v) = mem.get(&key) {
                                result = result.join(v);
                            }
                        }
                    }
                }
                e.set(dst.clone(), result);
            }
            PtrInstr::Store { dst, src } => {
                let dst_ptr = e.get(dst);
                let src_val = e.get(src);
                for region in &dst_ptr.regions {
                    if let Some(vals) = dst_ptr.offset.concretize(16) {
                        for off in vals {
                            let key = (format!("{region}"), off);
                            let entry = mem.entry(key).or_insert_with(AbstractPointer::unknown);
                            *entry = entry.join(&src_val);
                        }
                    } else {
                        // Unknown offset: strong-update impossible, do nothing.
                    }
                }
            }
            PtrInstr::PtrAdd { dst, src, delta } => {
                let p = e.get(src);
                e.set(dst.clone(), ptr_add(&p, delta));
            }
            PtrInstr::Phi { dst, srcs } => {
                let mut joined = AbstractPointer::null();
                joined.regions.clear();
                joined.offset = ValueSet::Bottom;
                for src in srcs {
                    joined = joined.join(&e.get(src));
                }
                e.set(dst.clone(), joined);
            }
        }
    }
    e
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_region_display() {
        assert_eq!(PointerRegion::Global(0x1000).to_string(), "global(0x1000)");
        assert_eq!(PointerRegion::Null.to_string(), "null");
        assert_eq!(PointerRegion::Unknown.to_string(), "?");
    }

    #[test]
    fn test_pointer_region_is_safe() {
        assert!(PointerRegion::Global(0).is_safe_to_deref());
        assert!(!PointerRegion::Null.is_safe_to_deref());
        assert!(!PointerRegion::Unknown.is_safe_to_deref());
    }

    #[test]
    fn test_abstract_pointer_null() {
        let p = AbstractPointer::null();
        assert!(p.may_be_null());
        assert!(!p.is_definitely_safe());
    }

    #[test]
    fn test_abstract_pointer_exact() {
        let p = AbstractPointer::exact(PointerRegion::Stack(0x400), 8);
        assert!(!p.may_be_null());
        assert!(p.is_definitely_safe());
        assert!(p.is_precise());
    }

    #[test]
    fn test_abstract_pointer_join() {
        let p1 = AbstractPointer::exact(PointerRegion::Heap(0x100), 0);
        let p2 = AbstractPointer::exact(PointerRegion::Stack(0x200), 0);
        let joined = p1.join(&p2);
        assert_eq!(joined.region_count(), 2);
    }

    #[test]
    fn test_abstract_pointer_offset_by() {
        let p = AbstractPointer::exact(PointerRegion::Global(0x1000), 0);
        let shifted = p.offset_by(&ValueSet::singleton(8));
        match &shifted.offset {
            ValueSet::Concrete(v) => assert_eq!(v[0], 8),
            _ => panic!("expected Concrete"),
        }
    }

    #[test]
    fn test_pointer_env_get_unknown() {
        let env = PointerEnvironment::new();
        let p = env.get("no_such_var");
        assert!(!p.is_definitely_safe()); // Unknown
    }

    #[test]
    fn test_pointer_env_set_get() {
        let mut env = PointerEnvironment::new();
        env.set("x", AbstractPointer::exact(PointerRegion::Heap(0x100), 0));
        let p = env.get("x");
        assert!(p.regions.contains(&PointerRegion::Heap(0x100)));
    }

    #[test]
    fn test_pointer_env_join() {
        let mut e1 = PointerEnvironment::new();
        e1.set("p", AbstractPointer::exact(PointerRegion::Global(0), 0));
        let mut e2 = PointerEnvironment::new();
        e2.set("p", AbstractPointer::exact(PointerRegion::Stack(0), 0));
        let joined = e1.join(&e2);
        assert_eq!(joined.get("p").region_count(), 2);
    }

    #[test]
    fn test_points_to_set_from_environments() {
        let mut e = PointerEnvironment::new();
        e.set("a", AbstractPointer::exact(PointerRegion::Heap(0x10), 0));
        let pts = PointsToSet::from_environments(&[e]);
        assert!(pts.regions_of("a").contains(&PointerRegion::Heap(0x10)));
    }

    #[test]
    fn test_points_to_aliases() {
        let mut e = PointerEnvironment::new();
        e.set("x", AbstractPointer::exact(PointerRegion::Global(0), 0));
        e.set("y", AbstractPointer::exact(PointerRegion::Global(0), 4));
        let pts = PointsToSet::from_environments(&[e]);
        let aliases = pts.aliases_of(&PointerRegion::Global(0));
        assert!(aliases.contains(&"x"));
        assert!(aliases.contains(&"y"));
    }

    #[test]
    fn test_widen_bottom_returns_next() {
        let next = ValueSet::singleton(5);
        assert_eq!(widen(&ValueSet::Bottom, &next), next);
    }

    #[test]
    fn test_widen_identical_range_unchanged() {
        let r = ValueSet::Range {
            lo: 0,
            hi: 10,
            stride: 2,
        };
        let widened = widen(&r, &r);
        assert_eq!(widened, r);
    }

    #[test]
    fn test_widen_expanding_hi() {
        let prev = ValueSet::Range {
            lo: 0,
            hi: 10,
            stride: 1,
        };
        let next = ValueSet::Range {
            lo: 0,
            hi: 20,
            stride: 1,
        };
        let widened = widen(&prev, &next);
        match widened {
            ValueSet::Range { hi, .. } => assert_eq!(hi, u64::MAX),
            _ => panic!("expected Range"),
        }
    }

    #[test]
    fn test_may_alias_shared_region() {
        let p1 = AbstractPointer::exact(PointerRegion::Heap(0x100), 0);
        let p2 = AbstractPointer::exact(PointerRegion::Heap(0x100), 8);
        assert!(may_alias(&p1, &p2));
    }

    #[test]
    fn test_may_alias_disjoint_regions() {
        let p1 = AbstractPointer::exact(PointerRegion::Heap(0x100), 0);
        let p2 = AbstractPointer::exact(PointerRegion::Stack(0x200), 0);
        assert!(!may_alias(&p1, &p2));
    }

    #[test]
    fn test_must_alias_identical() {
        let p1 = AbstractPointer::exact(PointerRegion::Heap(0x100), 0);
        let p2 = AbstractPointer::exact(PointerRegion::Heap(0x100), 0);
        assert!(must_alias(&p1, &p2));
    }

    #[test]
    fn test_must_alias_different_offset() {
        let p1 = AbstractPointer::exact(PointerRegion::Heap(0x100), 0);
        let p2 = AbstractPointer::exact(PointerRegion::Heap(0x100), 8);
        assert!(!must_alias(&p1, &p2));
    }

    #[test]
    fn test_ptr_add_delta() {
        let p = AbstractPointer::exact(PointerRegion::Global(0x1000), 0);
        let result = ptr_add(&p, &ValueSet::singleton(4));
        match &result.offset {
            ValueSet::Concrete(v) => assert_eq!(v[0], 4),
            _ => panic!(),
        }
    }

    #[test]
    fn test_run_pointer_analysis_addr_of_copy() {
        let cfg = PtrCfg {
            blocks: vec![PtrBlock {
                id: 0,
                instrs: vec![
                    PtrInstr::AddrOf {
                        dst: "p".into(),
                        region: PointerRegion::Global(0x1000),
                        offset: 0,
                    },
                    PtrInstr::Copy {
                        dst: "q".into(),
                        src: "p".into(),
                    },
                ],
            }],
            successors: vec![vec![]],
            entry: 0,
        };
        let cfg_ref = &PointerAnalysisConfig::default();
        let result = run_pointer_analysis(&cfg, cfg_ref).unwrap();
        assert!(result.converged);
        let env = &result.environments[0];
        assert!(
            env.get("p")
                .regions
                .contains(&PointerRegion::Global(0x1000))
        );
        assert!(
            env.get("q")
                .regions
                .contains(&PointerRegion::Global(0x1000))
        );
    }

    #[test]
    fn test_run_pointer_analysis_empty_returns_error() {
        let cfg = PtrCfg {
            blocks: vec![],
            successors: vec![],
            entry: 0,
        };
        let result = run_pointer_analysis(&cfg, &PointerAnalysisConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_widen_envs() {
        let mut e1 = PointerEnvironment::new();
        e1.set("x", AbstractPointer::exact(PointerRegion::Heap(0), 0));
        let mut e2 = PointerEnvironment::new();
        e2.set("x", AbstractPointer::exact(PointerRegion::Stack(0), 0));
        let w = widen_envs(&e1, &e2);
        assert_eq!(w.get("x").region_count(), 2);
    }

    // ── Property test: points-to region soundness ───────────────────────────
    //
    // For straight-line pointer programs (AddrOf / Copy / PtrAdd), the analysis
    // result must contain every region a concrete execution could assign to each
    // variable. We build a random block, simulate it with an independent
    // reference tracking var → region-set, and assert the analysis over-
    // approximates the reference (no genuine points-to target dropped).
    mod prop {
        use super::*;
        use std::collections::{HashMap, HashSet};

        use crate::test_prng::Xs as Rng;

        #[test]
        fn prop_straightline_region_soundness() {
            let mut rng = Rng::new(0x71);
            for _ in 0..5_000 {
                let nvars = 3 + rng.below(4);
                let var = |i: u64| format!("v{i}");
                let mut instrs = Vec::new();
                // Independent reference: variable → set of regions it may hold.
                let mut refm: HashMap<String, HashSet<PointerRegion>> = HashMap::new();
                let ninstr = 3 + rng.below(8);
                for _ in 0..ninstr {
                    let dst = var(rng.below(nvars));
                    match rng.below(3) {
                        0 => {
                            let region = PointerRegion::Global(0x1000 + rng.below(4));
                            instrs.push(PtrInstr::AddrOf {
                                dst: dst.clone(), region: region.clone(), offset: rng.below(4) * 4,
                            });
                            refm.insert(dst, HashSet::from([region]));
                        }
                        1 => {
                            let src = var(rng.below(nvars));
                            instrs.push(PtrInstr::Copy { dst: dst.clone(), src: src.clone() });
                            let s = refm.get(&src).cloned().unwrap_or_default();
                            refm.insert(dst, s);
                        }
                        _ => {
                            let src = var(rng.below(nvars));
                            instrs.push(PtrInstr::PtrAdd {
                                dst: dst.clone(), src: src.clone(),
                                delta: ValueSet::singleton(rng.below(4) * 4),
                            });
                            // PtrAdd preserves the region set (only offset moves).
                            let s = refm.get(&src).cloned().unwrap_or_default();
                            refm.insert(dst, s);
                        }
                    }
                }
                let cfg = PtrCfg {
                    blocks: vec![PtrBlock { id: 0, instrs }],
                    successors: vec![vec![]],
                    entry: 0,
                };
                let result = run_pointer_analysis(&cfg, &PointerAnalysisConfig::default()).unwrap();
                let env = &result.environments[0];
                for (v, regions) in &refm {
                    let got = &env.get(v).regions;
                    for r in regions {
                        assert!(
                            got.contains(r),
                            "points-to unsound: {v} should contain {r:?}, got {got:?}"
                        );
                    }
                }
            }
        }
    }
}
