//! MLIL alias analysis — determines which memory accesses may refer to the
//! same location (may-alias) or provably refer to different locations
//! (no-alias) within an SSA-form MLIL function.
//!
//! Implements Andersen-style points-to analysis on SSA variables, augmented
//! with stack-frame offset reasoning.

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::collections::VecDeque;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// MayAlias
// ─────────────────────────────────────────────────────────────────────────────

/// The result of an alias query between two memory accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MayAlias {
    /// The two accesses definitely refer to the same location.
    MustAlias,
    /// The two accesses may or may not refer to the same location.
    MayAlias,
    /// The two accesses cannot refer to the same location.
    NoAlias,
    /// The analysis could not determine the relationship.
    Unknown,
}

impl fmt::Display for MayAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MustAlias => write!(f, "MustAlias"),
            Self::MayAlias => write!(f, "MayAlias"),
            Self::NoAlias => write!(f, "NoAlias"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryLocation
// ─────────────────────────────────────────────────────────────────────────────

/// An abstract memory location used by the alias analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MemoryLocation {
    /// A stack slot at a specific frame offset and access size.
    StackSlot { offset: i64, size: u32 },
    /// A global variable at a fixed virtual address.
    Global { addr: u64, size: u32 },
    /// A heap allocation (malloc/new) identified by the call site.
    Heap { alloc_site: u64 },
    /// A pointer-dereference whose base is an SSA variable.
    Deref { base_var: String },
    /// A field access: base + constant offset.
    Field { base_var: String, field_offset: i64, size: u32 },
    /// Unknown / escaped memory (may alias everything).
    Unknown,
}

impl MemoryLocation {
    /// Return `true` if this is a stack location.
    #[must_use]
    pub fn is_stack(&self) -> bool {
        match self {
            Self::StackSlot { .. } => true,
            Self::Field { base_var, .. } => base_var.contains("rbp") || base_var.contains("rsp"),
            _ => false,
        }
    }

    /// Return `true` if this location may escape (i.e., may be aliased by
    /// an unknown pointer).
    #[must_use]
    pub const fn may_escape(&self) -> bool {
        matches!(self, Self::Unknown | Self::Heap { .. } | Self::Deref { .. })
    }

    /// Compute the alias relation between `self` and `other`.
    #[must_use]
    pub fn alias_with(&self, other: &Self) -> MayAlias {
        match (self, other) {
            // Same stack slot (identical offset and size) → MustAlias.
            (
                Self::StackSlot { offset: o1, size: s1 },
                Self::StackSlot { offset: o2, size: s2 },
            ) if o1 == o2 && s1 == s2 => MayAlias::MustAlias,
            // Overlapping but not identical stack slots → MayAlias.
            (
                Self::StackSlot { offset: o1, size: s1 },
                Self::StackSlot { offset: o2, size: s2 },
            ) if overlapping_intervals(*o1, i64::from(*s1), *o2, i64::from(*s2)) => MayAlias::MayAlias,
            // Two stack slots that don't overlap → NoAlias.
            (Self::StackSlot { .. }, Self::StackSlot { .. }) => MayAlias::NoAlias,
            // Different globals → NoAlias if addresses don't overlap.
            (
                Self::Global { addr: a1, size: s1 },
                Self::Global { addr: a2, size: s2 },
            ) => {
                if overlapping_intervals(*a1 as i64, i64::from(*s1), *a2 as i64, i64::from(*s2)) {
                    if a1 == a2 && s1 == s2 {
                        MayAlias::MustAlias
                    } else {
                        MayAlias::MayAlias
                    }
                } else {
                    MayAlias::NoAlias
                }
            }
            // Stack vs global → NoAlias.
            (Self::StackSlot { .. }, Self::Global { .. })
            | (Self::Global { .. }, Self::StackSlot { .. }) => MayAlias::NoAlias,
            // Different heap allocation sites → NoAlias.
            (Self::Heap { alloc_site: a1 }, Self::Heap { alloc_site: a2 }) => {
                if a1 == a2 { MayAlias::MayAlias } else { MayAlias::NoAlias }
            }
            // Unknown → MayAlias everything.
            (Self::Unknown, _) | (_, Self::Unknown) => MayAlias::MayAlias,
            // Deref of same base → MayAlias (could be same or different element).
            (Self::Deref { base_var: b1 }, Self::Deref { base_var: b2 }) => {
                if b1 == b2 { MayAlias::MayAlias } else { MayAlias::Unknown }
            }
            // Field at same base, same offset → MustAlias.
            (
                Self::Field { base_var: b1, field_offset: fo1, size: s1 },
                Self::Field { base_var: b2, field_offset: fo2, size: s2 },
            ) => {
                if b1 == b2 && fo1 == fo2 && s1 == s2 {
                    MayAlias::MustAlias
                } else if b1 == b2 {
                    if overlapping_intervals(*fo1, i64::from(*s1), *fo2, i64::from(*s2)) {
                        MayAlias::MayAlias
                    } else {
                        MayAlias::NoAlias
                    }
                } else {
                    MayAlias::Unknown
                }
            }
            _ => MayAlias::Unknown,
        }
    }
}

const fn overlapping_intervals(start1: i64, size1: i64, start2: i64, size2: i64) -> bool {
    let end1 = start1.saturating_add(size1);
    let end2 = start2.saturating_add(size2);
    start1 < end2 && start2 < end1
}

impl fmt::Display for MemoryLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackSlot { offset, size } => write!(f, "stack[{offset:+}:{size}]"),
            Self::Global { addr, size } => write!(f, "global[{addr:#x}:{size}]"),
            Self::Heap { alloc_site } => write!(f, "heap@{alloc_site:#x}"),
            Self::Deref { base_var } => write!(f, "*{base_var}"),
            Self::Field { base_var, field_offset, size } => {
                write!(f, "({base_var}+{field_offset:+})[{size}]")
            }
            Self::Unknown => write!(f, "?"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AliasSet
// ─────────────────────────────────────────────────────────────────────────────

/// A set of memory locations that are considered may-alias with each other.
#[derive(Debug, Clone)]
pub struct AliasSet {
    /// Unique ID of this alias set.
    pub id: u32,
    /// The memory locations in this set.
    pub members: Vec<MemoryLocation>,
    /// Whether this set contains an Unknown location (may alias everything).
    pub contains_unknown: bool,
}

impl AliasSet {
    /// Create a new alias set with a single member.
    #[must_use]
    pub fn singleton(id: u32, loc: MemoryLocation) -> Self {
        let contains_unknown = loc == MemoryLocation::Unknown;
        Self { id, members: vec![loc], contains_unknown }
    }

    /// Add a member to this set.
    pub fn add(&mut self, loc: MemoryLocation) {
        if loc == MemoryLocation::Unknown {
            self.contains_unknown = true;
        }
        if !self.members.contains(&loc) {
            self.members.push(loc);
        }
    }

    /// Return `true` if `loc` may alias any member of this set.
    #[must_use]
    pub fn may_alias_any(&self, loc: &MemoryLocation) -> bool {
        if self.contains_unknown {
            return true;
        }
        self.members.iter().any(|m| m.alias_with(loc) != MayAlias::NoAlias)
    }
}

impl fmt::Display for AliasSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AliasSet#{}: {{", self.id)?;
        for (i, m) in self.members.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{m}")?;
        }
        write!(f, "}}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PointsToGraph — Andersen-style
// ─────────────────────────────────────────────────────────────────────────────

/// Points-to graph: maps SSA variable names to the set of memory locations they
/// may point to.
#[derive(Debug, Default)]
struct PointsToGraph {
    /// var → set of pointed-to memory locations.
    pts: HashMap<String, HashSet<MemoryLocationId>>,
    /// Interned memory locations.
    locations: Vec<MemoryLocation>,
    /// Location → ID lookup.
    loc_ids: HashMap<String, usize>,
}

type MemoryLocationId = usize;

impl PointsToGraph {
    fn intern(&mut self, loc: MemoryLocation) -> MemoryLocationId {
        let key = loc.to_string();
        if let Some(&id) = self.loc_ids.get(&key) {
            return id;
        }
        let id = self.locations.len();
        self.locations.push(loc);
        self.loc_ids.insert(key, id);
        id
    }

    fn add_points_to(&mut self, var: &str, loc: MemoryLocation) {
        let id = self.intern(loc);
        self.pts.entry(var.to_string()).or_default().insert(id);
    }

    fn points_to(&self, var: &str) -> Vec<&MemoryLocation> {
        self.pts
            .get(var)
            .map(|ids| ids.iter().filter_map(|&id| self.locations.get(id)).collect())
            .unwrap_or_default()
    }

    fn merge(&mut self, src: &str, dst: &str) {
        let ids: Vec<usize> = self
            .pts
            .get(src)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for id in ids {
            self.pts.entry(dst.to_string()).or_default().insert(id);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilAliasStatement — minimal representation
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified MLIL statement for alias analysis.
#[derive(Debug, Clone)]
pub enum AliasStatement {
    /// `dst = &stack_slot(offset, size)`
    TakeAddress { dst: String, stack_offset: i64, size: u32 },
    /// `dst = src` — copy.
    Copy { dst: String, src: String },
    /// `dst = *src` — load.
    Load { dst: String, src: String, size: u32 },
    /// `*dst = src` — store.
    Store { dst: String, src: String, size: u32 },
    /// `dst = malloc(size)` — heap allocation.
    Alloc { dst: String, alloc_site: u64 },
    /// `dst = global_addr` — direct global reference.
    GlobalRef { dst: String, addr: u64, size: u32 },
    /// `dst = field(base, offset, size)` — struct field.
    FieldAccess { dst: String, base: String, offset: i64, size: u32 },
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilAliasAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Alias analysis engine for MLIL SSA.
#[derive(Debug)]
pub struct MlilAliasAnalysis {
    pts: PointsToGraph,
    alias_sets: Vec<AliasSet>,
    next_set_id: u32,
    /// Cache: (`loc_a`, `loc_b`) → alias result.
    cache: HashMap<(String, String), MayAlias>,
    /// All access sites: (addr, location).
    accesses: Vec<(u64, MemoryLocation)>,
    /// Sized memory events: (kind, location, `byte_size`, optional source var).
    sized_events: Vec<MemoryEvent>,
    /// FIFO of recently-loaded dst vars (uses [`VecDeque`] to keep insertion
    /// order while supporting cheap front-pops for liveness diagnostics).
    recent_loaded: VecDeque<String>,
}

/// Kind of memory event recorded during alias analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryEventKind {
    Load,
    Store,
}

/// A typed memory event captured by [`MlilAliasAnalysis`].
#[derive(Debug, Clone)]
pub struct MemoryEvent {
    pub kind: MemoryEventKind,
    pub location: MemoryLocation,
    pub byte_size: u32,
    /// Source SSA variable name (for stores), or loaded-from var (for loads).
    pub source_var: Option<String>,
}

impl MlilAliasAnalysis {
    /// Create a new alias analysis engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pts: PointsToGraph::default(),
            alias_sets: Vec::new(),
            next_set_id: 0,
            cache: HashMap::new(),
            accesses: Vec::new(),
            sized_events: Vec::new(),
            recent_loaded: VecDeque::new(),
        }
    }

    /// All sized memory events seen so far.
    #[must_use]
    pub fn sized_events(&self) -> &[MemoryEvent] {
        &self.sized_events
    }

    /// Drain the FIFO of recently-loaded destination variable names (oldest
    /// first). Returns up to `max` entries.
    pub fn drain_recent_loaded(&mut self, max: usize) -> Vec<String> {
        let mut out = Vec::with_capacity(max.min(self.recent_loaded.len()));
        while out.len() < max {
            match self.recent_loaded.pop_front() {
                Some(v) => out.push(v),
                None => break,
            }
        }
        out
    }

    /// Process a statement, updating the points-to graph.
    pub fn process_statement(&mut self, stmt: &AliasStatement) {
        match stmt {
            AliasStatement::TakeAddress { dst, stack_offset, size } => {
                let loc = MemoryLocation::StackSlot { offset: *stack_offset, size: *size };
                self.pts.add_points_to(dst, loc);
            }
            AliasStatement::Copy { dst, src } => {
                self.pts.merge(src, dst);
            }
            AliasStatement::Load { dst, src, size } => {
                // *src flows into dst: dst may point to anything *src points to.
                let locs: Vec<_> = self.pts.points_to(src).into_iter().cloned().collect();
                if locs.is_empty() {
                    self.pts.add_points_to(dst, MemoryLocation::Unknown);
                    self.sized_events.push(MemoryEvent {
                        kind: MemoryEventKind::Load,
                        location: MemoryLocation::Unknown,
                        byte_size: *size,
                        source_var: Some(src.clone()),
                    });
                } else {
                    for loc in locs {
                        let deref_loc = MemoryLocation::Deref { base_var: format!("{loc}") };
                        self.pts.add_points_to(dst, deref_loc.clone());
                        self.sized_events.push(MemoryEvent {
                            kind: MemoryEventKind::Load,
                            location: deref_loc,
                            byte_size: *size,
                            source_var: Some(src.clone()),
                        });
                    }
                }
                self.recent_loaded.push_back(dst.clone());
            }
            AliasStatement::Store { dst, src, size } => {
                // Track that dst is being written.
                let locs: Vec<_> = self.pts.points_to(dst).into_iter().cloned().collect();
                for loc in locs {
                    self.accesses.push((0, loc.clone()));
                    self.sized_events.push(MemoryEvent {
                        kind: MemoryEventKind::Store,
                        location: loc,
                        byte_size: *size,
                        source_var: Some(src.clone()),
                    });
                }
            }
            AliasStatement::Alloc { dst, alloc_site } => {
                self.pts.add_points_to(dst, MemoryLocation::Heap { alloc_site: *alloc_site });
            }
            AliasStatement::GlobalRef { dst, addr, size } => {
                self.pts.add_points_to(dst, MemoryLocation::Global { addr: *addr, size: *size });
            }
            AliasStatement::FieldAccess { dst, base, offset, size } => {
                let locs: Vec<_> = self.pts.points_to(base).into_iter().cloned().collect();
                if locs.is_empty() {
                    self.pts.add_points_to(
                        dst,
                        MemoryLocation::Field {
                            base_var: base.clone(),
                            field_offset: *offset,
                            size: *size,
                        },
                    );
                } else {
                    for base_loc in locs {
                        let field_loc = MemoryLocation::Field {
                            base_var: base_loc.to_string(),
                            field_offset: *offset,
                            size: *size,
                        };
                        self.pts.add_points_to(dst, field_loc);
                    }
                }
            }
        }
    }

    /// Record a memory access at the given address with the given location.
    pub fn record_access(&mut self, addr: u64, loc: MemoryLocation) {
        self.accesses.push((addr, loc));
    }

    /// Query whether two SSA variable names may alias.
    #[must_use]
    pub fn query_var_alias(&mut self, a: &str, b: &str) -> MayAlias {
        let cache_key = if a <= b {
            (a.to_string(), b.to_string())
        } else {
            (b.to_string(), a.to_string())
        };
        if let Some(&cached) = self.cache.get(&cache_key) {
            return cached;
        }

        let pts_a: Vec<_> = self.pts.points_to(a).into_iter().cloned().collect();
        let pts_b: Vec<_> = self.pts.points_to(b).into_iter().cloned().collect();

        let result = if pts_a.is_empty() || pts_b.is_empty() {
            MayAlias::Unknown
        } else {
            let mut worst = MayAlias::NoAlias;
            'outer: for la in &pts_a {
                for lb in &pts_b {
                    let r = la.alias_with(lb);
                    match r {
                        MayAlias::MustAlias => { worst = MayAlias::MustAlias; break 'outer; }
                        MayAlias::MayAlias => { worst = MayAlias::MayAlias; }
                        MayAlias::Unknown => { if worst == MayAlias::NoAlias { worst = MayAlias::Unknown; } }
                        MayAlias::NoAlias => {}
                    }
                }
            }
            worst
        };

        self.cache.insert(cache_key, result);
        result
    }

    /// Query the alias relation between two memory locations directly.
    #[must_use]
    pub fn query_loc_alias(&self, a: &MemoryLocation, b: &MemoryLocation) -> MayAlias {
        a.alias_with(b)
    }

    /// Run a full analysis on a sequence of statements.
    pub fn analyze_aliases(&mut self, stmts: &[AliasStatement]) {
        for stmt in stmts {
            self.process_statement(stmt);
        }
    }

    /// Build alias sets by grouping accesses that may alias.
    pub fn build_alias_sets(&mut self) {
        self.alias_sets.clear();
        let accesses: Vec<_> = self.accesses.clone();

        for (_, loc) in accesses {
            let existing = self.alias_sets.iter_mut().find(|set| set.may_alias_any(&loc));
            if let Some(set) = existing {
                set.add(loc);
            } else {
                let id = self.next_set_id;
                self.next_set_id += 1;
                self.alias_sets.push(AliasSet::singleton(id, loc));
            }
        }
    }

    /// Return all alias sets.
    #[must_use]
    pub fn alias_sets(&self) -> &[AliasSet] {
        &self.alias_sets
    }

    /// Return the points-to set for a variable.
    #[must_use]
    pub fn points_to(&self, var: &str) -> Vec<&MemoryLocation> {
        self.pts.points_to(var)
    }

    /// Return `true` if the analysis concludes that `a` and `b` cannot alias.
    #[must_use]
    pub fn no_alias(&mut self, a: &str, b: &str) -> bool {
        self.query_var_alias(a, b) == MayAlias::NoAlias
    }

    /// Return the number of distinct points-to entries.
    #[must_use]
    pub fn pts_entry_count(&self) -> usize {
        self.pts.pts.values().map(|s| s.len()).sum()
    }

    /// Reset all analysis state.
    pub fn reset(&mut self) {
        self.pts = PointsToGraph::default();
        self.alias_sets.clear();
        self.cache.clear();
        self.accesses.clear();
    }
}

impl Default for MlilAliasAnalysis {
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

    #[test]
    fn stack_slots_no_overlap() {
        let a = MemoryLocation::StackSlot { offset: -8, size: 4 };
        let b = MemoryLocation::StackSlot { offset: -16, size: 4 };
        assert_eq!(a.alias_with(&b), MayAlias::NoAlias);
    }

    #[test]
    fn stack_slots_must_alias() {
        let a = MemoryLocation::StackSlot { offset: -8, size: 8 };
        let b = MemoryLocation::StackSlot { offset: -8, size: 8 };
        assert_eq!(a.alias_with(&b), MayAlias::MustAlias);
    }

    #[test]
    fn stack_vs_global_no_alias() {
        let a = MemoryLocation::StackSlot { offset: -8, size: 8 };
        let b = MemoryLocation::Global { addr: 0x4000, size: 8 };
        assert_eq!(a.alias_with(&b), MayAlias::NoAlias);
    }

    #[test]
    fn points_to_stack() {
        let mut analysis = MlilAliasAnalysis::new();
        let stmt = AliasStatement::TakeAddress {
            dst: "p".into(),
            stack_offset: -8,
            size: 8,
        };
        analysis.process_statement(&stmt);
        let pts = analysis.points_to("p");
        assert_eq!(pts.len(), 1);
        assert!(matches!(pts[0], MemoryLocation::StackSlot { offset: -8, size: 8 }));
    }

    #[test]
    fn copy_propagates_pts() {
        let mut analysis = MlilAliasAnalysis::new();
        analysis.process_statement(&AliasStatement::TakeAddress {
            dst: "p".into(),
            stack_offset: -8,
            size: 8,
        });
        analysis.process_statement(&AliasStatement::Copy {
            dst: "q".into(),
            src: "p".into(),
        });
        assert_eq!(analysis.points_to("q").len(), 1);
    }

    #[test]
    fn var_alias_query() {
        let mut analysis = MlilAliasAnalysis::new();
        analysis.process_statement(&AliasStatement::TakeAddress { dst: "a".into(), stack_offset: -8, size: 4 });
        analysis.process_statement(&AliasStatement::TakeAddress { dst: "b".into(), stack_offset: -16, size: 4 });
        assert_eq!(analysis.query_var_alias("a", "b"), MayAlias::NoAlias);
    }

    // ── Additional edge-case coverage ────────────────────────────────────────

    #[test]
    fn stack_slots_partially_overlapping_may_alias() {
        // Slot A at -8 size 8 covers [-8, 0); slot B at -4 size 4 covers [-4, 0).
        // They overlap but are not identical → MayAlias.
        let a = MemoryLocation::StackSlot { offset: -8, size: 8 };
        let b = MemoryLocation::StackSlot { offset: -4, size: 4 };
        assert_eq!(a.alias_with(&b), MayAlias::MayAlias);
        // Symmetric.
        assert_eq!(b.alias_with(&a), MayAlias::MayAlias);
    }

    #[test]
    fn adjacent_stack_slots_no_alias_at_boundary() {
        // [-8, -4) and [-4, 0) are adjacent but disjoint.
        let a = MemoryLocation::StackSlot { offset: -8, size: 4 };
        let b = MemoryLocation::StackSlot { offset: -4, size: 4 };
        assert_eq!(a.alias_with(&b), MayAlias::NoAlias);
    }

    #[test]
    fn global_overlap_classification() {
        let a = MemoryLocation::Global { addr: 0x1000, size: 8 };
        let b = MemoryLocation::Global { addr: 0x1000, size: 8 };
        let c = MemoryLocation::Global { addr: 0x1004, size: 4 };
        let d = MemoryLocation::Global { addr: 0x2000, size: 4 };
        assert_eq!(a.alias_with(&b), MayAlias::MustAlias);
        assert_eq!(a.alias_with(&c), MayAlias::MayAlias);
        assert_eq!(a.alias_with(&d), MayAlias::NoAlias);
    }

    #[test]
    fn heap_alloc_sites_distinguish() {
        let h1 = MemoryLocation::Heap { alloc_site: 0x1000 };
        let h2 = MemoryLocation::Heap { alloc_site: 0x2000 };
        let same = MemoryLocation::Heap { alloc_site: 0x1000 };
        // Different sites are NoAlias; same site is MayAlias (not Must).
        assert_eq!(h1.alias_with(&h2), MayAlias::NoAlias);
        assert_eq!(h1.alias_with(&same), MayAlias::MayAlias);
    }

    #[test]
    fn unknown_aliases_everything() {
        let u = MemoryLocation::Unknown;
        let s = MemoryLocation::StackSlot { offset: -8, size: 8 };
        let g = MemoryLocation::Global { addr: 0x1000, size: 4 };
        let h = MemoryLocation::Heap { alloc_site: 0x100 };
        assert_eq!(u.alias_with(&s), MayAlias::MayAlias);
        assert_eq!(u.alias_with(&g), MayAlias::MayAlias);
        assert_eq!(u.alias_with(&h), MayAlias::MayAlias);
        assert!(u.may_escape());
    }

    #[test]
    fn field_access_overlap_within_same_base() {
        let f1 = MemoryLocation::Field {
            base_var: "p".into(),
            field_offset: 0,
            size: 8,
        };
        let f2 = MemoryLocation::Field {
            base_var: "p".into(),
            field_offset: 0,
            size: 8,
        };
        let f3 = MemoryLocation::Field {
            base_var: "p".into(),
            field_offset: 4,
            size: 4,
        };
        let f4 = MemoryLocation::Field {
            base_var: "q".into(), // different base
            field_offset: 0,
            size: 8,
        };
        assert_eq!(f1.alias_with(&f2), MayAlias::MustAlias);
        assert_eq!(f1.alias_with(&f3), MayAlias::MayAlias);
        // Different bases → Unknown (could be the same object).
        assert_eq!(f1.alias_with(&f4), MayAlias::Unknown);
    }

    #[test]
    fn alias_set_singleton_then_grow() {
        let mut s = AliasSet::singleton(
            0,
            MemoryLocation::StackSlot { offset: -8, size: 4 },
        );
        assert!(!s.contains_unknown);
        assert_eq!(s.members.len(), 1);
        // Adding the same member is idempotent.
        s.add(MemoryLocation::StackSlot { offset: -8, size: 4 });
        assert_eq!(s.members.len(), 1);
        // Adding Unknown flips the contains_unknown flag.
        s.add(MemoryLocation::Unknown);
        assert!(s.contains_unknown);
        // After Unknown is in the set, any query returns true.
        assert!(s.may_alias_any(&MemoryLocation::Global { addr: 0xdead, size: 8 }));
    }

    #[test]
    fn empty_analysis_has_no_points_to() {
        let analysis = MlilAliasAnalysis::new();
        assert_eq!(analysis.points_to("nonexistent").len(), 0);
        assert_eq!(analysis.pts_entry_count(), 0);
        assert!(analysis.sized_events().is_empty());
    }

    #[test]
    fn load_from_unknown_records_event() {
        let mut analysis = MlilAliasAnalysis::new();
        // Loading from a variable we never tracked → Unknown loc, event recorded.
        analysis.process_statement(&AliasStatement::Load {
            dst: "v".into(),
            src: "ptr".into(),
            size: 4,
        });
        let evs = analysis.sized_events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, MemoryEventKind::Load);
        assert_eq!(evs[0].byte_size, 4);
        assert_eq!(evs[0].location, MemoryLocation::Unknown);
    }

    #[test]
    fn drain_recent_loaded_respects_max() {
        let mut analysis = MlilAliasAnalysis::new();
        for i in 0..5 {
            analysis.process_statement(&AliasStatement::Load {
                dst: format!("v{i}"),
                src: "p".into(),
                size: 1,
            });
        }
        let drained = analysis.drain_recent_loaded(3);
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0], "v0", "FIFO order: oldest first");
        // Remaining 2 must still be present.
        let rest = analysis.drain_recent_loaded(100);
        assert_eq!(rest.len(), 2);
        assert_eq!(rest[0], "v3");
        // Draining empty queue is safe.
        assert!(analysis.drain_recent_loaded(10).is_empty());
    }

    #[test]
    fn reset_clears_state() {
        let mut analysis = MlilAliasAnalysis::new();
        analysis.process_statement(&AliasStatement::TakeAddress {
            dst: "p".into(),
            stack_offset: -8,
            size: 8,
        });
        assert!(analysis.pts_entry_count() > 0);
        analysis.reset();
        assert_eq!(analysis.pts_entry_count(), 0);
        assert!(analysis.points_to("p").is_empty());
    }

    #[test]
    fn analyze_aliases_batch_and_no_alias_query() {
        let mut analysis = MlilAliasAnalysis::new();
        analysis.analyze_aliases(&[
            AliasStatement::TakeAddress { dst: "a".into(), stack_offset: -8, size: 4 },
            AliasStatement::TakeAddress { dst: "b".into(), stack_offset: -32, size: 4 },
            AliasStatement::Copy { dst: "c".into(), src: "a".into() },
        ]);
        // a and b clearly don't alias.
        assert!(analysis.no_alias("a", "b"));
        // a and c (copy) DO alias.
        assert!(!analysis.no_alias("a", "c"));
    }

    #[test]
    fn boundary_extreme_offsets_no_panic() {
        // i64::MIN / MAX as stack offsets must not crash overlap arithmetic.
        let a = MemoryLocation::StackSlot { offset: i64::MIN, size: 1 };
        let b = MemoryLocation::StackSlot { offset: i64::MAX, size: 1 };
        // We don't assert a specific result — just that it does not panic.
        let _ = a.alias_with(&b);
        let _ = b.alias_with(&a);
        // Zero-size slots are degenerate but must be handled.
        let z = MemoryLocation::StackSlot { offset: 0, size: 0 };
        let _ = z.alias_with(&z);
    }

    #[test]
    fn may_escape_only_for_escaping_kinds() {
        assert!(MemoryLocation::Unknown.may_escape());
        assert!(MemoryLocation::Heap { alloc_site: 0 }.may_escape());
        assert!(MemoryLocation::Deref { base_var: "p".into() }.may_escape());
        assert!(!MemoryLocation::StackSlot { offset: 0, size: 4 }.may_escape());
        assert!(!MemoryLocation::Global { addr: 0, size: 4 }.may_escape());
    }
}
