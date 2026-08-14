//! LLIL branch target resolution.
//!
//! Resolves statically-unknown branch targets by combining several heuristics:
//! jump-table pattern recognition, value propagation from known constants, and
//! fall-through inference.  The result is a [`ResolutionResult`] that maps each
//! indirect-branch instruction to its resolved target set.
//!
//! # Key types
//! - [`BranchTarget`]      — one resolved (or unresolved) branch target.
//! - [`ResolutionResult`]  — the complete per-instruction resolution map.
//! - [`LlilBranchResolver`] — configurable resolver.
//! - [`resolve_branches`]  — top-level entry point.

use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// BranchTarget
// ─────────────────────────────────────────────────────────────────────────────

/// One resolved branch target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BranchTarget {
    /// A statically-known absolute target address.
    Static(u64),
    /// A jump-table entry at the given index.
    TableEntry { table_addr: u64, index: u32 },
    /// A PLT/GOT stub (resolved lazily at runtime).
    PltStub { stub_addr: u64 },
    /// The branch returns to the caller (tail-call or indirect return).
    Return,
    /// A target that could not be resolved.
    Unresolved,
}

impl BranchTarget {
    /// Return the static address if known.
    #[must_use]
    pub const fn static_addr(&self) -> Option<u64> {
        if let Self::Static(a) = self {
            Some(*a)
        } else {
            None
        }
    }

    /// Return `true` if this target is fully resolved.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        !matches!(self, Self::Unresolved)
    }
}

impl std::fmt::Display for BranchTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(a) => write!(f, "0x{a:x}"),
            Self::TableEntry { table_addr, index } => {
                write!(f, "table[0x{table_addr:x}][{index}]")
            }
            Self::PltStub { stub_addr } => write!(f, "PLT@0x{stub_addr:x}"),
            Self::Return => write!(f, "<return>"),
            Self::Unresolved => write!(f, "<unresolved>"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IndirectBranchKind — classification for the resolver
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of an indirect branch for resolution heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndirectBranchKind {
    /// `jmp [reg]` — target in a register.
    RegisterJump,
    /// `jmp [mem + reg*scale]` — jump table pattern.
    JumpTable { scale: u8 },
    /// `call [reg]` — indirect call (e.g. virtual dispatch).
    IndirectCall,
    /// `ret` — return instruction.
    Return,
    /// Cannot be classified.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────────
// IndirectBranch — an instruction to be resolved
// ─────────────────────────────────────────────────────────────────────────────

/// An indirect branch instruction that needs target resolution.
#[derive(Debug, Clone)]
pub struct IndirectBranch {
    /// Address of the branch instruction.
    pub address: u64,
    /// Classification.
    pub kind: IndirectBranchKind,
    /// If the register holding the target is known (from constant propagation).
    pub reg_value: Option<i64>,
    /// Jump-table base address (from lifter analysis or pattern matching).
    pub table_base: Option<u64>,
    /// Maximum number of table entries (bounds from preceding comparison).
    pub table_max_entries: Option<u32>,
    /// PLT stub address (set when the pattern matches a PLT call).
    pub plt_stub: Option<u64>,
    /// Addresses suggested by other analyses (e.g. type recovery, profiling).
    pub hints: Vec<u64>,
}

impl IndirectBranch {
    /// Create a minimal indirect branch record.
    #[must_use]
    pub const fn new(address: u64, kind: IndirectBranchKind) -> Self {
        Self {
            address,
            kind,
            reg_value: None,
            table_base: None,
            table_max_entries: None,
            plt_stub: None,
            hints: Vec::new(),
        }
    }

    /// Return `true` if sufficient information is available for resolution.
    #[must_use]
    pub fn is_resolvable(&self) -> bool {
        self.reg_value.is_some()
            || self.table_base.is_some()
            || self.plt_stub.is_some()
            || !self.hints.is_empty()
            || self.kind == IndirectBranchKind::Return
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JumpTableRange — address range believed to be a jump table
// ─────────────────────────────────────────────────────────────────────────────

/// A memory range believed to hold a jump table.
#[derive(Debug, Clone)]
pub struct JumpTableRange {
    /// Address of the first table entry.
    pub base: u64,
    /// Entry stride in bytes (1, 2, 4, or 8).
    pub entry_size: u8,
    /// Number of entries.
    pub count: u32,
    /// Whether entries are relative (offset from base) or absolute addresses.
    pub relative: bool,
}

impl JumpTableRange {
    /// Compute the target address for entry `i`.
    ///
    /// `raw_entry` is the integer value read from `base + i * entry_size`.
    #[must_use]
    pub const fn compute_target(&self, raw_entry: i64, _index: u32) -> u64 {
        if self.relative {
            self.base.cast_signed().wrapping_add(raw_entry).cast_unsigned()
        } else {
            raw_entry.cast_unsigned()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolutionResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of branch resolution for a function.
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// Map from branch instruction address to its resolved target set.
    pub targets: HashMap<u64, Vec<BranchTarget>>,
    /// Number of indirect branches that were fully resolved.
    pub resolved_count: usize,
    /// Number of indirect branches that remain unresolved.
    pub unresolved_count: usize,
    /// Addresses believed to be jump tables.
    pub jump_tables: Vec<JumpTableRange>,
}

impl ResolutionResult {
    /// Get the resolved targets for a branch at `addr`.
    #[must_use]
    pub fn targets_for(&self, addr: u64) -> &[BranchTarget] {
        self.targets.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// Return `true` if the branch at `addr` was fully resolved.
    #[must_use]
    pub fn is_resolved(&self, addr: u64) -> bool {
        self.targets
            .get(&addr)
            .is_some_and(|t| t.iter().any(BranchTarget::is_resolved))
    }

    /// All unique static target addresses across all branches.
    #[must_use]
    pub fn all_static_targets(&self) -> Vec<u64> {
        let mut addrs: HashSet<u64> = HashSet::new();
        for targets in self.targets.values() {
            for t in targets {
                if let Some(a) = t.static_addr() {
                    addrs.insert(a);
                }
            }
        }
        let mut v: Vec<u64> = addrs.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Resolution rate (0.0 – 1.0).
    #[must_use]
    pub fn resolution_rate(&self) -> f64 {
        let total = self.resolved_count + self.unresolved_count;
        if total == 0 {
            1.0
        } else {
            f64::from(u32::try_from(self.resolved_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilBranchResolver
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves indirect branch targets using a combination of heuristics.
///
/// Heuristics applied in order:
/// 1. If `kind == Return` → target is `BranchTarget::Return`.
/// 2. If `plt_stub` is set → `BranchTarget::PltStub`.
/// 3. If `reg_value` is set → `BranchTarget::Static(reg_value as u64)`.
/// 4. If `table_base` is set → expand jump-table entries.
/// 5. For each `hint` → `BranchTarget::Static(hint)`.
/// 6. Otherwise → `BranchTarget::Unresolved`.
#[derive(Debug, Clone)]
pub struct LlilBranchResolver {
    /// The binary image (base address → byte slice).  Used for jump-table reads.
    pub memory: HashMap<u64, Vec<u8>>,
    /// Pointer width of the target (4 or 8 bytes).
    pub pointer_width: u8,
    /// Maximum number of jump-table entries to accept (guards against false positives).
    pub max_table_entries: u32,
    /// If `true`, validate static targets by checking if the address falls
    /// within a known code region.
    pub validate_targets: bool,
    /// Known code regions `[start, end)`.
    pub code_regions: Vec<(u64, u64)>,
}

impl Default for LlilBranchResolver {
    fn default() -> Self {
        Self::new(8)
    }
}

impl LlilBranchResolver {
    /// Create a new resolver for the given pointer width.
    #[must_use]
    pub fn new(pointer_width: u8) -> Self {
        Self {
            memory: HashMap::new(),
            pointer_width,
            max_table_entries: 1024,
            validate_targets: false,
            code_regions: Vec::new(),
        }
    }

    /// Register a memory region.
    pub fn add_memory(&mut self, base: u64, data: Vec<u8>) {
        self.memory.insert(base, data);
    }

    /// Register a code region `[start, end)`.
    pub fn add_code_region(&mut self, start: u64, end: u64) {
        self.code_regions.push((start, end));
    }

    /// Return `true` if `addr` falls within a known code region.
    #[must_use]
    pub fn is_code_addr(&self, addr: u64) -> bool {
        self.code_regions.iter().any(|(s, e)| addr >= *s && addr < *e)
    }

    /// Read `size` bytes from the memory map at `addr`.
    fn read_mem(&self, addr: u64, size: u8) -> Option<i64> {
        for (&base, data) in &self.memory {
            if addr >= base {
                let offset = usize::try_from(addr - base).unwrap_or(usize::MAX);
                if offset + size as usize <= data.len() {
                    let bytes = &data[offset..offset + size as usize];
                    let v = match size {
                        1 => i64::from(bytes[0]),
                        2 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
                        4 => i64::from(i32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
                        8 => i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])),
                        _ => return None,
                    };
                    return Some(v);
                }
            }
        }
        None
    }

    /// Resolve a single indirect branch.
    #[must_use]
    pub fn resolve_one(&self, branch: &IndirectBranch) -> Vec<BranchTarget> {
        let mut targets: Vec<BranchTarget> = Vec::new();

        // 1. Return.
        if branch.kind == IndirectBranchKind::Return {
            return vec![BranchTarget::Return];
        }

        // 2. PLT stub.
        if let Some(stub) = branch.plt_stub {
            targets.push(BranchTarget::PltStub { stub_addr: stub });
        }

        // 3. Constant register value.
        if let Some(v) = branch.reg_value {
            let addr = v.cast_unsigned();
            if !self.validate_targets || self.is_code_addr(addr) {
                targets.push(BranchTarget::Static(addr));
            }
        }

        // 4. Jump table expansion.
        if let Some(table_base) = branch.table_base {
            let max_entries = branch
                .table_max_entries
                .unwrap_or(self.max_table_entries)
                .min(self.max_table_entries);

            let scale = match branch.kind {
                IndirectBranchKind::JumpTable { scale } => scale,
                _ => self.pointer_width,
            };

            let mut table = JumpTableRange {
                base: table_base,
                entry_size: scale,
                count: 0,
                relative: false,
            };

            let mut seen: HashSet<u64> = HashSet::new();
            for i in 0..max_entries {
                let entry_addr = table_base + u64::from(i) * u64::from(scale);
                let Some(raw) = self.read_mem(entry_addr, scale) else { break };
                let target_addr = table.compute_target(raw, i);
                if self.validate_targets && !self.is_code_addr(target_addr) {
                    break;
                }
                if seen.insert(target_addr) {
                    targets.push(BranchTarget::TableEntry {
                        table_addr: table_base,
                        index: i,
                    });
                    // Also track the static address.
                    targets.push(BranchTarget::Static(target_addr));
                }
                table.count += 1;
            }
        }

        // 5. Hints.
        for &hint in &branch.hints {
            let t = BranchTarget::Static(hint);
            if !targets.contains(&t) {
                targets.push(t);
            }
        }

        // 6. Fallback.
        if targets.is_empty() {
            targets.push(BranchTarget::Unresolved);
        }

        targets
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_branches — top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve all indirect branches in a function.
///
/// Returns a [`ResolutionResult`] summarizing the resolution outcomes.
#[must_use]
pub fn resolve_branches(
    branches: &[IndirectBranch],
    resolver: &LlilBranchResolver,
) -> ResolutionResult {
    let mut targets_map: HashMap<u64, Vec<BranchTarget>> = HashMap::new();
    let mut resolved_count = 0usize;
    let mut unresolved = 0usize;
    let mut jump_tables: Vec<JumpTableRange> = Vec::new();

    for branch in branches {
        let targets = resolver.resolve_one(branch);
        let any_resolved = targets.iter().any(BranchTarget::is_resolved);
        if any_resolved {
            resolved_count += 1;
        } else {
            unresolved += 1;
        }

        // Record jump tables.
        if let Some(base) = branch.table_base {
            let count = branch.table_max_entries.unwrap_or(0);
            let scale = match branch.kind {
                IndirectBranchKind::JumpTable { scale } => scale,
                _ => resolver.pointer_width,
            };
            jump_tables.push(JumpTableRange {
                base,
                entry_size: scale,
                count,
                relative: false,
            });
        }

        targets_map.insert(branch.address, targets);
    }

    ResolutionResult {
        targets: targets_map,
        resolved_count,
        unresolved_count: unresolved,
        jump_tables,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchStats — aggregate statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics for branch resolution across a binary.
#[derive(Debug, Clone, Default)]
pub struct BranchStats {
    /// Total indirect branches encountered.
    pub total: usize,
    /// Fully resolved.
    pub resolved: usize,
    /// Resolved via jump-table analysis.
    pub jump_table_resolved: usize,
    /// Resolved via constant propagation.
    pub const_resolved: usize,
    /// Resolved via hints.
    pub hint_resolved: usize,
    /// Unresolved.
    pub unresolved: usize,
}

impl BranchStats {
    /// Incorporate results from one function.
    pub const fn record(&mut self, result: &ResolutionResult) {
        self.total += result.resolved_count + result.unresolved_count;
        self.resolved += result.resolved_count;
        self.unresolved += result.unresolved_count;
    }

    /// Overall resolution rate.
    #[must_use]
    pub fn rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            f64::from(u32::try_from(self.resolved).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> LlilBranchResolver {
        LlilBranchResolver::new(8)
    }

    #[test]
    fn test_return_resolves_to_return() {
        let branch = IndirectBranch::new(0x1000, IndirectBranchKind::Return);
        let r = resolver();
        let targets = r.resolve_one(&branch);
        assert_eq!(targets, vec![BranchTarget::Return]);
    }

    #[test]
    fn test_const_register_resolves_static() {
        let mut branch = IndirectBranch::new(0x1000, IndirectBranchKind::RegisterJump);
        branch.reg_value = Some(0x2000i64);
        let r = resolver();
        let targets = r.resolve_one(&branch);
        assert!(targets.contains(&BranchTarget::Static(0x2000)));
    }

    #[test]
    fn test_plt_stub_resolves() {
        let mut branch = IndirectBranch::new(0x1000, IndirectBranchKind::IndirectCall);
        branch.plt_stub = Some(0x3000);
        let r = resolver();
        let targets = r.resolve_one(&branch);
        assert!(targets.contains(&BranchTarget::PltStub { stub_addr: 0x3000 }));
    }

    #[test]
    fn test_hint_resolves_static() {
        let mut branch = IndirectBranch::new(0x1000, IndirectBranchKind::Unknown);
        branch.hints.push(0x4000);
        let r = resolver();
        let targets = r.resolve_one(&branch);
        assert!(targets.contains(&BranchTarget::Static(0x4000)));
    }

    #[test]
    fn test_unresolvable_gives_unresolved() {
        let branch = IndirectBranch::new(0x1000, IndirectBranchKind::RegisterJump);
        let r = resolver();
        let targets = r.resolve_one(&branch);
        assert!(targets.contains(&BranchTarget::Unresolved));
    }

    #[test]
    fn test_jump_table_from_memory() {
        let mut r = LlilBranchResolver::new(4);
        // 3-entry absolute jump table at 0x8000 with 4-byte entries.
        let data: Vec<u8> = [
            0x00u8, 0x10, 0x00, 0x00, // 0x1000
            0x00, 0x20, 0x00, 0x00, // 0x2000
            0x00, 0x30, 0x00, 0x00, // 0x3000
        ]
        .to_vec();
        r.add_memory(0x8000, data);

        let mut branch = IndirectBranch::new(0x9000, IndirectBranchKind::JumpTable { scale: 4 });
        branch.table_base = Some(0x8000);
        branch.table_max_entries = Some(3);

        let targets = r.resolve_one(&branch);
        let static_targets: Vec<u64> = targets
            .iter()
            .filter_map(|t| t.static_addr())
            .collect();
        assert!(static_targets.contains(&0x1000));
        assert!(static_targets.contains(&0x2000));
        assert!(static_targets.contains(&0x3000));
    }

    #[test]
    fn test_resolve_branches_batch() {
        let mut r = resolver();
        r.add_code_region(0x1000, 0x9000);
        let branches = vec![
            {
                let b = IndirectBranch::new(0x1000, IndirectBranchKind::Return);
                b
            },
            {
                let mut b = IndirectBranch::new(0x2000, IndirectBranchKind::RegisterJump);
                b.reg_value = Some(0x5000);
                b
            },
            IndirectBranch::new(0x3000, IndirectBranchKind::Unknown),
        ];
        let result = resolve_branches(&branches, &r);
        assert!(result.is_resolved(0x1000));
        assert!(result.is_resolved(0x2000));
        assert!(!result.is_resolved(0x3000));
        assert_eq!(result.resolved_count, 2);
        assert_eq!(result.unresolved_count, 1);
    }

    #[test]
    fn test_resolution_rate() {
        let result = ResolutionResult {
            targets: HashMap::new(),
            resolved_count: 3,
            unresolved_count: 1,
            jump_tables: vec![],
        };
        assert!((result.resolution_rate() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_all_static_targets() {
        let mut targets = HashMap::new();
        targets.insert(0x1000u64, vec![BranchTarget::Static(0xabcd)]);
        targets.insert(0x2000u64, vec![BranchTarget::Static(0x1234), BranchTarget::Return]);
        let result = ResolutionResult {
            targets,
            resolved_count: 2,
            unresolved_count: 0,
            jump_tables: vec![],
        };
        let static_targets = result.all_static_targets();
        assert!(static_targets.contains(&0xabcd));
        assert!(static_targets.contains(&0x1234));
    }

    // ── Additional edge-case coverage ────────────────────────────────────────

    #[test]
    fn test_branch_target_static_addr_helpers() {
        // static_addr returns Some only for Static variant.
        assert_eq!(BranchTarget::Static(0xdead).static_addr(), Some(0xdead));
        assert_eq!(BranchTarget::Return.static_addr(), None);
        assert_eq!(BranchTarget::Unresolved.static_addr(), None);
        assert_eq!(BranchTarget::PltStub { stub_addr: 1 }.static_addr(), None);
        assert_eq!(
            BranchTarget::TableEntry { table_addr: 0, index: 0 }.static_addr(),
            None
        );
        // is_resolved: everything except Unresolved.
        assert!(BranchTarget::Static(0).is_resolved());
        assert!(BranchTarget::Return.is_resolved());
        assert!(BranchTarget::PltStub { stub_addr: 0 }.is_resolved());
        assert!(BranchTarget::TableEntry { table_addr: 0, index: 0 }.is_resolved());
        assert!(!BranchTarget::Unresolved.is_resolved());
    }

    #[test]
    fn test_indirect_branch_resolvability_flags() {
        // Plain RegisterJump with nothing populated is NOT resolvable.
        let bare = IndirectBranch::new(0x1000, IndirectBranchKind::RegisterJump);
        assert!(!bare.is_resolvable());
        // Return is always resolvable even with no extra info.
        let ret = IndirectBranch::new(0x1000, IndirectBranchKind::Return);
        assert!(ret.is_resolvable());
        // A single hint is sufficient.
        let mut hinted = IndirectBranch::new(0x1000, IndirectBranchKind::Unknown);
        hinted.hints.push(0x42);
        assert!(hinted.is_resolvable());
    }

    #[test]
    fn test_empty_branches_gives_perfect_rate() {
        // Edge: zero branches → rate is 1.0 (vacuous truth).
        let result = resolve_branches(&[], &resolver());
        assert!((result.resolution_rate() - 1.0).abs() < 1e-9);
        assert_eq!(result.resolved_count, 0);
        assert_eq!(result.unresolved_count, 0);
        assert!(result.targets.is_empty());
    }

    #[test]
    fn test_jump_table_truncated_memory_stops_early() {
        // Memory contains 2 valid entries but we claim 5. The resolver must
        // stop at the boundary, not panic or read OOB.
        let mut r = LlilBranchResolver::new(4);
        let data: Vec<u8> = vec![
            0x00, 0x10, 0x00, 0x00, // 0x1000
            0x00, 0x20, 0x00, 0x00, // 0x2000
            // only 8 bytes — entry 2 is missing
        ];
        r.add_memory(0x8000, data);

        let mut branch = IndirectBranch::new(0x9000, IndirectBranchKind::JumpTable { scale: 4 });
        branch.table_base = Some(0x8000);
        branch.table_max_entries = Some(5);

        let targets = r.resolve_one(&branch);
        let static_targets: Vec<u64> = targets.iter().filter_map(|t| t.static_addr()).collect();
        assert_eq!(static_targets.len(), 2, "should stop after truncation");
        assert!(static_targets.contains(&0x1000));
        assert!(static_targets.contains(&0x2000));
    }

    #[test]
    fn test_jump_table_max_entries_cap_enforced() {
        // resolver.max_table_entries must override an over-large per-branch cap.
        let mut r = LlilBranchResolver::new(4);
        r.max_table_entries = 2;
        // 4 valid entries in memory.
        let mut data: Vec<u8> = Vec::new();
        for i in 0u32..4 {
            data.extend_from_slice(&(0x1000u32 + i * 0x10).to_le_bytes());
        }
        r.add_memory(0x8000, data);

        let mut branch = IndirectBranch::new(0x9000, IndirectBranchKind::JumpTable { scale: 4 });
        branch.table_base = Some(0x8000);
        branch.table_max_entries = Some(1024);
        let targets = r.resolve_one(&branch);
        let static_targets: Vec<u64> =
            targets.iter().filter_map(|t| t.static_addr()).collect();
        assert_eq!(static_targets.len(), 2, "resolver cap of 2 must dominate");
    }

    #[test]
    fn test_jump_table_deduplicates_repeated_targets() {
        // A jump table with all entries pointing to the same handler should
        // resolve to exactly one static target (deduped).
        let mut r = LlilBranchResolver::new(4);
        let mut data: Vec<u8> = Vec::new();
        for _ in 0..4 {
            data.extend_from_slice(&0x1234u32.to_le_bytes());
        }
        r.add_memory(0x8000, data);

        let mut branch = IndirectBranch::new(0x9000, IndirectBranchKind::JumpTable { scale: 4 });
        branch.table_base = Some(0x8000);
        branch.table_max_entries = Some(4);
        let targets = r.resolve_one(&branch);
        let static_targets: Vec<u64> =
            targets.iter().filter_map(|t| t.static_addr()).collect();
        assert_eq!(static_targets, vec![0x1234]);
    }

    #[test]
    fn test_validate_targets_rejects_non_code() {
        // With validate_targets=true and no code region covering 0x9999,
        // a constant-register branch into 0x9999 should be rejected.
        let mut r = LlilBranchResolver::new(8);
        r.validate_targets = true;
        r.add_code_region(0x1000, 0x2000);

        let mut branch = IndirectBranch::new(0x500, IndirectBranchKind::RegisterJump);
        branch.reg_value = Some(0x9999);
        let targets = r.resolve_one(&branch);
        // The Static target should be absent; resolver falls back to Unresolved.
        assert!(!targets.contains(&BranchTarget::Static(0x9999)));
        assert!(targets.contains(&BranchTarget::Unresolved));
    }

    #[test]
    fn test_validate_targets_accepts_in_range() {
        let mut r = LlilBranchResolver::new(8);
        r.validate_targets = true;
        r.add_code_region(0x1000, 0x2000);
        let mut branch = IndirectBranch::new(0x500, IndirectBranchKind::RegisterJump);
        branch.reg_value = Some(0x1500);
        let targets = r.resolve_one(&branch);
        assert!(targets.contains(&BranchTarget::Static(0x1500)));
        // Boundary: the END of a code region is exclusive.
        let mut branch_end = IndirectBranch::new(0x500, IndirectBranchKind::RegisterJump);
        branch_end.reg_value = Some(0x2000);
        let targets_end = r.resolve_one(&branch_end);
        assert!(!targets_end.contains(&BranchTarget::Static(0x2000)));
    }

    #[test]
    fn test_relative_jump_table_compute_target_wraps() {
        // A relative table at high base with a negative offset must wrap correctly.
        let table = JumpTableRange {
            base: 0x1_0000,
            entry_size: 4,
            count: 0,
            relative: true,
        };
        // Offset -0x100 from 0x1_0000 → 0xFF00.
        assert_eq!(table.compute_target(-0x100, 0), 0xFF00);
        // Offset 0 → base itself.
        assert_eq!(table.compute_target(0, 0), 0x1_0000);
        // Min/max i64 offsets must not panic.
        let _ = table.compute_target(i64::MIN, 0);
        let _ = table.compute_target(i64::MAX, 0);
    }

    #[test]
    fn test_resolution_rate_all_unresolved() {
        let result = ResolutionResult {
            targets: HashMap::new(),
            resolved_count: 0,
            unresolved_count: 7,
            jump_tables: vec![],
        };
        assert!((result.resolution_rate() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_branch_stats_aggregation() {
        // record() must sum across multiple per-function results.
        let mut stats = BranchStats::default();
        let r1 = ResolutionResult {
            targets: HashMap::new(),
            resolved_count: 3,
            unresolved_count: 1,
            jump_tables: vec![],
        };
        let r2 = ResolutionResult {
            targets: HashMap::new(),
            resolved_count: 2,
            unresolved_count: 4,
            jump_tables: vec![],
        };
        stats.record(&r1);
        stats.record(&r2);
        assert_eq!(stats.total, 10);
        assert_eq!(stats.resolved, 5);
        assert_eq!(stats.unresolved, 5);
        assert!((stats.rate() - 0.5).abs() < 1e-9);
        // Empty stats rate is 1.0.
        let empty = BranchStats::default();
        assert!((empty.rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_targets_for_unknown_address_is_empty() {
        let result = ResolutionResult {
            targets: HashMap::new(),
            resolved_count: 0,
            unresolved_count: 0,
            jump_tables: vec![],
        };
        assert!(result.targets_for(0xdeadbeef).is_empty());
        assert!(!result.is_resolved(0xdeadbeef));
    }

    #[test]
    fn test_indirect_call_with_plt_and_reg_value() {
        // Both PLT stub and a register-value hint set → both must appear.
        let r = resolver();
        let mut branch = IndirectBranch::new(0x1000, IndirectBranchKind::IndirectCall);
        branch.plt_stub = Some(0xABCD);
        branch.reg_value = Some(0x4000);
        let targets = r.resolve_one(&branch);
        assert!(targets.contains(&BranchTarget::PltStub { stub_addr: 0xABCD }));
        assert!(targets.contains(&BranchTarget::Static(0x4000)));
    }
}
