//! Call-site diffing between two versions of a function.
//!
//! Detects added/removed/changed calls to other functions, argument count changes,
//! calling convention changes, and indirect-call promotion/demotion.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Address type ─────────────────────────────────────────────────────────────

pub type Addr = u64;

// ── Calling convention ────────────────────────────────────────────────────────

/// Calling convention used at a call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    /// Standard C calling convention (caller cleans stack).
    Cdecl,
    /// Callee cleans stack.
    Stdcall,
    /// First arg in ECX (thiscall).
    Thiscall,
    /// Microsoft x64 (rcx, rdx, r8, r9 + stack).
    MsX64,
    /// System V AMD64 ABI (rdi, rsi, rdx, rcx, r8, r9 + stack).
    SysVAmd64,
    /// ARM AAPCS.
    Aapcs,
    /// Unknown / not inferred.
    Unknown,
}

impl std::fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Thiscall => "thiscall",
            Self::MsX64 => "ms_x64",
            Self::SysVAmd64 => "sysv_amd64",
            Self::Aapcs => "aapcs",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ── Call target ───────────────────────────────────────────────────────────────

/// The target of a call instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallTarget {
    /// Direct call to a known address.
    Direct(Addr),
    /// Indirect call via a register or memory operand (target unknown statically).
    Indirect,
    /// Import thunk resolved to a named symbol.
    Import(String),
    /// Call to an internal function with a known name.
    Named { addr: Addr, name: String },
}

impl CallTarget {
    /// Returns the address if this is a direct or named call.
    #[must_use]
    pub const fn addr(&self) -> Option<Addr> {
        match self {
            Self::Direct(a) | Self::Named { addr: a, .. } => Some(*a),
            Self::Indirect | Self::Import(_) => None,
        }
    }

    /// Returns the symbol name if available.
    #[must_use]
    pub const fn name(&self) -> Option<&str> {
        match self {
            Self::Import(n) | Self::Named { name: n, .. } => Some(n.as_str()),
            Self::Direct(_) | Self::Indirect => None,
        }
    }

    /// True if this is an indirect call.
    #[must_use]
    pub const fn is_indirect(&self) -> bool {
        matches!(self, Self::Indirect)
    }
}

// ── Call site ─────────────────────────────────────────────────────────────────

/// A single call instruction within a function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Address of the call instruction itself.
    pub instruction_addr: Addr,
    /// The call target.
    pub target: CallTarget,
    /// Number of arguments passed (if known).
    pub arg_count: Option<u32>,
    /// Calling convention at this site.
    pub calling_convention: CallingConvention,
    /// Whether this is a tail call.
    pub is_tail_call: bool,
    /// Whether the return value is used.
    pub return_value_used: bool,
}

impl CallSite {
    /// Create a simple direct call with no extra metadata.
    #[must_use]
    pub const fn direct(instruction_addr: Addr, target_addr: Addr) -> Self {
        Self {
            instruction_addr,
            target: CallTarget::Direct(target_addr),
            arg_count: None,
            calling_convention: CallingConvention::Unknown,
            is_tail_call: false,
            return_value_used: false,
        }
    }

    /// Create an import call.
    #[must_use]
    pub fn import(instruction_addr: Addr, name: impl Into<String>) -> Self {
        Self {
            instruction_addr,
            target: CallTarget::Import(name.into()),
            arg_count: None,
            calling_convention: CallingConvention::Unknown,
            is_tail_call: false,
            return_value_used: false,
        }
    }
}

// ── Change kinds ──────────────────────────────────────────────────────────────

/// How a call site's target changed between old and new.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetChange {
    /// Target address changed.
    AddressChanged { old_addr: Addr, new_addr: Addr },
    /// Import symbol changed.
    ImportChanged { old_name: String, new_name: String },
    /// Promoted from indirect to direct.
    IndirectToDirected(Addr),
    /// Demoted from direct to indirect.
    DirectedToIndirect(Addr),
    /// Changed from direct to import.
    DirectToImport(String),
    /// Changed from import to direct.
    ImportToDirect(Addr),
    /// No target change.
    Unchanged,
}

/// How a call site's argument count changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgCountChange {
    Added(u32),
    Removed(u32),
    Changed { old: u32, new: u32 },
    Unchanged,
    Unknown,
}

/// How the calling convention changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConventionChange {
    Changed {
        old: CallingConvention,
        new: CallingConvention,
    },
    Unchanged,
}

/// Aggregate change description for a modified call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSiteModification {
    pub target_change: TargetChange,
    pub arg_count_change: ArgCountChange,
    pub convention_change: ConventionChange,
    pub tail_call_changed: bool,
    pub return_use_changed: bool,
}

impl CallSiteModification {
    /// True if any property changed.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.target_change != TargetChange::Unchanged
            || (self.arg_count_change != ArgCountChange::Unchanged
                && self.arg_count_change != ArgCountChange::Unknown)
            || self.convention_change != ConventionChange::Unchanged
            || self.tail_call_changed
            || self.return_use_changed
    }

    /// One-line description of the most significant change.
    #[must_use]
    pub fn primary_description(&self) -> String {
        if self.target_change != TargetChange::Unchanged {
            return format!("target changed: {:?}", self.target_change);
        }
        if self.arg_count_change != ArgCountChange::Unchanged
            && self.arg_count_change != ArgCountChange::Unknown
        {
            return format!("arg count: {:?}", self.arg_count_change);
        }
        if self.convention_change != ConventionChange::Unchanged {
            return format!("convention: {:?}", self.convention_change);
        }
        if self.tail_call_changed {
            return "tail-call flag changed".to_string();
        }
        if self.return_use_changed {
            return "return-value usage changed".to_string();
        }
        "no change".to_string()
    }
}

// ── Diff result ───────────────────────────────────────────────────────────────

/// The kind of change for a call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallSiteChange {
    /// Call site is new (not present in old version).
    Added,
    /// Call site was removed.
    Removed,
    /// Call site exists in both but something changed.
    Modified(CallSiteModification),
    /// Call site is identical.
    Unchanged,
}

/// Diff record for a single call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSiteDiffEntry {
    /// Instruction address in the old version (or new version for Added sites).
    pub addr: Addr,
    pub change: CallSiteChange,
    pub old_site: Option<CallSite>,
    pub new_site: Option<CallSite>,
}

/// Statistics summary of a call-site diff.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallSiteDiffSummary {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub unchanged: usize,
    /// Number of sites where a direct call changed to indirect or vice versa.
    pub directness_changes: usize,
    /// Number of sites where the argument count changed.
    pub arg_count_changes: usize,
    /// Number of sites where the calling convention changed.
    pub convention_changes: usize,
}

/// Full call-site diff for one function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSiteDiff {
    /// Function address in old binary.
    pub old_func_addr: Addr,
    /// Function address in new binary.
    pub new_func_addr: Addr,
    pub entries: Vec<CallSiteDiffEntry>,
    pub summary: CallSiteDiffSummary,
}

impl CallSiteDiff {
    /// True if all call sites are identical.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.summary.added == 0
            && self.summary.removed == 0
            && self.summary.modified == 0
    }

    /// One-line description.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.is_identical() {
            return "call sites unchanged".to_string();
        }
        let mut parts = Vec::new();
        let s = &self.summary;
        if s.added > 0 {
            parts.push(format!("+{} call", s.added));
        }
        if s.removed > 0 {
            parts.push(format!("-{} call", s.removed));
        }
        if s.modified > 0 {
            parts.push(format!("~{} call", s.modified));
        }
        parts.join(", ")
    }

    /// Return all added call sites.
    #[must_use]
    pub fn added_sites(&self) -> Vec<&CallSiteDiffEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.change, CallSiteChange::Added))
            .collect()
    }

    /// Return all removed call sites.
    #[must_use]
    pub fn removed_sites(&self) -> Vec<&CallSiteDiffEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.change, CallSiteChange::Removed))
            .collect()
    }

    /// Return modified call sites whose target changed.
    #[must_use]
    pub fn target_changed_sites(&self) -> Vec<&CallSiteDiffEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let CallSiteChange::Modified(m) = &e.change {
                    m.target_change != TargetChange::Unchanged
                } else {
                    false
                }
            })
            .collect()
    }
}

// ── Matching strategy ─────────────────────────────────────────────────────────

/// How call sites in old and new versions are matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchStrategy {
    /// Match by instruction address (no rebasing).
    ExactAddress,
    /// Match by relative offset from function entry.
    RelativeOffset,
    /// Match by call target name/symbol (for import-heavy code).
    ByTargetName,
    /// Match using a pre-built address translation map.
    Mapped(HashMap<Addr, Addr>),
}

impl MatchStrategy {
    fn translate(&self, old_addr: Addr, old_entry: Addr, new_entry: Addr) -> Addr {
        match self {
            Self::ExactAddress | Self::ByTargetName => old_addr,
            Self::RelativeOffset => {
                // The offset is SIGNED: cold and outlined blocks are placed
                // below the function entry, and `saturating_sub` clamped every
                // one of them to 0, aliasing them onto the new entry block.
                let offset = old_addr.wrapping_sub(old_entry) as i64;
                new_entry.wrapping_add_signed(offset)
            }
            Self::Mapped(map) => *map.get(&old_addr).unwrap_or(&old_addr),
        }
    }
}

// ── Differ ────────────────────────────────────────────────────────────────────

/// Computes a `CallSiteDiff` between old and new call-site lists.
#[derive(Debug)]
pub struct CallSiteDiffer {
    strategy: MatchStrategy,
}

impl Default for CallSiteDiffer {
    fn default() -> Self {
        Self { strategy: MatchStrategy::ExactAddress }
    }
}

impl CallSiteDiffer {
    /// Create a new differ.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a specific matching strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: MatchStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Diff the call sites of one function across two versions.
    #[must_use]
    pub fn diff(
        &self,
        old_func_addr: Addr,
        new_func_addr: Addr,
        old_sites: &[CallSite],
        new_sites: &[CallSite],
    ) -> CallSiteDiff {
        match &self.strategy {
            MatchStrategy::ByTargetName => {
                Self::diff_by_name(old_func_addr, new_func_addr, old_sites, new_sites)
            }
            _ => self.diff_by_address(old_func_addr, new_func_addr, old_sites, new_sites),
        }
    }

    fn diff_by_address(
        &self,
        old_func_addr: Addr,
        new_func_addr: Addr,
        old_sites: &[CallSite],
        new_sites: &[CallSite],
    ) -> CallSiteDiff {
        // Build lookup maps.
        let new_map: HashMap<Addr, &CallSite> =
            new_sites.iter().map(|s| (s.instruction_addr, s)).collect();

        let mut entries: Vec<CallSiteDiffEntry> = Vec::new();
        let mut matched_new: std::collections::HashSet<Addr> =
            std::collections::HashSet::new();

        for old_site in old_sites {
            let translated = self.strategy.translate(
                old_site.instruction_addr,
                old_func_addr,
                new_func_addr,
            );

            if let Some(&new_site) = new_map.get(&translated) {
                matched_new.insert(translated);
                let modification = Self::compare_sites(old_site, new_site);
                let change = if modification.has_changes() {
                    CallSiteChange::Modified(modification)
                } else {
                    CallSiteChange::Unchanged
                };
                entries.push(CallSiteDiffEntry {
                    addr: old_site.instruction_addr,
                    change,
                    old_site: Some(old_site.clone()),
                    new_site: Some(new_site.clone()),
                });
            } else {
                entries.push(CallSiteDiffEntry {
                    addr: old_site.instruction_addr,
                    change: CallSiteChange::Removed,
                    old_site: Some(old_site.clone()),
                    new_site: None,
                });
            }
        }

        for new_site in new_sites {
            if !matched_new.contains(&new_site.instruction_addr) {
                entries.push(CallSiteDiffEntry {
                    addr: new_site.instruction_addr,
                    change: CallSiteChange::Added,
                    old_site: None,
                    new_site: Some(new_site.clone()),
                });
            }
        }

        let summary = Self::build_summary(&entries);
        CallSiteDiff { old_func_addr, new_func_addr, entries, summary }
    }

    fn diff_by_name(
        old_func_addr: Addr,
        new_func_addr: Addr,
        old_sites: &[CallSite],
        new_sites: &[CallSite],
    ) -> CallSiteDiff {
        // Group by target name; fall back to address matching for unnamed sites.
        let mut new_named: HashMap<String, Vec<&CallSite>> = HashMap::new();

        for s in new_sites {
            if let Some(name) = s.target.name() {
                new_named.entry(name.to_string()).or_default().push(s);
            }
        }

        let mut used_new_addrs: std::collections::HashSet<Addr> =
            std::collections::HashSet::new();
        let mut entries: Vec<CallSiteDiffEntry> = Vec::new();

        for old_site in old_sites {
            if let Some(name) = old_site.target.name()
                && let Some(candidates) = new_named.get_mut(name) {
                    if let Some(pos) = candidates
                        .iter()
                        .position(|s| !used_new_addrs.contains(&s.instruction_addr))
                    {
                        let new_site = candidates[pos];
                        used_new_addrs.insert(new_site.instruction_addr);
                        let modification = Self::compare_sites(old_site, new_site);
                        let change = if modification.has_changes() {
                            CallSiteChange::Modified(modification)
                        } else {
                            CallSiteChange::Unchanged
                        };
                        entries.push(CallSiteDiffEntry {
                            addr: old_site.instruction_addr,
                            change,
                            old_site: Some(old_site.clone()),
                            new_site: Some(new_site.clone()),
                        });
                        continue;
                    }
                }
            // Unmatched: removed.
            entries.push(CallSiteDiffEntry {
                addr: old_site.instruction_addr,
                change: CallSiteChange::Removed,
                old_site: Some(old_site.clone()),
                new_site: None,
            });
        }

        // Remaining new sites without a match.
        for new_site in new_sites {
            if !used_new_addrs.contains(&new_site.instruction_addr) {
                entries.push(CallSiteDiffEntry {
                    addr: new_site.instruction_addr,
                    change: CallSiteChange::Added,
                    old_site: None,
                    new_site: Some(new_site.clone()),
                });
            }
        }

        let summary = Self::build_summary(&entries);
        CallSiteDiff { old_func_addr, new_func_addr, entries, summary }
    }

    fn compare_sites(old: &CallSite, new: &CallSite) -> CallSiteModification {
        // Target change.
        let target_change = match (&old.target, &new.target) {
            (CallTarget::Direct(a), CallTarget::Direct(b)) if a == b => TargetChange::Unchanged,
            (CallTarget::Direct(a), CallTarget::Direct(b)) => {
                TargetChange::AddressChanged { old_addr: *a, new_addr: *b }
            }
            (CallTarget::Import(a), CallTarget::Import(b)) if a == b => TargetChange::Unchanged,
            (CallTarget::Import(a), CallTarget::Import(b)) => TargetChange::ImportChanged {
                old_name: a.clone(),
                new_name: b.clone(),
            },
            (CallTarget::Indirect, CallTarget::Direct(b)) => {
                TargetChange::IndirectToDirected(*b)
            }
            (CallTarget::Direct(a), CallTarget::Indirect) => {
                TargetChange::DirectedToIndirect(*a)
            }
            (CallTarget::Direct(_), CallTarget::Import(n)) => {
                TargetChange::DirectToImport(n.clone())
            }
            (CallTarget::Import(_), CallTarget::Direct(a)) => TargetChange::ImportToDirect(*a),
            _ => {
                // Named <-> Named etc; treat as unchanged if names match.
                if old.target.name() == new.target.name() && old.target.name().is_some() {
                    TargetChange::Unchanged
                } else if let (Some(oa), Some(na)) = (old.target.addr(), new.target.addr()) {
                    if oa == na {
                        TargetChange::Unchanged
                    } else {
                        TargetChange::AddressChanged { old_addr: oa, new_addr: na }
                    }
                } else {
                    TargetChange::Unchanged
                }
            }
        };

        // Arg count change.
        let arg_count_change = match (old.arg_count, new.arg_count) {
            (Some(a), Some(b)) if a == b => ArgCountChange::Unchanged,
            (Some(a), Some(b)) => ArgCountChange::Changed { old: a, new: b },
            (Some(a), None) => ArgCountChange::Removed(a),
            (None, Some(b)) => ArgCountChange::Added(b),
            (None, None) => ArgCountChange::Unknown,
        };

        // Convention change.
        let convention_change = if old.calling_convention == new.calling_convention {
            ConventionChange::Unchanged
        } else {
            ConventionChange::Changed {
                old: old.calling_convention.clone(),
                new: new.calling_convention.clone(),
            }
        };

        CallSiteModification {
            target_change,
            arg_count_change,
            convention_change,
            tail_call_changed: old.is_tail_call != new.is_tail_call,
            return_use_changed: old.return_value_used != new.return_value_used,
        }
    }

    fn build_summary(entries: &[CallSiteDiffEntry]) -> CallSiteDiffSummary {
        let mut s = CallSiteDiffSummary::default();
        for e in entries {
            match &e.change {
                CallSiteChange::Added => s.added += 1,
                CallSiteChange::Removed => s.removed += 1,
                CallSiteChange::Modified(m) => {
                    s.modified += 1;
                    if matches!(
                        m.target_change,
                        TargetChange::IndirectToDirected(_) | TargetChange::DirectedToIndirect(_)
                    ) {
                        s.directness_changes += 1;
                    }
                    if !matches!(
                        m.arg_count_change,
                        ArgCountChange::Unchanged | ArgCountChange::Unknown
                    ) {
                        s.arg_count_changes += 1;
                    }
                    if m.convention_change != ConventionChange::Unchanged {
                        s.convention_changes += 1;
                    }
                }
                CallSiteChange::Unchanged => s.unchanged += 1,
            }
        }
        s
    }
}

// ── Batch diff ────────────────────────────────────────────────────────────────

/// A matched function pair with their call-site lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallSites {
    pub name: String,
    pub old_addr: Addr,
    pub new_addr: Addr,
    pub old_sites: Vec<CallSite>,
    pub new_sites: Vec<CallSite>,
}

/// Results of diffing call sites across many functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCallSiteDiff {
    pub results: Vec<(String, CallSiteDiff)>,
}

impl BatchCallSiteDiff {
    /// Functions where at least one call site changed.
    #[must_use]
    pub fn changed_functions(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|(_, d)| !d.is_identical())
            .map(|(n, _)| n.as_str())
            .collect()
    }

    /// Total count of new call sites across all functions.
    #[must_use]
    pub fn total_added(&self) -> usize {
        self.results.iter().map(|(_, d)| d.summary.added).sum()
    }

    /// Total count of removed call sites across all functions.
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.results.iter().map(|(_, d)| d.summary.removed).sum()
    }
}

/// Diff call sites for multiple function pairs.
#[must_use]
pub fn diff_batch(
    pairs: &[FunctionCallSites],
    strategy: MatchStrategy,
) -> BatchCallSiteDiff {
    let differ = CallSiteDiffer::new().with_strategy(strategy);
    let results = pairs
        .iter()
        .map(|p| {
            let d = differ.diff(p.old_addr, p.new_addr, &p.old_sites, &p.new_sites);
            (p.name.clone(), d)
        })
        .collect();
    BatchCallSiteDiff { results }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sites(base: Addr, targets: &[(Addr, Addr)]) -> Vec<CallSite> {
        targets
            .iter()
            .map(|&(instr, tgt)| CallSite::direct(base + instr, tgt))
            .collect()
    }

    #[test]
    fn test_identical_sites() {
        let old = make_sites(0x1000, &[(0, 0x5000), (8, 0x6000)]);
        let new = make_sites(0x1000, &[(0, 0x5000), (8, 0x6000)]);
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &old, &new);
        assert!(diff.is_identical());
        assert_eq!(diff.summary.unchanged, 2);
    }

    #[test]
    fn test_added_call() {
        let old = make_sites(0x1000, &[(0, 0x5000)]);
        let new = make_sites(0x1000, &[(0, 0x5000), (8, 0x6000)]);
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &old, &new);
        assert_eq!(diff.summary.added, 1);
        assert!(!diff.is_identical());
    }

    #[test]
    fn test_removed_call() {
        let old = make_sites(0x1000, &[(0, 0x5000), (8, 0x6000)]);
        let new = make_sites(0x1000, &[(0, 0x5000)]);
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &old, &new);
        assert_eq!(diff.summary.removed, 1);
    }

    #[test]
    fn test_target_changed() {
        let old = make_sites(0x1000, &[(0, 0x5000)]);
        let new = make_sites(0x1000, &[(0, 0x5001)]);
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &old, &new);
        assert_eq!(diff.summary.modified, 1);
        let entry = &diff.entries[0];
        if let CallSiteChange::Modified(m) = &entry.change {
            assert!(
                matches!(m.target_change, TargetChange::AddressChanged { .. }),
                "expected AddressChanged"
            );
        } else {
            panic!("expected Modified");
        }
    }

    #[test]
    fn test_indirect_to_direct() {
        let old_site = CallSite {
            instruction_addr: 0x1000,
            target: CallTarget::Indirect,
            arg_count: None,
            calling_convention: CallingConvention::Unknown,
            is_tail_call: false,
            return_value_used: false,
        };
        let new_site = CallSite::direct(0x1000, 0x9000);
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &[old_site], &[new_site]);
        assert_eq!(diff.summary.directness_changes, 1);
    }

    #[test]
    fn test_arg_count_change() {
        let mut old_site = CallSite::direct(0x1000, 0x5000);
        old_site.arg_count = Some(3);
        let mut new_site = CallSite::direct(0x1000, 0x5000);
        new_site.arg_count = Some(4);
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &[old_site], &[new_site]);
        assert_eq!(diff.summary.arg_count_changes, 1);
    }

    #[test]
    fn test_describe_non_empty() {
        let old = make_sites(0x1000, &[(0, 0x5000)]);
        let new = make_sites(0x1000, &[(0, 0x5001)]);
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &old, &new);
        let desc = diff.describe();
        assert!(desc.contains("call"), "desc = {desc}");
    }

    #[test]
    fn test_by_name_strategy() {
        let old_site = CallSite::import(0x1000, "VirtualAlloc");
        let new_site = CallSite::import(0x2000, "VirtualAlloc"); // different address, same name
        let differ = CallSiteDiffer::new().with_strategy(MatchStrategy::ByTargetName);
        let diff = differ.diff(0x1000, 0x2000, &[old_site], &[new_site]);
        assert!(diff.is_identical(), "same import name should match");
    }

    #[test]
    fn test_batch_diff() {
        let pairs = vec![FunctionCallSites {
            name: "fn_a".to_string(),
            old_addr: 0x1000,
            new_addr: 0x1000,
            old_sites: make_sites(0x1000, &[(0, 0x5000)]),
            new_sites: make_sites(0x1000, &[(0, 0x5000), (8, 0x6000)]),
        }];
        let batch = diff_batch(&pairs, MatchStrategy::ExactAddress);
        assert_eq!(batch.total_added(), 1);
        assert_eq!(batch.changed_functions(), vec!["fn_a"]);
    }

    #[test]
    fn test_convention_change() {
        let mut old_site = CallSite::direct(0x1000, 0x5000);
        old_site.calling_convention = CallingConvention::Cdecl;
        let mut new_site = CallSite::direct(0x1000, 0x5000);
        new_site.calling_convention = CallingConvention::Stdcall;
        let differ = CallSiteDiffer::new();
        let diff = differ.diff(0x1000, 0x1000, &[old_site], &[new_site]);
        assert_eq!(diff.summary.convention_changes, 1);
    }
}
