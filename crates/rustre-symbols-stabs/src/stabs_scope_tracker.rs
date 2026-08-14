//! STABS scope tracker.
//!
//! Processes the `N_LBRAC` (left-brace) and `N_RBRAC` (right-brace) STABS
//! entries to reconstruct lexical scopes for a compilation unit.  Also handles
//! `N_FUN` entries, which implicitly open a function scope.
//!
//! The tracker maintains a stack of open scopes and a flat list of fully closed
//! scopes.  After all STABS have been fed, callers can use [`scope_at_offset`]
//! to find the innermost scope active at a given byte offset within the
//! compilation unit.

use std::fmt;

// ── STABS entry types (relevant subset) ──────────────────────────────────────

/// Relevant STABS entry type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StabsEntryType {
    /// `N_FUN` (0x24) — function start/end.
    Fun = 0x24,
    /// `N_LBRAC` (0xC0) — left brace (scope open).
    LBrac = 0xC0,
    /// `N_RBRAC` (0xE0) — right brace (scope close).
    RBrac = 0xE0,
    /// `N_SO` (0x64) — source file.
    So = 0x64,
    /// `N_SOL` (0x84) — sub-file (included source).
    Sol = 0x84,
}

// ── ScopeKind ─────────────────────────────────────────────────────────────────

/// The kind of a STABS scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeKind {
    /// Top-level compilation unit scope.
    TranslationUnit,
    /// A function body (opened by `N_FUN`).
    Function {
        /// Mangled / demangled function name.
        name: String,
    },
    /// A lexical block within a function (opened by `N_LBRAC`).
    LexicalBlock {
        /// 1-based nesting depth within the function.
        depth: u32,
    },
}

impl fmt::Display for ScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TranslationUnit => write!(f, "TU"),
            Self::Function { name } => write!(f, "fn:{name}"),
            Self::LexicalBlock { depth } => write!(f, "block@{depth}"),
        }
    }
}

// ── Scope ─────────────────────────────────────────────────────────────────────

/// A fully closed STABS scope.
#[derive(Debug, Clone)]
pub struct Scope {
    /// Kind of this scope.
    pub kind: ScopeKind,
    /// Byte offset within the CU where the scope starts (inclusive).
    pub start_offset: u64,
    /// Byte offset within the CU where the scope ends (exclusive).
    pub end_offset: u64,
    /// Zero-based index of this scope in the flat list.
    pub index: usize,
    /// Index of the parent scope (`None` for the TU scope).
    pub parent_index: Option<usize>,
}

impl Scope {
    /// Returns `true` if `offset` falls inside this scope.
    #[must_use]
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start_offset && offset < self.end_offset
    }

    /// Returns the size of this scope in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.end_offset.saturating_sub(self.start_offset)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{:#x}..{:#x}) idx={}",
            self.kind, self.start_offset, self.end_offset, self.index
        )
    }
}

// ── Open scope (tracker stack element) ───────────────────────────────────────

#[derive(Debug)]
struct OpenScope {
    kind: ScopeKind,
    start_offset: u64,
    /// Will become `Scope::index` when closed.
    index: usize,
    parent_index: Option<usize>,
}

// ── TrackerError ──────────────────────────────────────────────────────────────

/// Errors from the scope tracker.
#[derive(Debug, Clone)]
pub enum TrackerError {
    /// An `N_RBRAC` was encountered with no matching open scope.
    UnmatchedRBrac {
        /// Offset of the unmatched `N_RBRAC`.
        offset: u64,
    },
    /// An `N_FUN` with an empty name was fed (empty name signals function end in
    /// some toolchain variants; silently ignored).
    FunEnd,
}

impl fmt::Display for TrackerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmatchedRBrac { offset } => {
                write!(f, "unmatched N_RBRAC at offset {offset:#x}")
            }
            Self::FunEnd => write!(f, "N_FUN end marker (ignored)"),
        }
    }
}

// ── StabsScopeTracker ─────────────────────────────────────────────────────────

/// Reconstructs the STABS scope tree from a sequence of `N_FUN`, `N_LBRAC`,
/// and `N_RBRAC` entries.
///
/// Feed entries in address order.  After feeding is complete, call
/// [`StabsScopeTracker::finalise`] to close any implicitly open scopes, then
/// use [`scope_at_offset`] to query.
pub struct StabsScopeTracker {
    /// Fully closed scopes.
    scopes: Vec<Scope>,
    /// Stack of currently open scopes (innermost last).
    stack: Vec<OpenScope>,
    /// Next index to assign.
    next_index: usize,
    /// Nesting depth of lexical blocks within the current function.
    block_depth: u32,
    /// Total bytes covered by the CU (updated on each entry).
    cu_end: u64,
}

impl StabsScopeTracker {
    /// Create an empty tracker.  Optionally opens a TU-level scope.
    #[must_use]
    pub fn new() -> Self {
        let mut t = Self {
            scopes: Vec::new(),
            stack: Vec::new(),
            next_index: 0,
            block_depth: 0,
            cu_end: 0,
        };
        // Push a root TU scope that will be closed in `finalise`.
        t.stack.push(OpenScope {
            kind: ScopeKind::TranslationUnit,
            start_offset: 0,
            index: 0,
            parent_index: None,
        });
        t.next_index = 1;
        t
    }

    /// Feed an `N_FUN` entry.
    ///
    /// An empty `name` signals the end of the current function in some
    /// toolchains; this is handled by closing the innermost function scope.
    pub fn feed_fun(&mut self, name: &str, offset: u64) -> Result<(), TrackerError> {
        if name.is_empty() {
            // Some toolchains emit N_FUN "" to close the function.
            self.update_cu_end(offset);
            self.close_function_scope(offset);
            return Err(TrackerError::FunEnd);
        }
        // If a previous function is still open, close it at the last seen
        // offset (its trailing N_RBRAC, captured in cu_end) before starting
        // a new one.  Without this, sequential N_FUN entries would nest.
        if self.stack.iter().any(|s| matches!(s.kind, ScopeKind::Function { .. })) {
            let close_at = self.cu_end;
            self.close_function_scope(close_at);
        }
        self.update_cu_end(offset);
        let parent = self.stack.last().map(|s| s.index);
        let idx = self.next_index;
        self.next_index += 1;
        self.block_depth = 0;
        self.stack.push(OpenScope {
            kind: ScopeKind::Function { name: name.to_owned() },
            start_offset: offset,
            index: idx,
            parent_index: parent,
        });
        Ok(())
    }

    /// Feed an `N_LBRAC` (left brace) entry.
    pub fn feed_lbrac(&mut self, offset: u64) {
        self.update_cu_end(offset);
        self.block_depth += 1;
        let parent = self.stack.last().map(|s| s.index);
        let idx = self.next_index;
        self.next_index += 1;
        self.stack.push(OpenScope {
            kind: ScopeKind::LexicalBlock { depth: self.block_depth },
            start_offset: offset,
            index: idx,
            parent_index: parent,
        });
    }

    /// Feed an `N_RBRAC` (right brace) entry.
    pub fn feed_rbrac(&mut self, offset: u64) -> Result<(), TrackerError> {
        self.update_cu_end(offset);
        // Pop the innermost non-TU scope.
        let top = self.stack.last().map(|s| &s.kind);
        if matches!(
            top,
            Some(ScopeKind::LexicalBlock { .. }) | Some(ScopeKind::Function { .. })
        ) {
            let open = self.stack.pop().unwrap();
            if matches!(open.kind, ScopeKind::LexicalBlock { .. }) && self.block_depth > 0 {
                self.block_depth -= 1;
            }
            self.scopes.push(Scope {
                kind: open.kind,
                start_offset: open.start_offset,
                end_offset: offset,
                index: open.index,
                parent_index: open.parent_index,
            });
            Ok(())
        } else {
            Err(TrackerError::UnmatchedRBrac { offset })
        }
    }

    /// Finalise: close all remaining open scopes using `end_offset`.
    pub fn finalise(&mut self, end_offset: u64) {
        self.cu_end = self.cu_end.max(end_offset);
        while let Some(open) = self.stack.pop() {
            self.scopes.push(Scope {
                kind: open.kind,
                start_offset: open.start_offset,
                end_offset: self.cu_end,
                index: open.index,
                parent_index: open.parent_index,
            });
        }
        // Sort so scope_at_offset can binary-search on start_offset.
        self.scopes.sort_by_key(|s| s.start_offset);
    }

    /// All fully closed scopes (available after [`Self::finalise`]).
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Number of closed scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// Returns `true` when no scopes have been closed yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    fn update_cu_end(&mut self, offset: u64) {
        if offset > self.cu_end {
            self.cu_end = offset;
        }
    }

    fn close_function_scope(&mut self, end_offset: u64) {
        if let Some(pos) = self.stack.iter().rposition(|s| {
            matches!(s.kind, ScopeKind::Function { .. })
        }) {
            let open = self.stack.remove(pos);
            self.scopes.push(Scope {
                kind: open.kind,
                start_offset: open.start_offset,
                end_offset,
                index: open.index,
                parent_index: open.parent_index,
            });
        }
    }
}

impl Default for StabsScopeTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── scope_at_offset ───────────────────────────────────────────────────────────

/// Return the innermost scope active at `offset`, if any.
///
/// The tracker must be finalised before calling this function.
///
/// ```rust
/// use rustre_symbols_stabs::stabs_scope_tracker::{StabsScopeTracker, scope_at_offset};
/// let mut t = StabsScopeTracker::new();
/// t.feed_fun("foo", 0x1000).ok();
/// t.feed_lbrac(0x1010);
/// t.feed_rbrac(0x1020).ok();
/// t.finalise(0x1050);
/// let s = scope_at_offset(t.scopes(), 0x1015);
/// assert!(s.is_some());
/// ```
#[must_use]
pub fn scope_at_offset(scopes: &[Scope], offset: u64) -> Option<&Scope> {
    // Walk all scopes and pick the deepest (smallest size) that contains offset.
    scopes
        .iter()
        .filter(|s| s.contains(offset))
        .min_by_key(|s| s.size())
}

/// Return all scopes active at `offset`, ordered from outermost to innermost.
#[must_use]
pub fn scopes_at_offset(scopes: &[Scope], offset: u64) -> Vec<&Scope> {
    let mut matching: Vec<&Scope> = scopes.iter().filter(|s| s.contains(offset)).collect();
    // Outermost first: sort by scope size descending.
    matching.sort_by(|a, b| b.size().cmp(&a.size()));
    matching
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tracker() -> StabsScopeTracker {
        let mut t = StabsScopeTracker::new();
        t.feed_fun("foo", 0x1000).unwrap();
        t.feed_lbrac(0x1010);
        t.feed_rbrac(0x1020).unwrap();
        t.feed_fun("bar", 0x2000).unwrap();
        t.feed_lbrac(0x2010);
        t.feed_lbrac(0x2020);
        t.feed_rbrac(0x2030).unwrap();
        t.feed_rbrac(0x2040).unwrap();
        t.finalise(0x3000);
        t
    }

    #[test]
    fn scope_count() {
        let t = build_tracker();
        // TU + foo + block(foo) + bar + block1(bar) + block2(bar)
        assert!(t.len() >= 5);
    }

    #[test]
    fn scope_at_offset_inside_function() {
        let t = build_tracker();
        let s = scope_at_offset(t.scopes(), 0x1005).unwrap();
        assert!(matches!(&s.kind, ScopeKind::Function { name } if name == "foo"));
    }

    #[test]
    fn scope_at_offset_inside_block() {
        let t = build_tracker();
        let s = scope_at_offset(t.scopes(), 0x1015).unwrap();
        assert!(matches!(s.kind, ScopeKind::LexicalBlock { .. }));
    }

    #[test]
    fn scope_at_offset_nested_blocks() {
        let t = build_tracker();
        // 0x2025 is inside both nested blocks; should return the innermost.
        let s = scope_at_offset(t.scopes(), 0x2025).unwrap();
        assert!(matches!(s.kind, ScopeKind::LexicalBlock { depth: 2 }));
    }

    #[test]
    fn scope_at_offset_between_functions() {
        let t = build_tracker();
        // Between foo (ends ~0x1050 due to finalise) and bar (starts 0x2000),
        // only the TU scope should match at 0x1500.
        let s = scope_at_offset(t.scopes(), 0x1500).unwrap();
        assert!(matches!(s.kind, ScopeKind::TranslationUnit));
    }

    #[test]
    fn scopes_at_offset_order() {
        let t = build_tracker();
        let stack = scopes_at_offset(t.scopes(), 0x2025);
        // Outermost (largest) should be first.
        assert!(stack.len() >= 2);
        assert!(stack[0].size() >= stack[1].size());
    }

    #[test]
    fn unmatched_rbrac_error() {
        let mut t = StabsScopeTracker::new();
        let r = t.feed_rbrac(0x100);
        assert!(r.is_err());
    }

    #[test]
    fn fun_end_marker_returns_err() {
        let mut t = StabsScopeTracker::new();
        t.feed_fun("foo", 0x1000).unwrap();
        let r = t.feed_fun("", 0x1050);
        assert!(matches!(r, Err(TrackerError::FunEnd)));
        t.finalise(0x1100);
    }

    #[test]
    fn scope_contains() {
        let s = Scope {
            kind: ScopeKind::TranslationUnit,
            start_offset: 0x100,
            end_offset: 0x200,
            index: 0,
            parent_index: None,
        };
        assert!(s.contains(0x150));
        assert!(!s.contains(0x100 - 1));
        assert!(!s.contains(0x200));
    }

    #[test]
    fn scope_size() {
        let s = Scope {
            kind: ScopeKind::TranslationUnit,
            start_offset: 0,
            end_offset: 256,
            index: 0,
            parent_index: None,
        };
        assert_eq!(s.size(), 256);
    }

    #[test]
    fn scope_display() {
        let s = Scope {
            kind: ScopeKind::Function { name: "main".to_owned() },
            start_offset: 0x1000,
            end_offset: 0x2000,
            index: 1,
            parent_index: Some(0),
        };
        let d = s.to_string();
        assert!(d.contains("main"));
        assert!(d.contains("0x1000"));
    }

    #[test]
    fn tracker_is_empty_initially() {
        let t = StabsScopeTracker::new();
        assert!(t.is_empty());
    }
}
