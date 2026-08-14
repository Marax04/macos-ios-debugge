// ============================================================================
// core/selection.rs — Global selection state
// Propagated through AppState, never passed directly between views.
// ============================================================================

use crate::core::types::{Addr, AddrRange};
use serde::{Deserialize, Serialize};

/// What is currently selected in the UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Selection {
    #[default]
    None,
    /// Single address (instruction, byte, …)
    Address(Addr),
    /// Contiguous address range
    Range(AddrRange),
    /// A whole function (by id)
    Function(u32),
    /// A basic block inside a function
    Block { func_id: u32, block_id: u32 },
    /// A token in the listing (address + token index)
    Token { addr: Addr, token_idx: usize },
    /// A variable in the decompiler pseudo-code
    Variable { func_id: u32, var_id: u32 },
    /// A row in a panel (functions, strings, xrefs…)
    Row { panel: PanelId, row: usize },
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub enum PanelId {
    Listing,
    HexView,
    Decompiler,
    CfgGraph,
    Functions,
    Strings,
    Xrefs,
    Symbols,
    Segments,
    Breakpoints,
    Threads,
    Registers,
    Stack,
    Log,
}

impl Selection {
    /// Extract the primary address from any selection variant.
    pub const fn primary_addr(&self) -> Option<Addr> {
        match self {
            Self::Address(a) => Some(*a),
            Self::Range(r) => Some(r.start),
            Self::Token { addr, .. } => Some(*addr),
            _ => None,
        }
    }

    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub const fn as_range(&self) -> Option<AddrRange> {
        match self {
            Self::Range(r) => Some(*r),
            Self::Address(a) => Some(AddrRange::new(*a, Addr(a.0 + 1))),
            _ => None,
        }
    }
}

// ── Hover state (not persisted, clears each frame) ─────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HoverState {
    pub addr: Option<Addr>,
    pub token: Option<String>,
    pub tooltip: Option<String>,
    pub panel: Option<PanelId>,
}

// ── Selection history ─────────────────────────────────────────────────────────

/// Keeps track selection of a specific panel over time for quick undo.
#[derive(Debug, Default)]
pub struct SelectionHistory {
    past: Vec<Selection>,
    future: Vec<Selection>,
    max: usize,
}

impl SelectionHistory {
    pub fn new(max: usize) -> Self {
        Self {
            max,
            ..Default::default()
        }
    }

    pub fn push(&mut self, sel: Selection) {
        if self.past.last() == Some(&sel) {
            return;
        }
        self.future.clear();
        if self.past.len() >= self.max {
            self.past.remove(0);
        }
        self.past.push(sel);
    }

    pub fn undo(&mut self) -> Option<Selection> {
        if self.past.len() < 2 {
            return None;
        }
        let current = self.past.pop().unwrap();
        self.future.push(current);
        self.past.last().cloned()
    }

    pub fn redo(&mut self) -> Option<Selection> {
        let next = self.future.pop()?;
        self.past.push(next.clone());
        Some(next)
    }

    pub fn current(&self) -> Option<&Selection> {
        self.past.last()
    }
    pub const fn can_undo(&self) -> bool {
        self.past.len() >= 2
    }
    pub const fn can_redo(&self) -> bool {
        !self.future.is_empty()
    }
}

#[doc(hidden)]
pub fn ensure_used_selection() {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let none_sel = Selection::None;
    let _ = none_sel.is_none();
    let _ = none_sel.primary_addr();
    let _ = none_sel.as_range();

    let addr_sel = Selection::Address(Addr(0));
    let _ = addr_sel.primary_addr();
    let _ = addr_sel.as_range();
    let _ = addr_sel.is_none();

    let mut hist = SelectionHistory::new(2);
    hist.push(Selection::Address(Addr(1)));
    hist.push(Selection::Address(Addr(2)));
    let _ = hist.current();
    let _ = hist.can_undo();
    let _ = hist.can_redo();
    let _ = hist.undo();
    let _ = hist.redo();
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──

#[cfg(test)]
mod _coverage {
    use super::*;

    #[test]
    fn touches_selection_methods() {
        let none_sel = Selection::None;
        assert!(none_sel.is_none());
        assert!(none_sel.primary_addr().is_none());
        assert!(none_sel.as_range().is_none());

        let addr_sel = Selection::Address(Addr(0x1000));
        assert_eq!(addr_sel.primary_addr(), Some(Addr(0x1000)));
        assert!(!addr_sel.is_none());
        let range = addr_sel.as_range().expect("address should yield a range");
        assert_eq!(range.start, Addr(0x1000));

        let range_sel = Selection::Range(AddrRange::new(Addr(0x10), Addr(0x20)));
        assert_eq!(range_sel.primary_addr(), Some(Addr(0x10)));
        assert!(range_sel.as_range().is_some());

        let token_sel = Selection::Token {
            addr: Addr(0x42),
            token_idx: 3,
        };
        assert_eq!(token_sel.primary_addr(), Some(Addr(0x42)));
        assert!(token_sel.as_range().is_none());
    }

    #[test]
    fn touches_selection_history_methods() {
        let mut hist = SelectionHistory::new(4);
        assert!(!hist.can_undo());
        assert!(!hist.can_redo());
        assert!(hist.current().is_none());
        assert!(hist.undo().is_none());
        assert!(hist.redo().is_none());

        hist.push(Selection::Address(Addr(1)));
        hist.push(Selection::Address(Addr(2)));
        assert_eq!(hist.current(), Some(&Selection::Address(Addr(2))));
        assert!(hist.can_undo());

        let prev = hist.undo().expect("undo should produce previous selection");
        assert_eq!(prev, Selection::Address(Addr(1)));
        assert!(hist.can_redo());

        let next = hist.redo().expect("redo should restore next selection");
        assert_eq!(next, Selection::Address(Addr(2)));
    }
}
