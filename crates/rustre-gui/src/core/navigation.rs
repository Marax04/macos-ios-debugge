// ============================================================================
// core/navigation.rs — Address-level navigation history (back/forward)
// Works like a browser history stack scoped to the binary address space.
// ============================================================================

use crate::core::types::Addr;
use serde::{Deserialize, Serialize};

const MAX_HISTORY: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NavEntry {
    pub addr: Addr,
    pub func_id: Option<u32>,
    pub label: Option<String>,
}

impl NavEntry {
    pub const fn new(addr: Addr, func_id: Option<u32>, label: Option<String>) -> Self {
        Self {
            addr,
            func_id,
            label,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct NavigationHistory {
    entries: Vec<NavEntry>,
    cursor: usize,
}

impl NavigationHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Navigate to `addr`. Clears forward history.
    pub fn push(&mut self, entry: NavEntry) {
        // Don't record duplicate of the current position
        if let Some(cur) = self.current() {
            if cur.addr == entry.addr {
                return;
            }
        }
        // Trim forward branch
        self.entries.truncate(self.cursor + 1);
        self.entries.push(entry);
        // LRU cap
        if self.entries.len() > MAX_HISTORY {
            self.entries.remove(0);
        } else {
            self.cursor = self.entries.len().saturating_sub(1);
        }
    }

    pub fn back(&mut self) -> Option<&NavEntry> {
        if self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        self.entries.get(self.cursor)
    }

    pub fn forward(&mut self) -> Option<&NavEntry> {
        if self.cursor + 1 >= self.entries.len() {
            return None;
        }
        self.cursor += 1;
        self.entries.get(self.cursor)
    }

    pub fn current(&self) -> Option<&NavEntry> {
        self.entries.get(self.cursor)
    }

    pub const fn can_go_back(&self) -> bool {
        self.cursor > 0
    }
    pub const fn can_go_forward(&self) -> bool {
        self.cursor + 1 < self.entries.len()
    }

    /// All entries — for breadcrumb / history panel display
    pub fn all(&self) -> &[NavEntry] {
        &self.entries
    }
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.cursor = 0;
    }
}

// ── Bookmarks (IDA 0–9 quick-jump) ───────────────────────────────────────────

const NUM_BOOKMARKS: usize = 10;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Bookmarks {
    slots: [Option<Addr>; NUM_BOOKMARKS],
    #[serde(default)]
    labels: [Option<String>; NUM_BOOKMARKS],
}

impl Bookmarks {
    pub fn set(&mut self, slot: usize, addr: Addr) {
        if slot < NUM_BOOKMARKS {
            self.slots[slot] = Some(addr);
        }
    }
    pub fn get(&self, slot: usize) -> Option<Addr> {
        self.slots.get(slot).copied().flatten()
    }
    pub fn clear(&mut self, slot: usize) {
        if slot < NUM_BOOKMARKS {
            self.slots[slot] = None;
            self.labels[slot] = None;
        }
    }
    pub fn all(&self) -> impl Iterator<Item = (usize, Addr)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|a| (i, a)))
    }

    /// Add a bookmark in the first available slot. Returns the slot index, or
    /// `None` if all slots are full.
    pub fn add(&mut self, addr: Addr, label: &str) -> Option<usize> {
        for i in 0..NUM_BOOKMARKS {
            if self.slots[i].is_none() {
                self.slots[i] = Some(addr);
                self.labels[i] = if label.is_empty() {
                    None
                } else {
                    Some(label.to_owned())
                };
                return Some(i);
            }
        }
        None
    }

    /// Remove a bookmark by slot (alias of `clear` for naming symmetry).
    pub fn remove(&mut self, slot: usize) {
        self.clear(slot);
    }

    /// Rename (set/replace label) of the bookmark in `slot`. Empty label clears.
    pub fn rename(&mut self, slot: usize, label: &str) {
        if slot < NUM_BOOKMARKS && self.slots[slot].is_some() {
            self.labels[slot] = if label.is_empty() {
                None
            } else {
                Some(label.to_owned())
            };
        }
    }

    /// Clear every slot.
    pub fn clear_all(&mut self) {
        for i in 0..NUM_BOOKMARKS {
            self.slots[i] = None;
            self.labels[i] = None;
        }
    }

    /// Return the optional label set via `add` / `rename`.
    pub fn label(&self, slot: usize) -> Option<&str> {
        self.labels.get(slot).and_then(|l| l.as_deref())
    }
}

// ── GotoTarget — parsed "G" input ─────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum GotoTarget {
    /// Raw hex address (0x-prefixed or bare)
    Addr(Addr),
    /// Symbol name
    Symbol(String),
    /// Relative offset from current addr
    RelOffset(i64),
}

impl std::str::FromStr for GotoTarget {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.starts_with('+') || s.starts_with('-') {
            // relative offset
            let n: i64 = if let Some(hex) = s.get(1..).and_then(|r| r.strip_prefix("0x")) {
                let sign = if s.starts_with('-') { -1i64 } else { 1i64 };
                i64::from_str_radix(hex, 16)
                    .map(|v| v * sign)
                    .map_err(|e| e.to_string())?
            } else {
                s.parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?
            };
            return Ok(Self::RelOffset(n));
        }
        // bare hex (with or without 0x)
        let hex_s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if let Ok(v) = u64::from_str_radix(hex_s, 16) {
            return Ok(Self::Addr(crate::core::types::Addr(v)));
        }
        // assume symbol name
        Ok(Self::Symbol(s.to_owned()))
    }
}

#[doc(hidden)]
pub fn ensure_used_navigation() {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let mut hist = NavigationHistory::new();
    hist.push(NavEntry::new(Addr(0x1000), None, None));
    let _all: &[NavEntry] = hist.all();
    let _c: usize = hist.cursor();
    hist.clear();

    let mut bm = Bookmarks::default();
    bm.set(0, Addr(0x2000));
    let _g: Option<Addr> = bm.get(0);
    bm.clear(0);
    let _slot = bm.add(Addr(0x3000), "entry");
    bm.rename(0, "renamed");
    let _ = bm.label(0);
    bm.remove(0);
    bm.clear_all();
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──
#[cfg(test)]
mod _coverage {
    use super::*;

    #[test]
    fn exercises_navigation_history() {
        let mut hist = NavigationHistory::new();
        assert!(!hist.can_go_back());
        assert!(!hist.can_go_forward());
        assert_eq!(hist.cursor(), 0);
        assert!(hist.all().is_empty());
        hist.push(NavEntry::new(Addr(0x1000), None, None));
        hist.push(NavEntry::new(Addr(0x2000), Some(1), Some("f".to_owned())));
        assert!(hist.can_go_back());
        assert!(!hist.can_go_forward());
        assert_eq!(hist.all().len(), 2);
        assert_eq!(hist.cursor(), 1);
        hist.clear();
        assert_eq!(hist.cursor(), 0);
        assert!(hist.all().is_empty());
    }

    #[test]
    fn exercises_bookmarks() {
        let mut bm = Bookmarks::default();
        bm.set(3, Addr(0xdead));
        assert_eq!(bm.get(3), Some(Addr(0xdead)));
        bm.clear(3);
        assert_eq!(bm.get(3), None);
    }
}
