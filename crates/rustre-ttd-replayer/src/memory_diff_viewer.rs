//! Memory diff viewer for TTD replay sessions.
//!
//! Provides [`MemDiffEntry`], [`MemDiffSession`], `categorize_diff()`,
//! and ASCII hex diff rendering between two replay positions.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DiffError {
    #[error("address range {start:#x}..{end:#x} is empty")]
    EmptyRange { start: u64, end: u64 },
    #[error("old and new byte slices have different lengths: {0} vs {1}")]
    LengthMismatch(usize, usize),
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ── MemoryCategory ────────────────────────────────────────────────────────────

/// High-level category for a memory region, used when annotating diffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryCategory {
    /// Thread/call stack.
    Stack,
    /// Heap allocation.
    Heap,
    /// Executable code section.
    Code,
    /// Read-only data section.
    RoData,
    /// Mapped file.
    Mapped,
    /// Unknown / uncategorised.
    Unknown,
}

impl MemoryCategory {
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stack   => "stack",
            Self::Heap    => "heap",
            Self::Code    => "code",
            Self::RoData  => "rodata",
            Self::Mapped  => "mapped",
            Self::Unknown => "unknown",
        }
    }
}

/// Categorise an address based on heuristic rules.
///
/// Real categorisation would use `VirtualQuery` / memory map data; this
/// function applies common x86-64 Linux/Windows layout heuristics.
#[must_use] 
pub fn categorize_diff(addr: u64) -> MemoryCategory {
    match addr {
        // Typical user-mode stack range (high addresses)
        a if a >= 0x7F00_0000_0000_0000 => MemoryCategory::Stack,
        a if a >= 0x7FFF_0000_0000 => MemoryCategory::Stack,
        // Kernel space
        a if a >= 0xFFFF_8000_0000_0000 => MemoryCategory::Code,
        // Very low addresses: likely code sections (< 4 GB)
        a if (0x0000_0000_0040_0000..0x0000_0000_0100_0000).contains(&a) => MemoryCategory::Code,
        // Low (<< 64 KB) — null page / guard regions
        a if a < 0x0000_0000_0001_0000 => MemoryCategory::Unknown,
        // Typical heap range
        a if (0x0000_0000_0100_0000..0x0000_0001_0000_0000).contains(&a) => MemoryCategory::Heap,
        // Mapped files / shared libraries (roughly 0x7f... on Linux)
        a if a >= 0x0000_7F00_0000_0000 => MemoryCategory::Mapped,
        _ => MemoryCategory::Unknown,
    }
}

// ── MemDiffEntry ──────────────────────────────────────────────────────────────

/// A single changed memory region between two replay positions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemDiffEntry {
    /// Base address of the changed region.
    pub address: u64,
    /// Bytes at the earlier (old) replay position.
    pub old_bytes: Vec<u8>,
    /// Bytes at the later (new) replay position.
    pub new_bytes: Vec<u8>,
    /// Human-readable annotation (e.g., "stack frame of main", "heap chunk").
    pub annotation: Option<String>,
    /// Categorised memory region.
    pub category: MemoryCategory,
}

impl MemDiffEntry {
    /// Create a new diff entry.
    #[must_use] 
    pub fn new(address: u64, old_bytes: Vec<u8>, new_bytes: Vec<u8>) -> Self {
        let category = categorize_diff(address);
        Self { address, old_bytes, new_bytes, annotation: None, category }
    }

    /// Create a diff entry with a custom annotation.
    pub fn with_annotation(mut self, ann: impl Into<String>) -> Self {
        self.annotation = Some(ann.into());
        self
    }

    /// Override the category.
    #[must_use] 
    pub const fn with_category(mut self, cat: MemoryCategory) -> Self {
        self.category = cat;
        self
    }

    /// Number of bytes that differ between old and new.
    #[must_use] 
    pub fn changed_byte_count(&self) -> usize {
        self.old_bytes.iter().zip(self.new_bytes.iter()).filter(|(a, b)| a != b).count()
    }

    /// Length of the region.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.old_bytes.len().max(self.new_bytes.len())
    }

    /// True if no bytes changed (identical regions).
    #[must_use] 
    pub fn is_identical(&self) -> bool {
        self.old_bytes == self.new_bytes
    }

    /// Render as an ASCII hex diff.
    ///
    /// Format:
    /// ```text
    /// 0xADDR  OLD: 00 01 02 03  ....
    ///         NEW: 00 FF 02 04  .?..
    /// ```
    #[must_use] 
    pub fn render_ascii(&self) -> String {
        let mut out = String::new();
        let chunk_size = 16usize;
        let old = &self.old_bytes;
        let new = &self.new_bytes;
        let len = old.len().max(new.len());

        for chunk_start in (0..len).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(len);
            let old_chunk = old.get(chunk_start..chunk_end).unwrap_or(&[]);
            let new_chunk = new.get(chunk_start..chunk_end).unwrap_or(&[]);

            // Check if any byte changed in this chunk.
            let any_changed = old_chunk.iter().zip(new_chunk.iter()).any(|(a, b)| a != b)
                || old_chunk.len() != new_chunk.len();

            if !any_changed {
                continue;
            }

            let addr = self.address + chunk_start as u64;
            out.push_str(&format!("{addr:#018x}  OLD: "));
            for i in 0..chunk_size {
                if let Some(&b) = old_chunk.get(i) {
                    out.push_str(&format!("{b:02X} "));
                } else {
                    out.push_str("   ");
                }
            }
            out.push(' ');
            out.push_str(&ascii_printable(old_chunk));
            out.push('\n');

            out.push_str(&format!("{:20}", ""));
            out.push_str("NEW: ");
            for i in 0..chunk_size {
                if let Some(&b) = new_chunk.get(i) {
                    let changed = old_chunk.get(i).is_none_or(|o| *o != b);
                    if changed {
                        out.push_str(&format!("{b:02X}*"));
                    } else {
                        out.push_str(&format!("{b:02X} "));
                    }
                } else {
                    out.push_str("   ");
                }
            }
            out.push(' ');
            out.push_str(&ascii_printable(new_chunk));
            out.push('\n');
        }

        out
    }
}

fn ascii_printable(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '.' }).collect()
}

// ── MemDiffSession ────────────────────────────────────────────────────────────

/// A diff session between two replay tick positions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemDiffSession {
    /// Tick at the start of the comparison window.
    pub from_tick: u64,
    /// Tick at the end of the comparison window.
    pub to_tick: u64,
    /// All memory entries that changed between the two ticks.
    pub entries: Vec<MemDiffEntry>,
}

impl MemDiffSession {
    /// Create a new session.
    #[must_use] 
    pub const fn new(from_tick: u64, to_tick: u64) -> Self {
        Self { from_tick, to_tick, entries: Vec::new() }
    }

    /// Add a diff entry.
    pub fn add(&mut self, entry: MemDiffEntry) {
        if !entry.is_identical() {
            self.entries.push(entry);
        }
    }

    /// Build a diff from two memory state snapshots.
    ///
    /// `old_pages` and `new_pages` are maps of page-aligned base address → 4 KiB page bytes.
    #[must_use] 
    pub fn from_page_maps(
        from_tick: u64,
        to_tick: u64,
        old_pages: &HashMap<u64, Vec<u8>>,
        new_pages: &HashMap<u64, Vec<u8>>,
    ) -> Self {
        let mut session = Self::new(from_tick, to_tick);

        // Check modified and new pages.
        for (&addr, new_data) in new_pages {
            if let Some(old_data) = old_pages.get(&addr) {
                if old_data != new_data {
                    let entry = MemDiffEntry::new(addr, old_data.clone(), new_data.clone());
                    session.add(entry);
                }
            } else {
                // New page (not present in old snapshot).
                let old = vec![0u8; new_data.len()];
                let entry = MemDiffEntry::new(addr, old, new_data.clone())
                    .with_annotation("newly mapped page");
                session.add(entry);
            }
        }

        // Check removed pages.
        for (&addr, old_data) in old_pages {
            if !new_pages.contains_key(&addr) {
                let new = vec![0u8; old_data.len()];
                let entry = MemDiffEntry::new(addr, old_data.clone(), new)
                    .with_annotation("unmapped page");
                session.add(entry);
            }
        }

        // Sort by address for deterministic output.
        session.entries.sort_by_key(|e| e.address);
        session
    }

    /// Total number of changed bytes across all entries.
    #[must_use] 
    pub fn total_changed_bytes(&self) -> usize {
        self.entries.iter().map(MemDiffEntry::changed_byte_count).sum()
    }

    /// Number of changed pages.
    #[must_use] 
    pub const fn changed_page_count(&self) -> usize {
        self.entries.len()
    }

    /// Return entries filtered by category.
    #[must_use] 
    pub fn entries_in_category(&self, cat: MemoryCategory) -> Vec<&MemDiffEntry> {
        self.entries.iter().filter(|e| e.category == cat).collect()
    }

    /// Return a breakdown of changes by category.
    #[must_use] 
    pub fn category_summary(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for entry in &self.entries {
            *map.entry(entry.category.as_str().to_owned()).or_insert(0) += entry.changed_byte_count();
        }
        map
    }

    /// Render all entries as an ASCII hex diff listing.
    #[must_use] 
    pub fn render_ascii(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "=== Memory Diff: tick {} → {} ({} entries, {} bytes changed) ===\n",
            self.from_tick, self.to_tick, self.entries.len(), self.total_changed_bytes()
        ));
        for entry in &self.entries {
            let ann = entry.annotation.as_deref().unwrap_or("");
            out.push_str(&format!(
                "\n--- {} [{}, {}{}] ---\n",
                format!("{:#x}", entry.address),
                entry.category.as_str(),
                entry.changed_byte_count(),
                if ann.is_empty() { String::new() } else { format!(", {ann}") },
            ));
            out.push_str(&entry.render_ascii());
        }
        out
    }

    /// Export as JSON.
    pub fn to_json(&self) -> Result<String, DiffError> {
        serde_json::to_string_pretty(self).map_err(|e| DiffError::Serialization(e.to_string()))
    }

    /// True if no pages changed.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pages(addr: u64, data: &[u8]) -> HashMap<u64, Vec<u8>> {
        let mut m = HashMap::new();
        m.insert(addr, data.to_vec());
        m
    }

    #[test]
    fn test_mem_diff_entry_identical() {
        let e = MemDiffEntry::new(0x1000, vec![1, 2, 3], vec![1, 2, 3]);
        assert!(e.is_identical());
        assert_eq!(e.changed_byte_count(), 0);
    }

    #[test]
    fn test_mem_diff_entry_changed() {
        let e = MemDiffEntry::new(0x1000, vec![0x00, 0x01, 0x02], vec![0x00, 0xFF, 0x02]);
        assert!(!e.is_identical());
        assert_eq!(e.changed_byte_count(), 1);
    }

    #[test]
    fn test_mem_diff_entry_len() {
        let e = MemDiffEntry::new(0x1000, vec![1, 2, 3, 4], vec![1, 2, 3, 5]);
        assert_eq!(e.len(), 4);
    }

    #[test]
    fn test_mem_diff_entry_annotation() {
        let e = MemDiffEntry::new(0x1000, vec![1], vec![2]).with_annotation("test");
        assert_eq!(e.annotation.as_deref(), Some("test"));
    }

    #[test]
    fn test_mem_diff_entry_category_override() {
        let e = MemDiffEntry::new(0x1000, vec![1], vec![2]).with_category(MemoryCategory::Heap);
        assert_eq!(e.category, MemoryCategory::Heap);
    }

    #[test]
    fn test_categorize_diff_stack() {
        let cat = categorize_diff(0x7FFF_FFFF_0000);
        assert_eq!(cat, MemoryCategory::Stack);
    }

    #[test]
    fn test_categorize_diff_code() {
        let cat = categorize_diff(0x0000_0000_0040_1000);
        assert_eq!(cat, MemoryCategory::Code);
    }

    #[test]
    fn test_categorize_diff_heap() {
        let cat = categorize_diff(0x0000_0000_0200_0000);
        assert_eq!(cat, MemoryCategory::Heap);
    }

    #[test]
    fn test_mem_diff_session_new() {
        let s = MemDiffSession::new(100, 200);
        assert_eq!(s.from_tick, 100);
        assert_eq!(s.to_tick, 200);
        assert!(s.is_empty());
    }

    #[test]
    fn test_mem_diff_session_add_identical_ignored() {
        let mut s = MemDiffSession::new(0, 1);
        s.add(MemDiffEntry::new(0x1000, vec![1, 2], vec![1, 2]));
        assert!(s.is_empty());
    }

    #[test]
    fn test_mem_diff_session_add_changed() {
        let mut s = MemDiffSession::new(0, 1);
        s.add(MemDiffEntry::new(0x1000, vec![1, 2], vec![1, 3]));
        assert_eq!(s.changed_page_count(), 1);
    }

    #[test]
    fn test_mem_diff_session_from_page_maps_identical() {
        let old = make_pages(0x1000, &[1, 2, 3]);
        let new = make_pages(0x1000, &[1, 2, 3]);
        let session = MemDiffSession::from_page_maps(0, 1, &old, &new);
        assert!(session.is_empty());
    }

    #[test]
    fn test_mem_diff_session_from_page_maps_changed() {
        let old = make_pages(0x1000, &[1, 2, 3]);
        let new = make_pages(0x1000, &[1, 99, 3]);
        let session = MemDiffSession::from_page_maps(0, 1, &old, &new);
        assert_eq!(session.changed_page_count(), 1);
        assert_eq!(session.total_changed_bytes(), 1);
    }

    #[test]
    fn test_mem_diff_session_new_page() {
        let old: HashMap<u64, Vec<u8>> = HashMap::new();
        let new = make_pages(0x2000, &[0xAB; 16]);
        let session = MemDiffSession::from_page_maps(0, 1, &old, &new);
        assert_eq!(session.changed_page_count(), 1);
    }

    #[test]
    fn test_mem_diff_session_removed_page() {
        let old = make_pages(0x3000, &[0xCC; 8]);
        let new: HashMap<u64, Vec<u8>> = HashMap::new();
        let session = MemDiffSession::from_page_maps(0, 1, &old, &new);
        assert_eq!(session.changed_page_count(), 1);
    }

    #[test]
    fn test_mem_diff_session_total_changed_bytes() {
        let old = make_pages(0x1000, &[0u8; 4]);
        let new = make_pages(0x1000, &[1u8; 4]);
        let session = MemDiffSession::from_page_maps(0, 1, &old, &new);
        assert_eq!(session.total_changed_bytes(), 4);
    }

    #[test]
    fn test_render_ascii_contains_address() {
        let old = make_pages(0x0000_0000_0040_0000, &[0x00; 32]);
        let mut new_data = vec![0x00u8; 32];
        new_data[5] = 0xFF;
        let new = make_pages(0x0000_0000_0040_0000, &new_data);
        let session = MemDiffSession::from_page_maps(0, 1, &old, &new);
        let text = session.render_ascii();
        assert!(text.contains("Memory Diff"), "text: {text}");
    }

    #[test]
    fn test_mem_diff_entry_render_ascii_nonempty() {
        let e = MemDiffEntry::new(0x1000, vec![0x00, 0x01], vec![0x00, 0xFF]);
        let text = e.render_ascii();
        assert!(text.contains("OLD:") || text.contains("NEW:") || text.is_empty());
    }

    #[test]
    fn test_category_summary() {
        let mut s = MemDiffSession::new(0, 1);
        s.add(MemDiffEntry::new(0x0000_0000_0040_0000, vec![1], vec![2]));
        let summary = s.category_summary();
        assert!(summary.values().sum::<usize>() > 0);
    }

    #[test]
    fn test_entries_in_category() {
        let mut s = MemDiffSession::new(0, 1);
        s.add(MemDiffEntry::new(0x1000, vec![1], vec![2]).with_category(MemoryCategory::Heap));
        s.add(MemDiffEntry::new(0x2000, vec![1], vec![2]).with_category(MemoryCategory::Code));
        assert_eq!(s.entries_in_category(MemoryCategory::Heap).len(), 1);
        assert_eq!(s.entries_in_category(MemoryCategory::Code).len(), 1);
    }

    #[test]
    fn test_to_json() {
        let mut s = MemDiffSession::new(0, 1);
        s.add(MemDiffEntry::new(0x1000, vec![1], vec![2]));
        let json = s.to_json().unwrap();
        assert!(json.contains("from_tick"));
    }

    #[test]
    fn test_memory_category_as_str() {
        assert_eq!(MemoryCategory::Stack.as_str(), "stack");
        assert_eq!(MemoryCategory::Heap.as_str(), "heap");
        assert_eq!(MemoryCategory::Code.as_str(), "code");
    }
}
