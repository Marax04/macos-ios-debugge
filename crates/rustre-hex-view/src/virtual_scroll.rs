//! Virtual scrolling for large binary files.
//!
//! Key types:
//! - [`VirtualScrollState`] — viewport offset, size, total bytes.
//! - [`PageCache`] — LRU cache of 4 KiB pages.
//! - [`ScrollAction`] — enumeration of scroll commands.
//! - [`VisibleRows`] — computed rows for the current viewport.
//! - [`LineRenderer`] — hex + ASCII column formatting.
//! - [`VirtualScrollView`] — full interactive view composing all of the above.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// ScrollAction
// ---------------------------------------------------------------------------

/// Commands that can be applied to a [`VirtualScrollState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScrollAction {
    /// Scroll up one row (subtract `bytes_per_row`).
    Up,
    /// Scroll down one row (add `bytes_per_row`).
    Down,
    /// Scroll up one full page.
    PageUp,
    /// Scroll down one full page.
    PageDown,
    /// Jump to an absolute byte offset.
    GoTo(u64),
    /// Jump to the beginning of the buffer.
    Home,
    /// Jump to the last visible position.
    End,
}

impl fmt::Display for ScrollAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Up => write!(f, "Up"),
            Self::Down => write!(f, "Down"),
            Self::PageUp => write!(f, "PageUp"),
            Self::PageDown => write!(f, "PageDown"),
            Self::GoTo(o) => write!(f, "GoTo({o:#x})"),
            Self::Home => write!(f, "Home"),
            Self::End => write!(f, "End"),
        }
    }
}

// ---------------------------------------------------------------------------
// VirtualScrollState
// ---------------------------------------------------------------------------

/// The core scroll state for a virtual hex view.
///
/// All offsets are in bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualScrollState {
    /// Byte offset of the top-left corner of the visible viewport.
    pub viewport_start: u64,
    /// Number of rows visible simultaneously.
    pub viewport_size: usize,
    /// Total file size in bytes.
    pub total_bytes: u64,
    /// Bytes rendered per row.
    pub bytes_per_row: usize,
}

impl VirtualScrollState {
    /// Create a new state.
    #[must_use]
    pub fn new(total_bytes: u64, viewport_size: usize, bytes_per_row: usize) -> Self {
        Self {
            viewport_start: 0,
            viewport_size,
            total_bytes,
            bytes_per_row: bytes_per_row.max(1),
        }
    }

    /// Total number of rows needed to display all data.
    #[must_use]
    pub const fn total_rows(&self) -> u64 {
        let bpr = self.bytes_per_row as u64;
        self.total_bytes.div_ceil(bpr)
    }

    /// Index of the first visible row.
    #[must_use]
    pub const fn top_row(&self) -> u64 {
        self.viewport_start / self.bytes_per_row as u64
    }

    /// Apply a [`ScrollAction`] to update `viewport_start`.
    pub fn apply(&mut self, action: ScrollAction) {
        let bpr = self.bytes_per_row as u64;
        let page = bpr * self.viewport_size as u64;
        let max_start = self.max_viewport_start();
        match action {
            ScrollAction::Up => self.viewport_start = self.viewport_start.saturating_sub(bpr),
            ScrollAction::Down => self.viewport_start = (self.viewport_start + bpr).min(max_start),
            ScrollAction::PageUp => self.viewport_start = self.viewport_start.saturating_sub(page),
            ScrollAction::PageDown => {
                self.viewport_start = (self.viewport_start + page).min(max_start);
            }
            ScrollAction::GoTo(o) => self.viewport_start = self.align_down(o).min(max_start),
            ScrollAction::Home => self.viewport_start = 0,
            ScrollAction::End => self.viewport_start = max_start,
        }
    }

    /// Maximum valid value for `viewport_start`.
    #[must_use]
    pub const fn max_viewport_start(&self) -> u64 {
        let bpr = self.bytes_per_row as u64;
        let page = bpr * self.viewport_size as u64;
        if self.total_bytes > page {
            let rows = self.total_bytes.div_ceil(bpr);
            let vis_rows = self.viewport_size as u64;
            (rows.saturating_sub(vis_rows)) * bpr
        } else {
            0
        }
    }

    /// Return `true` if `offset` is within the current viewport.
    #[must_use]
    pub const fn is_visible(&self, offset: u64) -> bool {
        let end = self.viewport_start + (self.bytes_per_row * self.viewport_size) as u64;
        offset >= self.viewport_start && offset < end
    }

    /// Scroll the viewport so that `offset` is visible.
    pub fn ensure_visible(&mut self, offset: u64) {
        if !self.is_visible(offset) {
            let aligned = self.align_down(offset);
            self.viewport_start = aligned.min(self.max_viewport_start());
        }
    }

    const fn align_down(&self, offset: u64) -> u64 {
        let bpr = self.bytes_per_row as u64;
        (offset / bpr) * bpr
    }

    /// Range of bytes visible: `[viewport_start, viewport_end)`.
    #[must_use]
    pub fn visible_range(&self) -> std::ops::Range<u64> {
        let end = (self.viewport_start + (self.bytes_per_row * self.viewport_size) as u64)
            .min(self.total_bytes);
        self.viewport_start..end
    }
}

// ---------------------------------------------------------------------------
// PageCache
// ---------------------------------------------------------------------------

/// LRU cache of 4 KiB pages backed by raw bytes.
///
/// Each page maps a byte offset (aligned to `page_size`) to a `Vec<u8>`.
pub struct PageCache {
    /// Maximum number of pages to keep.
    pub capacity: usize,
    /// Page size in bytes (default 4096).
    pub page_size: usize,
    cache: HashMap<u64, Vec<u8>>,
    order: VecDeque<u64>,
}

impl PageCache {
    pub const DEFAULT_PAGE_SIZE: usize = 4096;
    pub const DEFAULT_CAPACITY: usize = 64;

    /// Create a new page cache with the given capacity and page size.
    #[must_use]
    pub fn new(capacity: usize, page_size: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            page_size: page_size.max(1),
            cache: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Create a cache with default settings.
    #[must_use]
    pub fn default_cache() -> Self {
        Self::new(Self::DEFAULT_CAPACITY, Self::DEFAULT_PAGE_SIZE)
    }

    /// Look up a page by its aligned byte offset.
    #[must_use]
    pub fn get(&mut self, page_offset: u64) -> Option<&Vec<u8>> {
        if self.cache.contains_key(&page_offset) {
            // Move to back (most recently used).
            if let Some(pos) = self.order.iter().position(|&k| k == page_offset) {
                self.order.remove(pos);
            }
            self.order.push_back(page_offset);
            self.cache.get(&page_offset)
        } else {
            None
        }
    }

    /// Insert a page.
    pub fn insert(&mut self, page_offset: u64, data: Vec<u8>) {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.cache.entry(page_offset) {
            e.insert(data);
            return;
        }
        // Evict oldest if at capacity.
        while self.cache.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.cache.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(page_offset);
        self.cache.insert(page_offset, data);
    }

    /// Read bytes starting at `offset` for up to `len` bytes from the cache.
    ///
    /// Returns `None` if the required page is not cached.
    #[must_use]
    pub fn read(&mut self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let page_size = self.page_size as u64;
        let page_off = (offset / page_size) * page_size;
        let local_off = (offset - page_off) as usize;
        let page = self.get(page_off)?;
        let end = (local_off + len).min(page.len());
        Some(page[local_off..end].to_vec())
    }

    /// Number of pages currently cached.
    #[must_use]
    pub fn cached_pages(&self) -> usize {
        self.cache.len()
    }

    /// Evict a specific page.
    pub fn evict(&mut self, page_offset: u64) {
        self.cache.remove(&page_offset);
        if let Some(pos) = self.order.iter().position(|&k| k == page_offset) {
            self.order.remove(pos);
        }
    }

    /// Clear all cached pages.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.order.clear();
    }

    /// Pre-populate cache from a byte slice.
    pub fn populate_from(&mut self, data: &[u8]) {
        let ps = self.page_size;
        for (i, chunk) in data.chunks(ps).enumerate() {
            let offset = (i * ps) as u64;
            self.insert(offset, chunk.to_vec());
        }
    }
}

impl fmt::Debug for PageCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PageCache {{ capacity: {}, cached: {} }}",
            self.capacity,
            self.cache.len()
        )
    }
}

// ---------------------------------------------------------------------------
// VisibleRows
// ---------------------------------------------------------------------------

/// Computed visible rows for the current viewport.
#[derive(Debug, Clone)]
pub struct VisibleRows {
    /// `(row_index, byte_offset, bytes)` for each visible row.
    pub rows: Vec<(u64, u64, Vec<u8>)>,
    /// Bytes per row.
    pub bytes_per_row: usize,
}

impl VisibleRows {
    /// Build visible rows from raw data and scroll state.
    #[must_use]
    pub fn build(data: &[u8], state: &VirtualScrollState) -> Self {
        let bpr = state.bytes_per_row;
        let start = state.viewport_start as usize;
        let rows_to_show = state.viewport_size;
        let mut rows = Vec::with_capacity(rows_to_show);

        for row_idx in 0..rows_to_show as u64 {
            let row_off = (row_idx as usize).saturating_mul(bpr);
            let byte_off = start.saturating_add(row_off);
            if byte_off >= data.len() {
                break;
            }
            let end = (byte_off + bpr).min(data.len());
            rows.push((row_idx, byte_off as u64, data[byte_off..end].to_vec()));
        }

        Self {
            rows,
            bytes_per_row: bpr,
        }
    }

    /// Number of visible rows.
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get the bytes for row `idx`.
    #[must_use]
    pub fn row_bytes(&self, idx: usize) -> Option<&[u8]> {
        self.rows.get(idx).map(|(_, _, b)| b.as_slice())
    }
}

// ---------------------------------------------------------------------------
// LineRenderer
// ---------------------------------------------------------------------------

/// Renders a single row as hex + ASCII columns.
pub struct LineRenderer {
    pub bytes_per_row: usize,
    pub group_size: usize,
    pub uppercase: bool,
    pub show_ascii: bool,
    pub show_offset: bool,
}

impl Default for LineRenderer {
    fn default() -> Self {
        Self {
            bytes_per_row: 16,
            group_size: 1,
            uppercase: true,
            show_ascii: true,
            show_offset: true,
        }
    }
}

impl LineRenderer {
    /// Create a renderer with 16 bytes per row.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Render `(offset, bytes)` into a single display line.
    #[must_use]
    pub fn render(&self, offset: u64, bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(
            10 + self.bytes_per_row * 3 + if self.show_ascii { self.bytes_per_row + 4 } else { 0 },
        );
        if self.show_offset {
            let _ = write!(s, "{offset:08X}  ");
        }
        // Hex part.
        let gs = self.group_size.max(1);
        for (i, &b) in bytes.iter().enumerate() {
            if i > 0 && i.is_multiple_of(gs) {
                s.push(' ');
            }
            if self.uppercase {
                let _ = write!(s, "{b:02X}");
            } else {
                let _ = write!(s, "{b:02x}");
            }
        }
        // Padding.
        let mut filled = bytes.len();
        while filled < self.bytes_per_row {
            if filled > 0 && filled.is_multiple_of(gs) {
                s.push(' ');
            }
            s.push_str("  ");
            filled += 1;
        }
        // ASCII part.
        if self.show_ascii {
            s.push_str("  |");
            for &b in bytes {
                s.push(if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                });
            }
            s.push('|');
        }
        s
    }

    /// Render all visible rows.
    #[must_use]
    pub fn render_rows(&self, rows: &VisibleRows) -> Vec<String> {
        rows.rows
            .iter()
            .map(|(_, off, bytes)| self.render(*off, bytes))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// VirtualScrollView
// ---------------------------------------------------------------------------

/// Full virtual scroll view: combines state, cache, and renderer.
pub struct VirtualScrollView {
    pub state: VirtualScrollState,
    pub cache: PageCache,
    pub renderer: LineRenderer,
}

impl VirtualScrollView {
    /// Create a view over a complete byte slice.
    #[must_use]
    pub fn new(data: &[u8], viewport_size: usize, bytes_per_row: usize) -> Self {
        let mut cache = PageCache::default_cache();
        cache.populate_from(data);
        Self {
            state: VirtualScrollState::new(data.len() as u64, viewport_size, bytes_per_row),
            cache,
            renderer: LineRenderer::default(),
        }
    }

    /// Apply a scroll action.
    pub fn scroll(&mut self, action: ScrollAction) {
        self.state.apply(action);
    }

    /// Render currently visible rows from the cache.
    #[must_use]
    pub fn render_visible(&mut self) -> Vec<String> {
        let range = self.state.visible_range();
        let start = range.start as usize;
        let len = (range.end - range.start) as usize;
        let bpr = self.state.bytes_per_row;

        // Pull bytes from cache.
        let bytes = if let Some(data) = self.cache.read(start as u64, len) {
            data
        } else {
            vec![0u8; len]
        };

        let rows = VisibleRows::build(
            &bytes,
            &VirtualScrollState {
                viewport_start: 0, // already sliced
                viewport_size: self.state.viewport_size,
                total_bytes: bytes.len() as u64,
                bytes_per_row: bpr,
            },
        );

        // Re-compute offsets relative to file.
        rows.rows
            .iter()
            .map(|(_, local_off, b)| self.renderer.render(start as u64 + local_off, b))
            .collect()
    }

    /// Total rows needed to display all data.
    #[must_use]
    pub fn total_rows(&self) -> u64 {
        self.state.total_rows()
    }

    /// Current scroll position as a fraction in [0.0, 1.0].
    #[must_use]
    pub fn scroll_fraction(&self) -> f64 {
        let max = self.state.max_viewport_start();
        if max == 0 {
            return 0.0;
        }
        self.state.viewport_start as f64 / max as f64
    }
}

impl fmt::Debug for VirtualScrollView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VirtualScrollView {{ rows: {}, offset: {:#x} }}",
            self.total_rows(),
            self.state.viewport_start
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(n).collect()
    }

    // VirtualScrollState

    #[test]
    fn test_scroll_state_new() {
        let s = VirtualScrollState::new(1024, 24, 16);
        assert_eq!(s.total_bytes, 1024);
        assert_eq!(s.bytes_per_row, 16);
        assert_eq!(s.total_rows(), 64);
    }

    #[test]
    fn test_scroll_state_apply_down() {
        let mut s = VirtualScrollState::new(1024, 4, 16);
        s.apply(ScrollAction::Down);
        assert_eq!(s.viewport_start, 16);
    }

    #[test]
    fn test_scroll_state_apply_up_from_zero() {
        let mut s = VirtualScrollState::new(1024, 4, 16);
        s.apply(ScrollAction::Up);
        assert_eq!(s.viewport_start, 0);
    }

    #[test]
    fn test_scroll_state_apply_home() {
        let mut s = VirtualScrollState::new(1024, 4, 16);
        s.apply(ScrollAction::GoTo(512));
        s.apply(ScrollAction::Home);
        assert_eq!(s.viewport_start, 0);
    }

    #[test]
    fn test_scroll_state_apply_end() {
        let mut s = VirtualScrollState::new(1024, 4, 16);
        s.apply(ScrollAction::End);
        assert!(s.viewport_start > 0);
    }

    #[test]
    fn test_scroll_state_apply_goto() {
        let mut s = VirtualScrollState::new(4096, 4, 16);
        s.apply(ScrollAction::GoTo(256));
        assert_eq!(s.viewport_start, 256);
    }

    #[test]
    fn test_scroll_state_is_visible() {
        let s = VirtualScrollState::new(4096, 4, 16);
        assert!(s.is_visible(0));
        assert!(s.is_visible(16 * 3));
        assert!(!s.is_visible(16 * 5));
    }

    #[test]
    fn test_scroll_state_ensure_visible() {
        let mut s = VirtualScrollState::new(4096, 4, 16);
        s.ensure_visible(512);
        assert!(s.is_visible(512));
    }

    #[test]
    fn test_scroll_state_page_down() {
        let mut s = VirtualScrollState::new(4096, 4, 16);
        s.apply(ScrollAction::PageDown);
        assert!(s.viewport_start >= 16 * 4);
    }

    #[test]
    fn test_scroll_state_visible_range() {
        let s = VirtualScrollState::new(256, 4, 16);
        let r = s.visible_range();
        assert_eq!(r.start, 0);
        assert_eq!(r.end, 64); // min(0 + 4*16, 256) = 64
    }

    // PageCache

    #[test]
    fn test_page_cache_insert_and_get() {
        let mut c = PageCache::new(8, 64);
        c.insert(0, vec![1u8; 64]);
        assert!(c.get(0).is_some());
    }

    #[test]
    fn test_page_cache_miss() {
        let mut c = PageCache::new(8, 64);
        assert!(c.get(64).is_none());
    }

    #[test]
    fn test_page_cache_eviction() {
        let mut c = PageCache::new(2, 64);
        c.insert(0, vec![0u8; 64]);
        c.insert(64, vec![1u8; 64]);
        c.insert(128, vec![2u8; 64]); // should evict page 0
        assert_eq!(c.cached_pages(), 2);
    }

    #[test]
    fn test_page_cache_read() {
        let mut c = PageCache::new(4, 256);
        c.insert(0, vec![0xABu8; 256]);
        let bytes = c.read(10, 4).unwrap();
        assert_eq!(bytes, [0xAB; 4]);
    }

    #[test]
    fn test_page_cache_populate_from() {
        let mut c = PageCache::new(16, 64);
        c.populate_from(&sample(256));
        assert!(c.cached_pages() >= 4);
    }

    #[test]
    fn test_page_cache_clear() {
        let mut c = PageCache::new(4, 64);
        c.insert(0, vec![0u8; 64]);
        c.clear();
        assert_eq!(c.cached_pages(), 0);
    }

    #[test]
    fn test_page_cache_evict_single() {
        let mut c = PageCache::new(4, 64);
        c.insert(0, vec![0u8; 64]);
        c.evict(0);
        assert!(c.get(0).is_none());
    }

    // VisibleRows

    #[test]
    fn test_visible_rows_build() {
        let data = sample(256);
        let state = VirtualScrollState::new(256, 4, 16);
        let rows = VisibleRows::build(&data, &state);
        assert_eq!(rows.row_count(), 4);
    }

    #[test]
    fn test_visible_rows_row_bytes() {
        let data = vec![0xAAu8; 64];
        let state = VirtualScrollState::new(64, 2, 16);
        let rows = VisibleRows::build(&data, &state);
        let b = rows.row_bytes(0).unwrap();
        assert_eq!(b[0], 0xAA);
    }

    #[test]
    fn test_visible_rows_partial_last() {
        let data = sample(20);
        let state = VirtualScrollState::new(20, 4, 16);
        let rows = VisibleRows::build(&data, &state);
        assert_eq!(rows.row_count(), 2);
        assert_eq!(rows.rows[1].2.len(), 4);
    }

    // LineRenderer

    #[test]
    fn test_line_renderer_basic() {
        let r = LineRenderer::default();
        let line = r.render(0, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(line.contains("DE"));
        assert!(line.contains("AD"));
        assert!(line.starts_with("00000000"));
    }

    #[test]
    fn test_line_renderer_ascii() {
        let r = LineRenderer::default();
        let line = r.render(0, b"Hello");
        assert!(line.contains("|Hello"));
    }

    #[test]
    fn test_line_renderer_no_offset() {
        let r = LineRenderer {
            show_offset: false,
            ..LineRenderer::default()
        };
        let line = r.render(0, &[0xAA]);
        assert!(!line.starts_with("00000000"));
    }

    #[test]
    fn test_line_renderer_lowercase() {
        let r = LineRenderer {
            uppercase: false,
            ..LineRenderer::default()
        };
        let line = r.render(0, &[0xAB]);
        assert!(line.contains("ab"));
    }

    // VirtualScrollView

    #[test]
    fn test_virtual_scroll_view_new() {
        let data = sample(1024);
        let v = VirtualScrollView::new(&data, 8, 16);
        assert_eq!(v.state.total_bytes, 1024);
    }

    #[test]
    fn test_virtual_scroll_view_render() {
        let data = sample(256);
        let mut v = VirtualScrollView::new(&data, 4, 16);
        let lines = v.render_visible();
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn test_virtual_scroll_view_scroll_fraction_start() {
        let data = sample(1024);
        let v = VirtualScrollView::new(&data, 4, 16);
        assert_eq!(v.scroll_fraction(), 0.0);
    }

    #[test]
    fn test_virtual_scroll_view_scroll_action() {
        let data = sample(1024);
        let mut v = VirtualScrollView::new(&data, 4, 16);
        v.scroll(ScrollAction::PageDown);
        assert!(v.state.viewport_start > 0);
    }

    #[test]
    fn test_scroll_action_display() {
        assert_eq!(ScrollAction::Up.to_string(), "Up");
        assert_eq!(ScrollAction::GoTo(0x100).to_string(), "GoTo(0x100)");
    }
}
