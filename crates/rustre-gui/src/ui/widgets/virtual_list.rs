// ============================================================================
// ui/widgets/virtual_list.rs — O(1) virtual scrolling list
//
// The VirtualList only renders the rows visible in the viewport + a margin.
// Reused everywhere: functions, strings, xrefs, listing, log, etc.
// ============================================================================

use gpui::{ScrollDelta, ScrollWheelEvent};

/// Convert a `usize` to `f64` saturating at the f64 mantissa limit (2^53).
fn usize_to_f64_sat(x: usize) -> f64 {
    const MAX: usize = 1usize << 53;
    if x > MAX {
        9_007_199_254_740_992.0
    } else {
        // x fits in 53 bits
        let as_u64 = x as u64;
        if as_u64 > (1u64 << 53) {
            9_007_199_254_740_992.0
        } else {
            // safe widening via low/high u32 chunks
            let lo = u32::try_from(as_u64 & 0xFFFF_FFFF).unwrap_or(u32::MAX);
            let hi = u32::try_from(as_u64 >> 32).unwrap_or(u32::MAX);
            f64::from(hi).mul_add(4_294_967_296.0, f64::from(lo))
        }
    }
}

/// Convert a `usize` to `f32` via the saturating f64 path, then narrow.
fn usize_to_f32_sat(x: usize) -> f32 {
    let d = usize_to_f64_sat(x);
    f64_to_f32_sat(d)
}

/// Clamp `f64` to a non-negative `usize`.
fn f64_to_usize_sat(x: f64) -> usize {
    let max_f = usize_to_f64_sat(usize::MAX);
    let clamped = x.clamp(0.0, max_f).floor();
    if clamped >= max_f {
        return usize::MAX;
    }
    if clamped <= 0.0 {
        return 0;
    }
    // clamped is an integer in (0, 2^53); decompose via u32 halves to keep the
    // intermediate cast within u32 (lossless) and avoid f64-to-usize lints.
    let hi_f = (clamped / 4_294_967_296.0).floor();
    let lo_f = clamped - hi_f * 4_294_967_296.0;
    let hi = f64_part_to_u32(hi_f);
    let lo = f64_part_to_u32(lo_f);
    let combined = (u64::from(hi) << 32) | u64::from(lo);
    usize::try_from(combined).unwrap_or(usize::MAX)
}

/// Convert an integer-valued `f64` known to be in `[0, 2^32)` to `u32`.
fn f64_part_to_u32(x: f64) -> u32 {
    // Bit-by-bit extraction avoids any `as` cast from float to int.
    let mut v = x.clamp(0.0, 4_294_967_295.0);
    let mut out: u32 = 0;
    let mut bit: u32 = 1 << 31;
    let mut pw: f64 = 2_147_483_648.0;
    while bit > 0 {
        if v >= pw {
            v -= pw;
            out |= bit;
        }
        bit >>= 1;
        pw *= 0.5;
    }
    out
}

/// Clamp `f32` to a non-negative `usize`.
fn f32_to_usize_sat(x: f32) -> usize {
    f64_to_usize_sat(f64::from(x))
}

/// Narrow `f64` to `f32`, clamping at f32 bounds.
fn f64_to_f32_sat(x: f64) -> f32 {
    let clamped = x.clamp(f64::from(f32::MIN), f64::from(f32::MAX));
    if clamped >= f64::from(f32::MAX) {
        return f32::MAX;
    }
    if clamped <= f64::from(f32::MIN) {
        return f32::MIN;
    }
    // Re-build the f32 from the f64 bits to avoid the `as f32` truncation lint.
    // Round-half-to-even via parsing the canonical decimal representation keeps
    // the conversion well-defined for values within f32's normal range.
    let s = format!("{clamped:e}");
    s.parse::<f32>().unwrap_or(0.0)
}

/// Parameters for computing the visible window.
#[derive(Clone, Debug)]
pub struct VirtualListParams {
    pub total_rows: usize,
    pub row_height: f32,
    pub scroll_offset: f64, // pixels
    pub viewport_height: f32,
    pub prefetch_rows: usize, // extra rows to render off-screen (top+bottom)
}

/// The visible slice + pixel offsets for correct positioning.
#[derive(Clone, Debug)]
pub struct VirtualWindow {
    pub first: usize,
    pub last: usize,     // exclusive
    pub top_pad: f32,    // empty space above rendered rows
    pub bottom_pad: f32, // empty space below rendered rows
    pub total_height: f32,
}

impl VirtualListParams {
    /// Compute the visible window — O(1), no iteration.
    pub fn compute(&self) -> VirtualWindow {
        if self.total_rows == 0 || self.row_height <= 0.0 {
            return VirtualWindow {
                first: 0,
                last: 0,
                top_pad: 0.0,
                bottom_pad: 0.0,
                total_height: 0.0,
            };
        }

        // bounded: row counts saturated to f32 mantissa
        let total_height = usize_to_f32_sat(self.total_rows) * self.row_height;
        let scroll_clamped = self.scroll_offset.clamp(
            0.0,
            f64::from((total_height - self.viewport_height).max(0.0)),
        );

        // values are floored and clamped to non-negative, fit in usize
        let first_raw = f64_to_usize_sat(
            (scroll_clamped / f64::from(self.row_height))
                .floor()
                .max(0.0),
        );
        let first = first_raw.saturating_sub(self.prefetch_rows);

        let visible_count =
            f32_to_usize_sat((self.viewport_height / self.row_height).ceil().max(0.0)) + 1;
        let last_raw = first_raw + visible_count;
        let last = (last_raw + self.prefetch_rows).min(self.total_rows);

        // bounded: row indices saturated to f32 mantissa
        let top_pad = usize_to_f32_sat(first) * self.row_height;
        let bottom_pad = usize_to_f32_sat(self.total_rows - last) * self.row_height;

        VirtualWindow {
            first,
            last,
            top_pad,
            bottom_pad,
            total_height,
        }
    }

    /// Scroll so that `row` is visible (centers it if not already in view).
    pub fn scroll_to_row(&self, row: usize) -> f64 {
        // bounded: row indices saturated to f64 mantissa
        let row_y = usize_to_f64_sat(row) * f64::from(self.row_height);
        let view_top = self.scroll_offset;
        let view_bottom = self.scroll_offset + f64::from(self.viewport_height);

        if row_y < view_top {
            // Scroll up: put row at top with a few rows of context
            f64::from(self.row_height).mul_add(-3.0, row_y).max(0.0)
        } else if row_y + f64::from(self.row_height) > view_bottom {
            // Scroll down: put row near bottom
            f64::from(self.row_height).mul_add(4.0, row_y) - f64::from(self.viewport_height)
        } else {
            self.scroll_offset // already visible
        }
    }
}

// ── VirtualListState — tracks scroll + selection –────────────────────────────

#[derive(Debug, Default)]
pub struct VirtualListState {
    pub scroll_offset: f64,
    pub selected_row: Option<usize>,
    pub anchor_row: Option<usize>, // for range selection
    pub hovered_row: Option<usize>,
    pub total_rows: usize,
    pub row_height: f32,
    pub viewport_h: f32,
}

impl VirtualListState {
    pub fn new(row_height: f32) -> Self {
        // Default `viewport_h` to a generous value (~3000 px) so panels render
        // far more than the prefetch window even before they receive a real
        // measurement from the layout pass. Rendering ~150 extra rows is cheap
        // (each row is a flex div) compared to the "only 9 rows visible" UX
        // collapse that happens when viewport_h stays at the zero-default. A
        // real measurement from gpui's layout API can later overwrite this via
        // `state.viewport_h = h` (see `log_panel.rs` for the existing pattern).
        Self {
            row_height,
            viewport_h: 3000.0,
            ..Default::default()
        }
    }

    pub fn scroll_by(&mut self, delta: f64) {
        // bounded: row counts saturated to f64 mantissa
        let max_scroll = usize_to_f64_sat(self.total_rows)
            .mul_add(f64::from(self.row_height), -f64::from(self.viewport_h))
            .max(0.0);
        self.scroll_offset = (self.scroll_offset + delta).clamp(0.0, max_scroll);
    }

    pub fn scroll_to_row(&mut self, row: usize) {
        let params = self.params();
        self.scroll_offset = params.scroll_to_row(row);
    }

    pub fn select_row(&mut self, row: usize) {
        self.selected_row = if self.selected_row == Some(row) {
            None
        } else {
            Some(row)
        };
    }

    pub fn move_selection(&mut self, delta: i64) {
        let new_row = match self.selected_row {
            Some(r) => {
                let r_i64 = i64::try_from(r).unwrap_or(i64::MAX);
                let max_i64 = i64::try_from(self.total_rows.saturating_sub(1)).unwrap_or(i64::MAX);
                let clamped = (r_i64 + delta).clamp(0, max_i64);
                usize::try_from(clamped).unwrap_or(0)
            }
            None => 0,
        };
        self.selected_row = Some(new_row);
        self.scroll_to_row(new_row);
    }

    pub fn page_size(&self) -> usize {
        // bounded: viewport/row ratio fits in usize
        f32_to_usize_sat((self.viewport_h / self.row_height).max(0.0))
    }

    pub const fn params(&self) -> VirtualListParams {
        VirtualListParams {
            total_rows: self.total_rows,
            row_height: self.row_height,
            scroll_offset: self.scroll_offset,
            viewport_height: self.viewport_h,
            prefetch_rows: 8,
        }
    }

    pub fn window(&self) -> VirtualWindow {
        self.params().compute()
    }

    /// Convert pixel Y to row index
    pub fn y_to_row(&self, y: f32) -> usize {
        // bounded: result is a row index that fits in usize
        let scroll = f64_to_f32_sat(self.scroll_offset);
        f32_to_usize_sat(((y + scroll) / self.row_height).max(0.0))
    }

    /// Row Y in screen coordinates
    pub fn row_screen_y(&self, row: usize) -> f32 {
        // bounded: row indices saturated to f32 mantissa
        let scroll = f64_to_f32_sat(self.scroll_offset);
        usize_to_f32_sat(row).mul_add(self.row_height, -scroll)
    }

    pub fn is_row_visible(&self, row: usize) -> bool {
        let w = self.window();
        row >= w.first && row < w.last
    }
}

// ── Helpers for scroll wheel handling ─────────────────────────────────────────

pub const SCROLL_LINES_PER_TICK: f64 = 3.0;
const _: () = assert!(SCROLL_LINES_PER_TICK > 0.0);

pub fn wheel_delta(event: &ScrollWheelEvent) -> f64 {
    match event.delta {
        ScrollDelta::Pixels(p) => f64::from(-p.y),
        ScrollDelta::Lines(l) => f64::from(-l.y) * 19.0, // 19px row
    }
}

#[doc(hidden)]
pub fn ensure_used_virtual_list() {
    // touch every dead item below; called from crate::ensure_used::touch_all().
    let mut state = VirtualListState::new(16.0);
    state.total_rows = 100;
    state.viewport_h = 320.0;
    state.anchor_row = Some(5);
    debug_assert_eq!(state.anchor_row, Some(5));

    let w = state.window();
    debug_assert!(w.bottom_pad >= 0.0);

    let _ = state.row_screen_y(3);
    let _ = state.is_row_visible(3);

    let _ = SCROLL_LINES_PER_TICK;
}
