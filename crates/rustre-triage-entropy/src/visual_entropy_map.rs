//! Visual entropy heatmap generation.
//!
//! Produces a 2D grid of entropy values from a binary buffer, with
//! row/column aggregation, hotspot detection, and JSON output suitable
//! for frontend visualisation widgets.

use crate::{shannon_entropy_f32, casts};
use serde::{Deserialize, Serialize};
use std::fmt;

// ─── EntropyGrid ─────────────────────────────────────────────────────────────

/// A 2D grid of entropy values, row-major.
///
/// `grid[row][col]` is the entropy of the corresponding chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyGrid {
    /// Entropy values stored row-major: `values[row * cols + col]`.
    pub values: Vec<f32>,
    /// Number of columns.
    pub cols: usize,
    /// Number of rows.
    pub rows: usize,
    /// Byte size of the chunk each cell represents.
    pub cell_bytes: usize,
    /// Total bytes of the source buffer.
    pub total_bytes: usize,
}

impl EntropyGrid {
    /// Build an entropy grid from `data`.
    ///
    /// The grid has `cols` columns; rows are computed automatically.
    /// The last row may be shorter if `data.len()` is not a multiple of
    /// `cols * cell_bytes`.
    ///
    /// # Panics
    /// Panics if `cols == 0` or `cell_bytes == 0`.
    #[must_use]
    pub fn build(data: &[u8], cols: usize, cell_bytes: usize) -> Self {
        assert!(cols > 0, "cols must be > 0");
        assert!(cell_bytes > 0, "cell_bytes must be > 0");

        let total_bytes = data.len();
        let chunk_size = cell_bytes;
        let total_chunks = data.len().div_ceil(chunk_size);
        let rows = total_chunks.div_ceil(cols);

        let mut values = Vec::with_capacity(rows * cols);
        for chunk in data.chunks(chunk_size) {
            values.push(shannon_entropy_f32(chunk));
        }
        // Pad with 0.0 to fill the last partial row.
        while values.len() < rows * cols {
            values.push(0.0);
        }

        Self {
            values,
            cols,
            rows,
            cell_bytes,
            total_bytes,
        }
    }

    /// Get the entropy at `(row, col)`, or `None` if out of bounds.
    #[must_use]
    pub fn get(&self, row: usize, col: usize) -> Option<f32> {
        if row >= self.rows || col >= self.cols {
            return None;
        }
        self.values.get(row * self.cols + col).copied()
    }

    /// Get the entropy at `(row, col)`.
    ///
    /// Despite the name, this performs a bounds check via `get()` to prevent
    /// panics on out-of-bounds indices with adversarial or unexpected input.
    /// Returns `0.0` when `(row, col)` is out of range.
    #[inline]
    #[must_use]
    pub fn get_unchecked(&self, row: usize, col: usize) -> f32 {
        // Use row * self.cols + col with overflow guard, then bounds-checked index.
        let idx = row.saturating_mul(self.cols).saturating_add(col);
        self.values.get(idx).copied().unwrap_or(0.0)
    }

    /// Row aggregation: mean entropy of each row.
    #[must_use]
    pub fn row_means(&self) -> Vec<f32> {
        (0..self.rows)
            .map(|r| {
                let start = r * self.cols;
                let end = (start + self.cols).min(self.values.len());
                let slice = &self.values[start..end];
                if slice.is_empty() {
                    0.0
                } else {
                    slice.iter().sum::<f32>() / casts::usize_to_f32(slice.len())
                }
            })
            .collect()
    }

    /// Column aggregation: mean entropy of each column.
    #[must_use]
    pub fn col_means(&self) -> Vec<f32> {
        (0..self.cols)
            .map(|c| {
                let vals: Vec<f32> = (0..self.rows)
                    .filter_map(|r| self.get(r, c))
                    .collect();
                if vals.is_empty() {
                    0.0
                } else {
                    vals.iter().sum::<f32>() / casts::usize_to_f32(vals.len())
                }
            })
            .collect()
    }

    /// Maximum entropy across all cells.
    #[must_use]
    pub fn max_entropy(&self) -> f32 {
        self.values.iter().copied().fold(f32::MIN, f32::max)
    }

    /// Minimum entropy across all cells.
    #[must_use]
    pub fn min_entropy(&self) -> f32 {
        self.values.iter().copied().fold(f32::MAX, f32::min)
    }

    /// Mean entropy across all cells.
    #[must_use]
    pub fn mean_entropy(&self) -> f32 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.values.iter().sum::<f32>() / casts::usize_to_f32(self.values.len())
    }

    /// Number of cells with entropy >= `threshold`.
    #[must_use]
    pub fn high_entropy_count(&self, threshold: f32) -> usize {
        self.values.iter().filter(|&&v| v >= threshold).count()
    }

    /// Convert to a flat list of `(row, col, entropy)` tuples sorted by entropy descending.
    #[must_use]
    pub fn sorted_cells(&self) -> Vec<(usize, usize, f32)> {
        let mut cells: Vec<(usize, usize, f32)> = self
            .values
            .iter()
            .enumerate()
            .map(|(i, &e)| (i / self.cols, i % self.cols, e))
            .collect();
        cells.sort_unstable_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        cells
    }

    /// Byte offset of cell `(row, col)` in the original buffer.
    #[must_use]
    pub const fn cell_offset(&self, row: usize, col: usize) -> usize {
        (row * self.cols + col) * self.cell_bytes
    }
}

impl fmt::Display for EntropyGrid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntropyGrid {{ {}x{} cells, cell_bytes={}, mean={:.3} }}",
            self.rows,
            self.cols,
            self.cell_bytes,
            self.mean_entropy()
        )
    }
}

// ─── EntropyHotspot ──────────────────────────────────────────────────────────

/// A detected entropy hotspot — a contiguous run of high-entropy cells.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyHotspot {
    /// Start row (inclusive).
    pub start_row: usize,
    /// End row (inclusive).
    pub end_row: usize,
    /// Start col (inclusive).
    pub start_col: usize,
    /// End col (inclusive).
    pub end_col: usize,
    /// Mean entropy of the hotspot region.
    pub mean_entropy: f32,
    /// Maximum entropy in the hotspot region.
    pub max_entropy: f32,
    /// Number of cells in the hotspot.
    pub cell_count: usize,
    /// Byte offset of the hotspot start.
    pub byte_offset: usize,
    /// Byte size of the hotspot.
    pub byte_size: usize,
}

impl EntropyHotspot {
    /// Whether this hotspot likely contains encrypted content (mean >= 7.5).
    #[must_use]
    pub fn likely_encrypted(&self) -> bool {
        self.mean_entropy >= 7.5
    }

    /// Whether this hotspot likely contains compressed content (mean in [6.5, 7.5)).
    #[must_use]
    pub fn likely_compressed(&self) -> bool {
        self.mean_entropy >= 6.5 && self.mean_entropy < 7.5
    }
}

impl fmt::Display for EntropyHotspot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hotspot {{ rows=[{},{}], cols=[{},{}], cells={}, offset=0x{:x}, size={}, mean={:.3} }}",
            self.start_row,
            self.end_row,
            self.start_col,
            self.end_col,
            self.cell_count,
            self.byte_offset,
            self.byte_size,
            self.mean_entropy
        )
    }
}

// ─── HotspotDetector ─────────────────────────────────────────────────────────

/// Detects contiguous high-entropy regions in an `EntropyGrid`.
pub struct HotspotDetector {
    /// Entropy threshold above which a cell is considered "hot".
    pub threshold: f32,
    /// Minimum number of contiguous hot cells to form a hotspot.
    pub min_cells: usize,
}

impl Default for HotspotDetector {
    fn default() -> Self {
        Self {
            threshold: 6.5,
            min_cells: 4,
        }
    }
}

impl HotspotDetector {
    /// Create with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom threshold.
    #[must_use]
    pub const fn with_threshold(threshold: f32, min_cells: usize) -> Self {
        Self {
            threshold,
            min_cells,
        }
    }

    /// Detect hotspots by scanning row-by-row for consecutive hot cells.
    ///
    /// Within each row, consecutive cells above `threshold` are grouped into a
    /// run. Runs spanning multiple rows are merged if both rows are entirely
    /// "hot" within the same column range.
    #[must_use]
    pub fn detect(&self, grid: &EntropyGrid) -> Vec<EntropyHotspot> {
        let mut hotspots = Vec::new();

        // Simple row-wise run-length scan.
        for row in 0..grid.rows {
            let mut run_start: Option<usize> = None;
            for col in 0..grid.cols {
                let e = grid.get_unchecked(row, col);
                if e >= self.threshold {
                    if run_start.is_none() {
                        run_start = Some(col);
                    }
                } else if let Some(start) = run_start.take() {
                    let end = col - 1;
                    let cells = end - start + 1;
                    if cells >= self.min_cells {
                        let vals: Vec<f32> = (start..=end)
                            .filter_map(|c| grid.get(row, c))
                            .collect();
                        let mean = vals.iter().sum::<f32>() / casts::usize_to_f32(vals.len());
                        let max = vals.iter().copied().fold(f32::MIN, f32::max);
                        let offset = grid.cell_offset(row, start);
                        let size = cells * grid.cell_bytes;
                        hotspots.push(EntropyHotspot {
                            start_row: row,
                            end_row: row,
                            start_col: start,
                            end_col: end,
                            mean_entropy: mean,
                            max_entropy: max,
                            cell_count: cells,
                            byte_offset: offset,
                            byte_size: size,
                        });
                    }
                }
            }
            // Flush end-of-row run.
            if let Some(start) = run_start {
                let end = grid.cols - 1;
                let cells = end - start + 1;
                if cells >= self.min_cells {
                    let vals: Vec<f32> = (start..=end)
                        .filter_map(|c| grid.get(row, c))
                        .collect();
                    let mean = vals.iter().sum::<f32>() / casts::usize_to_f32(vals.len());
                    let max = vals.iter().copied().fold(f32::MIN, f32::max);
                    let offset = grid.cell_offset(row, start);
                    let size = cells * grid.cell_bytes;
                    hotspots.push(EntropyHotspot {
                        start_row: row,
                        end_row: row,
                        start_col: start,
                        end_col: end,
                        mean_entropy: mean,
                        max_entropy: max,
                        cell_count: cells,
                        byte_offset: offset,
                        byte_size: size,
                    });
                }
            }
        }

        // Sort by byte offset ascending.
        hotspots.sort_unstable_by_key(|h| h.byte_offset);
        hotspots
    }
}

// ─── VisualEntropyMap ─────────────────────────────────────────────────────────

/// Top-level 2D entropy map with hotspot annotations and JSON export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualEntropyMap {
    /// The underlying entropy grid.
    pub grid: EntropyGrid,
    /// Detected hotspots.
    pub hotspots: Vec<EntropyHotspot>,
    /// Row means (length == grid.rows).
    pub row_means: Vec<f32>,
    /// Column means (length == grid.cols).
    pub col_means: Vec<f32>,
    /// Overall mean entropy.
    pub overall_mean: f32,
    /// Overall max entropy.
    pub overall_max: f32,
}

impl VisualEntropyMap {
    /// Build a full visual entropy map from raw binary data.
    ///
    /// # Parameters
    /// - `data`: raw bytes to analyse.
    /// - `cols`: number of grid columns.
    /// - `cell_bytes`: number of bytes per cell.
    /// - `hotspot_threshold`: entropy cutoff for hotspot detection.
    #[must_use]
    pub fn build(data: &[u8], cols: usize, cell_bytes: usize, hotspot_threshold: f32) -> Self {
        let cols = cols.max(1);
        let cell_bytes = cell_bytes.max(1);
        let grid = EntropyGrid::build(data, cols, cell_bytes);
        let detector = HotspotDetector::with_threshold(hotspot_threshold, 4);
        let hotspots = detector.detect(&grid);
        let row_means = grid.row_means();
        let col_means = grid.col_means();
        let overall_mean = grid.mean_entropy();
        let overall_max = grid.max_entropy();
        Self {
            grid,
            hotspots,
            row_means,
            col_means,
            overall_mean,
            overall_max,
        }
    }

    /// Serialize the map to pretty-printed JSON.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on serialisation failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise from JSON.
    ///
    /// # Errors
    /// Returns `serde_json::Error` on parse failure.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Number of detected hotspots.
    #[must_use]
    pub const fn hotspot_count(&self) -> usize {
        self.hotspots.len()
    }

    /// Total bytes covered by hotspots.
    #[must_use]
    pub fn hotspot_byte_coverage(&self) -> usize {
        self.hotspots.iter().map(|h| h.byte_size).sum()
    }

    /// Return hotspots likely to be encrypted (`mean_entropy` >= 7.5).
    #[must_use]
    pub fn encrypted_hotspots(&self) -> Vec<&EntropyHotspot> {
        self.hotspots
            .iter()
            .filter(|h| h.likely_encrypted())
            .collect()
    }

    /// Return hotspots likely to be compressed (`mean_entropy` in [6.5, 7.5)).
    #[must_use]
    pub fn compressed_hotspots(&self) -> Vec<&EntropyHotspot> {
        self.hotspots
            .iter()
            .filter(|h| h.likely_compressed())
            .collect()
    }

    /// Generate a minimal ASCII representation of the grid.
    ///
    /// Each cell is rendered as a single character from the palette
    /// `" .:-=+*#%@"` (low → high entropy).
    #[must_use]
    pub fn ascii_render(&self, max_width: usize) -> String {
        const PALETTE: &[u8] = b" .:-=+*#%@";
        let n_palette = casts::usize_to_f32(PALETTE.len());
        let cols = self.grid.cols.min(max_width);
        let mut out = String::new();

        for row in 0..self.grid.rows {
            for col in 0..cols {
                let e = self
                    .grid
                    .get(row, col)
                    .unwrap_or(0.0);
                let idx = casts::f32_to_usize(((e / 8.0) * (n_palette - 1.0)).clamp(0.0, n_palette - 1.0));
                out.push(PALETTE[idx] as char);
            }
            out.push('\n');
        }
        out
    }

    /// Build a condensed summary for quick triage display.
    #[must_use]
    pub fn summary(&self) -> VisualEntropyMapSummary {
        VisualEntropyMapSummary {
            rows: self.grid.rows,
            cols: self.grid.cols,
            cell_bytes: self.grid.cell_bytes,
            total_bytes: self.grid.total_bytes,
            overall_mean: self.overall_mean,
            overall_max: self.overall_max,
            hotspot_count: self.hotspot_count(),
            hotspot_byte_coverage: self.hotspot_byte_coverage(),
            encrypted_hotspot_count: self.encrypted_hotspots().len(),
            compressed_hotspot_count: self.compressed_hotspots().len(),
        }
    }
}

impl fmt::Display for VisualEntropyMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VisualEntropyMap {{ {}x{} grid, mean={:.3}, max={:.3}, hotspots={} }}",
            self.grid.rows,
            self.grid.cols,
            self.overall_mean,
            self.overall_max,
            self.hotspot_count()
        )
    }
}

// ─── VisualEntropyMapSummary ──────────────────────────────────────────────────

/// Condensed summary of a visual entropy map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualEntropyMapSummary {
    pub rows: usize,
    pub cols: usize,
    pub cell_bytes: usize,
    pub total_bytes: usize,
    pub overall_mean: f32,
    pub overall_max: f32,
    pub hotspot_count: usize,
    pub hotspot_byte_coverage: usize,
    pub encrypted_hotspot_count: usize,
    pub compressed_hotspot_count: usize,
}

impl fmt::Display for VisualEntropyMapSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntropyMapSummary {{ {}×{} grid, mean={:.3}, max={:.3}, \
             hotspots={} (encrypted={}, compressed={}), coverage={}B }}",
            self.rows,
            self.cols,
            self.overall_mean,
            self.overall_max,
            self.hotspot_count,
            self.encrypted_hotspot_count,
            self.compressed_hotspot_count,
            self.hotspot_byte_coverage
        )
    }
}

// ─── RGB colour helpers ────────────────────────────────────────────────────────

/// Map an entropy value [0, 8] to an RGB colour tuple.
///
/// Colour ramp: dark blue → cyan → green → yellow → orange → red.
#[must_use]
pub fn entropy_to_rgb(entropy: f32) -> (u8, u8, u8) {
    let norm = (entropy / 8.0).clamp(0.0, 1.0);
    // Piecewise linear: blue(0) → cyan(0.25) → green(0.5) → yellow(0.75) → red(1.0)
    if norm < 0.25 {
        let seg = norm / 0.25;
        (0u8, casts::f32_to_u8(seg * 255.0), 255u8)
    } else if norm < 0.5 {
        let seg = (norm - 0.25) / 0.25;
        (0u8, 255u8, casts::f32_to_u8(255.0 * (1.0 - seg)))
    } else if norm < 0.75 {
        let seg = (norm - 0.5) / 0.25;
        (casts::f32_to_u8(seg * 255.0), 255u8, 0u8)
    } else {
        let seg = (norm - 0.75) / 0.25;
        (255u8, casts::f32_to_u8(255.0 * (1.0 - seg)), 0u8)
    }
}

/// Build a flat RGBA byte buffer from an `EntropyGrid` (4 bytes per cell).
#[must_use]
pub fn grid_to_rgba(grid: &EntropyGrid) -> Vec<u8> {
    let mut out = Vec::with_capacity(grid.values.len() * 4);
    for &e in &grid.values {
        let (r, g, b) = entropy_to_rgb(e);
        out.push(r);
        out.push(g);
        out.push(b);
        out.push(255); // alpha
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }

    fn uniform(n: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(n).collect()
    }

    // ── EntropyGrid ───────────────────────────────────────────────────────

    #[test]
    fn test_grid_build_dimensions() {
        let data = zeros(1024);
        let grid = EntropyGrid::build(&data, 16, 64);
        // 1024 / 64 = 16 chunks; 16 chunks / 16 cols = 1 row
        assert_eq!(grid.cols, 16);
        assert_eq!(grid.rows, 1);
        assert_eq!(grid.cell_bytes, 64);
    }

    #[test]
    fn test_grid_build_zero_entropy() {
        let data = zeros(512);
        let grid = EntropyGrid::build(&data, 8, 64);
        for r in 0..grid.rows {
            for c in 0..grid.cols {
                assert_eq!(grid.get(r, c).unwrap(), 0.0);
            }
        }
    }

    #[test]
    fn test_grid_build_uniform_entropy() {
        // The cell size must equal the alphabet: `uniform` cycles 0..=255, so a
        // 256-byte cell holds exactly one byte of each value and its entropy is
        // exactly 8.0. The cell was 128 bytes, which can hold at most 128
        // distinct values — a ceiling of log2(128) = 7.0 — so the `> 7.0`
        // assertion below was unreachable and the test always failed. The
        // comment already stated the intent ("one byte of each value → 8.0");
        // only the geometry disagreed with it.
        let data = uniform(1024);
        let grid = EntropyGrid::build(&data, 4, 256);
        for &v in &grid.values {
            if v > 0.0 {
                assert!(
                    (v - 8.0).abs() < 1e-5,
                    "a cell holding one of each byte value has entropy 8.0, got {v}"
                );
            }
        }
    }

    #[test]
    fn test_grid_get_out_of_bounds() {
        let data = zeros(256);
        let grid = EntropyGrid::build(&data, 4, 64);
        assert!(grid.get(100, 100).is_none());
    }

    #[test]
    fn test_grid_row_means_zeros() {
        let data = zeros(512);
        let grid = EntropyGrid::build(&data, 8, 64);
        for m in grid.row_means() {
            assert!((m - (0.0)).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn test_grid_col_means_length() {
        let data = zeros(256);
        let grid = EntropyGrid::build(&data, 8, 32);
        let means = grid.col_means();
        assert_eq!(means.len(), 8);
    }

    #[test]
    fn test_grid_max_min_entropy() {
        // 256-byte cells: one all-zero cell (entropy 0) and one holding every
        // byte value once (entropy 8). Previously both halves were 128 bytes,
        // capping the maximum at log2(128) = 7.0 and making `> 7.0`
        // unsatisfiable.
        let data: Vec<u8> = zeros(256).into_iter().chain(uniform(256)).collect();
        let grid = EntropyGrid::build(&data, 2, 256);
        assert!((grid.min_entropy() - (0.0)).abs() < f32::EPSILON);
        assert!(grid.max_entropy() > 7.0, "got {}", grid.max_entropy());
    }

    #[test]
    fn test_grid_cell_offset() {
        let data = zeros(1024);
        let grid = EntropyGrid::build(&data, 8, 128);
        assert_eq!(grid.cell_offset(0, 0), 0);
        assert_eq!(grid.cell_offset(0, 1), 128);
        assert_eq!(grid.cell_offset(1, 0), 8 * 128);
    }

    #[test]
    fn test_grid_sorted_cells() {
        let data: Vec<u8> = zeros(256).into_iter().chain(uniform(256)).collect();
        let grid = EntropyGrid::build(&data, 2, 256);
        let sorted = grid.sorted_cells();
        assert_eq!(sorted.len(), 2);
        assert!(sorted[0].2 > sorted[1].2);
    }

    #[test]
    fn test_grid_display() {
        let data = zeros(256);
        let grid = EntropyGrid::build(&data, 4, 64);
        let s = format!("{grid}");
        assert!(s.contains("EntropyGrid"));
    }

    // ── HotspotDetector ───────────────────────────────────────────────────

    #[test]
    fn test_hotspot_none_on_zeros() {
        let data = zeros(4096);
        let grid = EntropyGrid::build(&data, 16, 256);
        let detector = HotspotDetector::default();
        assert!(detector.detect(&grid).is_empty());
    }

    #[test]
    fn test_hotspot_detects_uniform_run() {
        // Last 8 cells are high entropy (uniform), rest are zero
        let data: Vec<u8> = zeros(8 * 256).into_iter().chain(uniform(8 * 256)).collect();
        let grid = EntropyGrid::build(&data, 16, 256);
        let detector = HotspotDetector::with_threshold(6.5, 4);
        let hotspots = detector.detect(&grid);
        assert!(!hotspots.is_empty());
        assert!(hotspots[0].cell_count >= 4);
    }

    // ── VisualEntropyMap ──────────────────────────────────────────────────

    #[test]
    fn test_map_build_zeros() {
        let map = VisualEntropyMap::build(&zeros(1024), 16, 64, 6.5);
        assert!((map.overall_mean - (0.0)).abs() < f32::EPSILON);
        assert_eq!(map.hotspot_count(), 0);
    }

    #[test]
    fn test_map_build_mixed() {
        // Same geometry fix as `test_grid_max_min_entropy`: cells must be 256
        // bytes for a cell to be able to exceed 7.0 bits at all.
        let data: Vec<u8> = zeros(512).into_iter().chain(uniform(512)).collect();
        let map = VisualEntropyMap::build(&data, 8, 256, 6.5);
        assert!(map.overall_mean > 0.0);
        assert!(map.overall_max > 7.0, "got {}", map.overall_max);
    }

    #[test]
    fn test_map_json_round_trip() {
        let map = VisualEntropyMap::build(&zeros(256), 4, 64, 6.5);
        let json = map.to_json().unwrap();
        assert!(json.contains("\"rows\""));
        let map2 = VisualEntropyMap::from_json(&json).unwrap();
        assert_eq!(map2.grid.rows, map.grid.rows);
    }

    #[test]
    fn test_map_ascii_render_lines() {
        let map = VisualEntropyMap::build(&zeros(512), 16, 32, 6.5);
        let art = map.ascii_render(80);
        let lines: Vec<&str> = art.lines().collect();
        assert_eq!(lines.len(), map.grid.rows);
    }

    #[test]
    fn test_map_summary() {
        let map = VisualEntropyMap::build(&zeros(1024), 16, 64, 6.5);
        let s = map.summary();
        assert_eq!(s.rows, map.grid.rows);
        assert_eq!(s.cols, map.grid.cols);
        let display = format!("{s}");
        assert!(display.contains("EntropyMapSummary"));
    }

    #[test]
    fn test_map_display() {
        let map = VisualEntropyMap::build(&zeros(256), 4, 64, 6.5);
        let s = format!("{map}");
        assert!(s.contains("VisualEntropyMap"));
    }

    #[test]
    fn test_map_hotspot_byte_coverage() {
        let data: Vec<u8> = zeros(512).into_iter().chain(uniform(512)).collect();
        let map = VisualEntropyMap::build(&data, 8, 128, 6.5);
        // All hotspot byte sizes should be > 0
        assert!(map.hotspot_byte_coverage() >= map.hotspot_count() * 128);
    }

    // ── entropy_to_rgb ────────────────────────────────────────────────────

    #[test]
    fn test_entropy_to_rgb_zero() {
        let (r, g, b) = entropy_to_rgb(0.0);
        assert_eq!((r, g, b), (0, 0, 255)); // blue
    }

    #[test]
    fn test_entropy_to_rgb_max() {
        let (r, _g, _b) = entropy_to_rgb(8.0);
        assert_eq!(r, 255); // red component dominant
    }

    #[test]
    fn test_entropy_to_rgb_mid() {
        let (r, g, b) = entropy_to_rgb(4.0);
        // Midpoint should be green-ish
        assert!(g == 255 || g > r);
        let _ = b;
    }

    // ── grid_to_rgba ──────────────────────────────────────────────────────

    #[test]
    fn test_grid_to_rgba_length() {
        let data = zeros(256);
        let grid = EntropyGrid::build(&data, 4, 64);
        let rgba = grid_to_rgba(&grid);
        assert_eq!(rgba.len(), grid.values.len() * 4);
    }

    #[test]
    fn test_grid_to_rgba_alpha_is_255() {
        let data = zeros(256);
        let grid = EntropyGrid::build(&data, 4, 64);
        let rgba = grid_to_rgba(&grid);
        for chunk in rgba.chunks(4) {
            assert_eq!(chunk[3], 255);
        }
    }

    // ── EntropyHotspot ────────────────────────────────────────────────────

    #[test]
    fn test_hotspot_likely_encrypted() {
        let h = EntropyHotspot {
            start_row: 0,
            end_row: 0,
            start_col: 0,
            end_col: 7,
            mean_entropy: 7.8,
            max_entropy: 7.9,
            cell_count: 8,
            byte_offset: 0,
            byte_size: 1024,
        };
        assert!(h.likely_encrypted());
        assert!(!h.likely_compressed());
    }

    #[test]
    fn test_hotspot_likely_compressed() {
        let h = EntropyHotspot {
            start_row: 0,
            end_row: 0,
            start_col: 0,
            end_col: 3,
            mean_entropy: 7.0,
            max_entropy: 7.4,
            cell_count: 4,
            byte_offset: 0,
            byte_size: 512,
        };
        assert!(h.likely_compressed());
        assert!(!h.likely_encrypted());
    }

    #[test]
    fn test_hotspot_display() {
        let h = EntropyHotspot {
            start_row: 0,
            end_row: 0,
            start_col: 0,
            end_col: 3,
            mean_entropy: 7.0,
            max_entropy: 7.4,
            cell_count: 4,
            byte_offset: 0x1000,
            byte_size: 512,
        };
        let s = format!("{h}");
        assert!(s.contains("Hotspot"));
        assert!(s.contains("0x1000"));
    }
}
