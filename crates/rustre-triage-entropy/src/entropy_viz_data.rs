//! Rich visualization data structures for entropy analysis.
//!
//! Covers heatmap cell data, block histogram, rolling entropy window, and
//! section boundary overlays for frontend rendering (JSON/SVG/canvas).

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{EntropyRating, SectionEntropy, shannon_entropy, casts};

// ── Heatmap cell ──────────────────────────────────────────────────────────────

/// A single cell in a 2D entropy heatmap.
use std::fmt::Write as _;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapCell {
    /// File offset of the first byte in this cell.
    pub offset: u64,
    /// Number of bytes covered by this cell.
    pub size: usize,
    /// Shannon entropy of the covered bytes.
    pub entropy: f64,
    /// Normalised entropy 0.0–1.0 (entropy / 8.0).
    pub normalized: f64,
    /// RGBA colour for rendering (r, g, b, a).
    pub rgba: [u8; 4],
    /// Qualitative rating.
    pub rating: EntropyRating,
    /// Name of the PE section this cell falls in (empty if not PE).
    pub section: String,
}

impl HeatmapCell {
    /// Compute a cell for `data[offset..offset+size]`.
    #[must_use] 
    pub fn compute(data: &[u8], offset: u64, size: usize, section: String) -> Self {
        let off = casts::u64_to_usize(offset);
        let end = (off + size).min(data.len());
        let slice = &data[off..end];
        let entropy = if slice.is_empty() { 0.0 } else { shannon_entropy(slice) };
        let normalized = entropy / 8.0;
        let rating = EntropyRating::from_entropy(entropy);
        let rgba = entropy_to_rgba(entropy);
        Self { offset, size, entropy, normalized, rgba, rating, section }
    }
}

/// Map entropy to an RGBA colour for heatmap rendering.
/// Colour scheme: blue → cyan → green → yellow → red (low → high entropy).
#[must_use] 
pub fn entropy_to_rgba(entropy: f64) -> [u8; 4] {
    let t = casts::f64_to_f32((entropy / 8.0).clamp(0.0, 1.0));
    // Four-stop gradient: 0→blue, 0.33→cyan, 0.66→yellow, 1→red
    let (r, g, b) = if t < 0.33 {
        let s = t / 0.33;
        interpolate_rgb((0, 0, 200), (0, 200, 200), s)
    } else if t < 0.66 {
        let s = (t - 0.33) / 0.33;
        interpolate_rgb((0, 200, 200), (200, 200, 0), s)
    } else {
        let s = (t - 0.66) / 0.34;
        interpolate_rgb((200, 200, 0), (220, 30, 30), s)
    };
    [r, g, b, 255]
}

fn interpolate_rgb(a: (u8, u8, u8), b: (u8, u8, u8), t: f32) -> (u8, u8, u8) {
    let lerp = |x: u8, y: u8| casts::f32_to_u8((f32::from(y) - f32::from(x)).mul_add(t, f32::from(x)));
    (lerp(a.0, b.0), lerp(a.1, b.1), lerp(a.2, b.2))
}

// ── 2D heatmap grid ───────────────────────────────────────────────────────────

/// A full 2D heatmap grid (row-major) suitable for canvas / SVG rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapGrid {
    /// All cells, row-major (row 0 = top).
    pub cells: Vec<HeatmapCell>,
    /// Number of cells per row.
    pub cols: usize,
    /// Number of rows.
    pub rows: usize,
    /// Cell width in pixels.
    pub cell_px: usize,
    /// Total data size covered.
    pub data_size: usize,
    /// Cell byte size.
    pub cell_bytes: usize,
}

impl HeatmapGrid {
    /// Build a heatmap grid from `data`.
    ///
    /// * `cell_bytes` — how many bytes each cell covers.
    /// * `cols` — number of columns (cells per row).
    /// * `cell_px` — pixel width/height of each cell.
    /// * `sections` — optional PE section table for overlaying section names.
    #[must_use] 
    pub fn build(
        data: &[u8],
        cell_bytes: usize,
        cols: usize,
        cell_px: usize,
        sections: &[SectionEntry],
    ) -> Self {
        let cell_bytes = cell_bytes.max(1);
        let cols = cols.max(1);
        let num_cells = data.len().div_ceil(cell_bytes);
        let rows = num_cells.div_ceil(cols);

        let mut cells = Vec::with_capacity(num_cells);
        for i in 0..num_cells {
            let offset = (i * cell_bytes) as u64;
            let section = find_section(offset, sections);
            cells.push(HeatmapCell::compute(data, offset, cell_bytes, section));
        }

        Self { cells, cols, rows, cell_px, data_size: data.len(), cell_bytes }
    }

    /// Get the cell at grid position (row, col).
    #[must_use] 
    pub fn cell_at(&self, row: usize, col: usize) -> Option<&HeatmapCell> {
        let idx = row * self.cols + col;
        self.cells.get(idx)
    }

    /// Export to a flat array of RGBA bytes (row-major).
    #[must_use] 
    pub fn to_rgba_bitmap(&self) -> Vec<u8> {
        let width = self.cols * self.cell_px;
        let height = self.rows * self.cell_px;
        let mut bitmap = vec![0u8; width * height * 4];

        for (i, cell) in self.cells.iter().enumerate() {
            let row = i / self.cols;
            let col = i % self.cols;
            let px_r = row * self.cell_px;
            let px_c = col * self.cell_px;
            for dy in 0..self.cell_px {
                for dx in 0..self.cell_px {
                    let y = px_r + dy;
                    let x = px_c + dx;
                    if x < width && y < height {
                        let off = (y * width + x) * 4;
                        bitmap[off..off + 4].copy_from_slice(&cell.rgba);
                    }
                }
            }
        }
        bitmap
    }

    /// SVG string for the heatmap (basic, no interactivity).
    #[must_use] 
    pub fn to_svg(&self) -> String {
        let width = self.cols * self.cell_px;
        let height = self.rows * self.cell_px;
        let mut svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">"#
        );
        for (idx, cell) in self.cells.iter().enumerate() {
            let row = idx / self.cols;
            let col = idx % self.cols;
            let px_x = col * self.cell_px;
            let px_y = row * self.cell_px;
            let [red, green, blue, _] = cell.rgba;
            write!(svg, r#"<rect x="{}" y="{}" width="{}" height="{}" fill="rgb({},{},{})" />"#,
                px_x, px_y, self.cell_px, self.cell_px, red, green, blue).unwrap();
        }
        svg.push_str("</svg>");
        svg
    }

    /// Return a section-name → mean-entropy map, sorted by section name so
    /// the result is stable for diffing across runs. Sections that contain
    /// no cells (e.g. empty PE sections) are omitted.
    #[must_use]
    pub fn mean_entropy_by_section(&self) -> BTreeMap<String, f64> {
        let mut sums: BTreeMap<String, (f64, usize)> = BTreeMap::new();
        for cell in &self.cells {
            if cell.section.is_empty() {
                continue;
            }
            let acc = sums.entry(cell.section.clone()).or_insert((0.0, 0));
            acc.0 += cell.entropy;
            acc.1 += 1;
        }
        sums.into_iter()
            .map(|(k, (sum, n))| (k, sum / casts::usize_to_f64(n)))
            .collect()
    }
}

// ── Block histogram ───────────────────────────────────────────────────────────

/// Histogram of entropy values across fixed-size blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHistogram {
    /// Bucket counts, indexed 0–79 where bucket i covers entropy [i*0.1, (i+1)*0.1).
    #[serde(with = "BigArray")]
    pub buckets: [u32; 80],
    /// Block size used.
    pub block_size: usize,
    /// Total number of blocks analysed.
    pub total_blocks: u32,
    /// Mean entropy across all blocks.
    pub mean: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// Median entropy.
    pub median: f64,
    /// 90th-percentile entropy.
    pub p90: f64,
}

impl BlockHistogram {
    /// Build a histogram from `data` using `block_size`-byte blocks.
    #[must_use] 
    pub fn build(data: &[u8], block_size: usize) -> Self {
        let block_size = block_size.max(16);
        let mut buckets = [0u32; 80];
        let mut entropies = Vec::with_capacity(data.len() / block_size + 1);

        let mut pos = 0;
        while pos + block_size <= data.len() {
            let e = shannon_entropy(&data[pos..pos + block_size]);
            let bucket = casts::f64_to_usize(e / 8.0 * 79.0).min(79);
            buckets[bucket] += 1;
            entropies.push(e);
            pos += block_size;
        }
        // Partial last block
        if pos < data.len() {
            let e = shannon_entropy(&data[pos..]);
            let bucket = casts::f64_to_usize(e / 8.0 * 79.0).min(79);
            buckets[bucket] += 1;
            entropies.push(e);
        }

        let total_blocks = casts::usize_to_u32(entropies.len());
        let mean = if entropies.is_empty() { 0.0 } else {
            entropies.iter().sum::<f64>() / casts::usize_to_f64(entropies.len())
        };
        let stddev = if entropies.len() < 2 { 0.0 } else {
            let var = entropies.iter().map(|&e| (e - mean).powi(2)).sum::<f64>() / casts::usize_to_f64(entropies.len());
            var.sqrt()
        };

        entropies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = percentile(&entropies, 0.50);
        let p90    = percentile(&entropies, 0.90);

        Self { buckets, block_size, total_blocks, mean, stddev, median, p90 }
    }

    /// Fraction of blocks with entropy above `threshold`.
    #[must_use] 
    pub fn fraction_above(&self, threshold: f64) -> f64 {
        if self.total_blocks == 0 { return 0.0; }
        let thresh_bucket = casts::f64_to_usize(threshold / 8.0 * 79.0).min(79);
        let above: u32 = self.buckets[thresh_bucket..].iter().sum();
        f64::from(above) / f64::from(self.total_blocks)
    }

    /// ASCII bar-chart string representation.
    #[must_use] 
    pub fn ascii_chart(&self, width: usize) -> String {
        let max_count = f64::from(*self.buckets.iter().max().unwrap_or(&1));
        let mut out = String::new();
        for (bucket_idx, &count) in self.buckets.iter().enumerate() {
            let entropy = casts::usize_to_f64(bucket_idx) * 8.0 / 79.0;
            let bar_len = casts::f64_to_usize((f64::from(count) / max_count) * casts::usize_to_f64(width));
            writeln!(out, "{:.1} |{}", entropy, "#".repeat(bar_len)).unwrap();
        }
        out
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let idx = casts::f64_to_usize(casts::usize_to_f64(sorted.len() - 1) * p);
    sorted[idx.min(sorted.len() - 1)]
}

// ── Rolling entropy window ────────────────────────────────────────────────────

/// Rolling-window entropy series for plotting entropy over the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingEntropyWindow {
    /// (offset, entropy) pairs, sampled every `step` bytes.
    pub series: Vec<(u64, f64)>,
    /// Window size in bytes.
    pub window_size: usize,
    /// Step between consecutive samples in bytes.
    pub step: usize,
}

impl RollingEntropyWindow {
    /// Compute the rolling entropy series.
    #[must_use] 
    pub fn compute(data: &[u8], window_size: usize, step: usize) -> Self {
        let window_size = window_size.max(1);
        let step = step.max(1);
        let mut series = Vec::new();
        let mut pos = 0usize;

        while pos + window_size <= data.len() {
            let e = shannon_entropy(&data[pos..pos + window_size]);
            series.push((pos as u64, e));
            pos += step;
        }
        // Final partial window
        if pos < data.len() {
            let e = shannon_entropy(&data[pos..]);
            series.push((pos as u64, e));
        }

        Self { series, window_size, step }
    }

    /// Sample the series at evenly spaced points (for downsampling large files).
    #[must_use] 
    pub fn downsample(&self, max_points: usize) -> Vec<(u64, f64)> {
        if self.series.len() <= max_points { return self.series.clone(); }
        let step = self.series.len() / max_points;
        self.series.iter().step_by(step.max(1)).copied().collect()
    }

    /// Find local maxima (anomalous spikes) in the series.
    #[must_use] 
    pub fn local_maxima(&self, threshold: f64) -> Vec<(u64, f64)> {
        let mut peaks = Vec::new();
        for i in 1..self.series.len().saturating_sub(1) {
            let (off, e) = self.series[i];
            let prev = self.series[i - 1].1;
            let next = self.series[i + 1].1;
            if e > prev && e > next && e > threshold {
                peaks.push((off, e));
            }
        }
        peaks
    }

    /// Export as JSON-serializable Vec<[f64; 2]> for chart.js / d3.js.
    #[must_use] 
    pub fn to_chart_data(&self) -> Vec<[f64; 2]> {
        self.series.iter().map(|&(off, e)| [casts::u64_to_f64(off), e]).collect()
    }
}

// ── Section overlay ───────────────────────────────────────────────────────────

/// A PE section boundary for overlaying on visualizations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntry {
    pub name: String,
    pub start_offset: u64,
    pub end_offset: u64,
    pub is_executable: bool,
    pub is_writable: bool,
}

impl SectionEntry {
    #[must_use] 
    pub const fn contains(&self, offset: u64) -> bool {
        offset >= self.start_offset && offset < self.end_offset
    }
}

/// Build section entries from a [`SectionEntropy`] list.
#[must_use] 
pub fn section_entries_from_entropy(sections: &[SectionEntropy]) -> Vec<SectionEntry> {
    sections.iter().map(|s| SectionEntry {
        name: s.name.clone(),
        start_offset: s.offset as u64,
        end_offset: (s.offset + s.size) as u64,
        is_executable: false,
        is_writable: false,
    }).collect()
}

fn find_section(offset: u64, sections: &[SectionEntry]) -> String {
    sections.iter()
        .find(|s| s.contains(offset))
        .map(|s| s.name.clone())
        .unwrap_or_default()
}

// ── Section entropy overlay ───────────────────────────────────────────────────

/// Combines a rolling entropy series with section boundary markers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyOverlayData {
    /// Rolling entropy series.
    pub series: Vec<(u64, f64)>,
    /// Section boundaries for overlaying.
    pub sections: Vec<SectionEntry>,
    /// High-entropy regions (offset, length) for annotation.
    pub high_entropy_regions: Vec<(u64, usize)>,
    /// File size.
    pub file_size: usize,
    /// Window size used.
    pub window_size: usize,
}

impl EntropyOverlayData {
    /// Build the overlay data from raw file bytes and optional section table.
    #[must_use] 
    pub fn build(
        data: &[u8],
        window_size: usize,
        step: usize,
        sections: Vec<SectionEntry>,
        high_entropy_threshold: f64,
    ) -> Self {
        let rolling = RollingEntropyWindow::compute(data, window_size, step);
        let series = rolling.series.clone();

        // Identify high-entropy regions
        let mut regions: Vec<(u64, usize)> = Vec::new();
        let mut in_region = false;
        let mut region_start = 0u64;

        for &(off, e) in &rolling.series {
            if e >= high_entropy_threshold {
                if !in_region {
                    in_region = true;
                    region_start = off;
                }
            } else if in_region {
                in_region = false;
                regions.push((region_start, casts::u64_to_usize(off - region_start)));
            }
        }
        if in_region
            && let Some(&(last_off, _)) = rolling.series.last() {
                regions.push((region_start, casts::u64_to_usize(last_off - region_start + u64::try_from(window_size).unwrap_or(u64::MAX))));
            }

        Self {
            series,
            sections,
            high_entropy_regions: regions,
            file_size: data.len(),
            window_size,
        }
    }

    /// Convert to a JSON string for charting libraries (hand-built, no extra dep).
    #[must_use] 
    pub fn to_chart_json(&self) -> String {
        let series: Vec<String> = self.series.iter()
            .map(|&(off, e)| format!("{{\"x\":{off},\"y\":{e:.4}}}"))
            .collect();

        let sections: Vec<String> = self.sections.iter().map(|s| {
            format!(
                "{{\"name\":\"{}\",\"start\":{},\"end\":{},\"executable\":{}}}",
                s.name.replace('"', "\\\""),
                s.start_offset, s.end_offset, s.is_executable
            )
        }).collect();

        let regions: Vec<String> = self.high_entropy_regions.iter()
            .map(|&(off, len)| format!("{{\"offset\":{off},\"length\":{len}}}"))
            .collect();

        format!(
            "{{\"entropy_series\":[{}],\"sections\":[{}],\"high_entropy_regions\":[{}],\"file_size\":{},\"window_size\":{}}}",
            series.join(","),
            sections.join(","),
            regions.join(","),
            self.file_size,
            self.window_size,
        )
    }
}

// ── Colour-coded ASCII heatmap ─────────────────────────────────────────────────

/// Render a compact ASCII heatmap of the entropy across a file,
/// with section names as labels (like `xxd | entropy` cross-section view).
#[must_use] 
pub fn render_ascii_heatmap(
    data: &[u8],
    block_size: usize,
    cols: usize,
    sections: &[SectionEntry],
) -> String {
    const CHARS: &[u8] = b" .:-=+*#@";
    let block_size = block_size.max(1);
    let cols = cols.max(1);
    let mut out = String::new();
    let mut pos = 0usize;
    let mut col = 0usize;

    while pos < data.len() {
        let end = (pos + block_size).min(data.len());
        let e = shannon_entropy(&data[pos..end]);
        let idx = casts::f64_to_usize((e / 8.0) * casts::usize_to_f64(CHARS.len() - 1));
        let ch = CHARS[idx.min(CHARS.len() - 1)] as char;
        out.push(ch);
        col += 1;
        if col >= cols {
            col = 0;
            // Append section label at end of row
            let row_offset = pos as u64;
            let sec = find_section(row_offset, sections);
            if !sec.is_empty() {
                write!(out, " {sec}").unwrap();
            }
            out.push('\n');
        }
        pos += block_size;
    }
    if col > 0 { out.push('\n'); }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_to_rgba_extremes() {
        let low = entropy_to_rgba(0.0);
        let high = entropy_to_rgba(8.0);
        assert_ne!(low, high);
        // Low entropy → blue-ish (b > r)
        assert!(low[2] > low[0], "low entropy should be blue-ish");
        // High entropy → red-ish (r > b)
        assert!(high[0] > high[2], "high entropy should be red-ish");
    }

    #[test]
    fn test_heatmap_grid_build() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let grid = HeatmapGrid::build(&data, 64, 8, 4, &[]);
        assert_eq!(grid.cols, 8);
        assert!(!grid.cells.is_empty());
    }

    #[test]
    fn test_heatmap_grid_svg_nonempty() {
        let data = vec![0xAAu8; 1024];
        let grid = HeatmapGrid::build(&data, 64, 4, 4, &[]);
        let svg = grid.to_svg();
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("rect"));
    }

    #[test]
    fn test_block_histogram_high_fraction() {
        // All random-ish data → high entropy fraction should be > 0
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let hist = BlockHistogram::build(&data, 256);
        assert!(hist.fraction_above(7.0) > 0.0);
    }

    #[test]
    fn test_rolling_entropy_window() {
        let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let rw = RollingEntropyWindow::compute(&data, 256, 64);
        assert!(!rw.series.is_empty());
        // All uniform → entropy should be roughly 8
        for &(_, e) in &rw.series {
            assert!(e > 7.0, "uniform data should have high entropy, got {e}");
        }
    }

    #[test]
    fn test_rolling_entropy_downsample() {
        let data: Vec<u8> = vec![0xAAu8; 4096];
        let rw = RollingEntropyWindow::compute(&data, 64, 16);
        let ds = rw.downsample(10);
        assert!(ds.len() <= 10 + 1);
    }

    #[test]
    fn test_section_overlay_build() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let sections = vec![
            SectionEntry { name: ".text".into(), start_offset: 0, end_offset: 2048, is_executable: true, is_writable: false },
            SectionEntry { name: ".data".into(), start_offset: 2048, end_offset: 4096, is_executable: false, is_writable: true },
        ];
        let overlay = EntropyOverlayData::build(&data, 256, 64, sections, 7.0);
        assert!(!overlay.series.is_empty());
    }

    #[test]
    fn test_ascii_heatmap_produces_output() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let out = render_ascii_heatmap(&data, 32, 16, &[]);
        assert!(!out.is_empty());
    }

    #[test]
    fn test_chart_json_structure() {
        let data: Vec<u8> = vec![0x42u8; 256];
        let overlay = EntropyOverlayData::build(&data, 64, 32, Vec::new(), 7.0);
        let json = overlay.to_chart_json();
        assert!(json.contains("\"entropy_series\""), "should contain entropy_series key");
        assert!(json.contains("\"file_size\":256"), "should contain correct file_size");
    }
}
