//! `entropy_visualizer` — entropy plot and map rendering for binary triage.
//!
//! Provides [`EntropyVisualizer`], [`EntropySlice`], [`EntropyMap`], and the
//! free function [`to_ascii_plot`] that produce terminal-friendly visualisations
//! of per-block Shannon entropy across a binary file.

use std::fmt;
use std::fmt::Write as _;
use serde::{Deserialize, Serialize};
use crate::{shannon_entropy_f32, EntropyCategory, casts};

// ─── EntropySlice ─────────────────────────────────────────────────────────────

/// A contiguous slice of a binary with its pre-computed entropy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropySlice {
    /// Byte offset within the parent buffer.
    pub offset: u64,
    /// Number of bytes in the slice.
    pub size: usize,
    /// Shannon entropy in bits (0.0 – 8.0).
    pub entropy: f32,
    /// Semantic category inferred from entropy.
    pub category: EntropyCategory,
    /// Optional human-readable label (e.g. section name).
    pub label: Option<String>,
}

impl EntropySlice {
    /// Compute an [`EntropySlice`] by measuring `data` at `offset`.
    #[must_use]
    pub fn from_data(offset: u64, data: &[u8]) -> Self {
        let entropy = shannon_entropy_f32(data);
        Self {
            offset,
            size: data.len(),
            entropy,
            category: EntropyCategory::classify(entropy),
            label: None,
        }
    }

    /// Attach a label and return the modified slice.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Return `true` when entropy exceeds the packed threshold (> 7.0).
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy > 7.0
    }

    /// Render a single row in an ASCII heat bar.
    ///
    /// Returns one character from the palette `" .:;+=xX$#"` that linearly
    /// maps `[0.0, 8.0]` to the ten-character palette.
    #[must_use]
    pub fn heat_char(&self) -> char {
        const PALETTE: &[u8] = b" .:;+=xX$#";
        let palette_max = casts::usize_to_f32(PALETTE.len() - 1);
        let idx = ((self.entropy / 8.0) * palette_max)
            .clamp(0.0, palette_max);
        let idx = casts::f32_to_usize(idx);
        PALETTE[idx] as char
    }
}

impl fmt::Display for EntropySlice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = self.label.as_deref().unwrap_or("(unnamed)");
        write!(
            f,
            "EntropySlice {{ offset: {:#x}, size: {}, entropy: {:.3}, category: {}, label: {} }}",
            self.offset, self.size, self.entropy, self.category, label
        )
    }
}

// ─── EntropyMap ───────────────────────────────────────────────────────────────

/// A 2-D entropy map: a rectangular grid of [`EntropySlice`]s.
///
/// Rows represent sequential blocks; columns can represent different
/// decompositions (e.g. different chunk sizes or different files).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyMap {
    /// Number of columns in the map.
    pub cols: usize,
    /// Ordered rows of slices.
    pub rows: Vec<Vec<EntropySlice>>,
    /// Column labels.
    pub col_labels: Vec<String>,
}

impl EntropyMap {
    /// Create an empty map with `cols` columns.
    #[must_use]
    pub fn new(cols: usize) -> Self {
        Self {
            cols,
            rows: Vec::new(),
            col_labels: (0..cols).map(|i| format!("col{i}")).collect(),
        }
    }

    /// Set the label for column `idx`.
    pub fn set_col_label(&mut self, idx: usize, label: impl Into<String>) {
        if idx < self.col_labels.len() {
            self.col_labels[idx] = label.into();
        }
    }

    /// Append a row of slices.  The row is truncated or padded with zero-entropy
    /// slices so that it has exactly `self.cols` entries.
    pub fn push_row(&mut self, mut row: Vec<EntropySlice>) {
        row.truncate(self.cols);
        while row.len() < self.cols {
            row.push(EntropySlice {
                offset: 0,
                size: 0,
                entropy: 0.0,
                category: EntropyCategory::Empty,
                label: None,
            });
        }
        self.rows.push(row);
    }

    /// Build an [`EntropyMap`] with one column by slicing `data` into blocks
    /// of `block_size` bytes.
    #[must_use]
    pub fn from_data(data: &[u8], block_size: usize) -> Self {
        let block_size = block_size.max(1);
        let mut map = Self::new(1);
        map.set_col_label(0, "entropy");
        for (i, chunk) in data.chunks(block_size).enumerate() {
            let slice = EntropySlice::from_data((i * block_size) as u64, chunk);
            map.push_row(vec![slice]);
        }
        map
    }

    /// Return all slices whose entropy exceeds `threshold`.
    #[must_use]
    pub fn high_entropy_slices(&self, threshold: f32) -> Vec<&EntropySlice> {
        self.rows
            .iter()
            .flat_map(|row| row.iter())
            .filter(|s| s.entropy > threshold)
            .collect()
    }

    /// Return the average entropy across all slices.
    #[must_use]
    pub fn mean_entropy(&self) -> f32 {
        let total: f32 = self.rows.iter().flat_map(|r| r.iter()).map(|s| s.entropy).sum();
        let count = self.rows.iter().map(std::vec::Vec::len).sum::<usize>();
        if count == 0 { 0.0 } else { total / casts::usize_to_f32(count) }
    }

    /// Return the maximum entropy found anywhere in the map.
    #[must_use]
    pub fn max_entropy(&self) -> f32 {
        self.rows
            .iter()
            .flat_map(|r| r.iter())
            .map(|s| s.entropy)
            .fold(0.0f32, f32::max)
    }

    /// Render the first column of the map as an ASCII heat strip of `width`
    /// characters.
    #[must_use]
    pub fn to_ascii_strip(&self, width: usize) -> String {
        if width == 0 || self.rows.is_empty() {
            return String::new();
        }
        let n = self.rows.len();
        let chars: String = (0..width)
            .map(|col| {
                let start = col * n / width;
                let end = ((col + 1) * n / width).max(start + 1).min(n);
                let avg: f32 = self.rows[start..end]
                    .iter()
                    .filter_map(|r| r.first())
                    .map(|s| s.entropy)
                    .sum::<f32>()
                    / casts::usize_to_f32(end - start);
                let slice = EntropySlice {
                    offset: 0,
                    size: 0,
                    entropy: avg,
                    category: EntropyCategory::classify(avg),
                    label: None,
                };
                slice.heat_char()
            })
            .collect();
        let border = "─".repeat(width + 2);
        format!("{border}\n|{chars}|\n{border}\n0{:^width$}8.0\n", "", width = width.saturating_sub(1))
    }

    /// Return the number of rows.
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }
}

impl fmt::Display for EntropyMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "EntropyMap {{ cols: {}, rows: {} }}", self.cols, self.rows.len())?;
        for (i, row) in self.rows.iter().enumerate().take(10) {
            write!(f, "  [{i:4}] ")?;
            for s in row {
                write!(f, "{:.2} ", s.entropy)?;
            }
            writeln!(f)?;
        }
        if self.rows.len() > 10 {
            writeln!(f, "  ... ({} more rows)", self.rows.len() - 10)?;
        }
        Ok(())
    }
}

// ─── EntropyVisualizer ────────────────────────────────────────────────────────

/// Top-level driver that builds entropy visualisations from raw binary data.
///
/// Configure it via builder methods, then call [`Self::build_map`] to produce
/// an [`EntropyMap`] or [`Self::render_plot`] for a quick ASCII overview.
pub struct EntropyVisualizer {
    /// Block size in bytes for the primary decomposition.
    pub block_size: usize,
    /// Width of the ASCII plot in characters.
    pub plot_width: usize,
    /// Threshold above which a slice is flagged as high-entropy.
    pub high_entropy_threshold: f32,
    /// Whether to annotate slices with their category.
    pub annotate: bool,
}

impl EntropyVisualizer {
    /// Create a new visualiser with a 512-byte block size and 80-character plot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            block_size: 512,
            plot_width: 80,
            high_entropy_threshold: 7.0,
            annotate: false,
        }
    }

    /// Set the block size.
    #[must_use]
    pub const fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    /// Set the ASCII plot width.
    #[must_use]
    pub const fn with_plot_width(mut self, width: usize) -> Self {
        self.plot_width = width;
        self
    }

    /// Set the high-entropy threshold.
    #[must_use]
    pub const fn with_threshold(mut self, threshold: f32) -> Self {
        self.high_entropy_threshold = threshold;
        self
    }

    /// Enable per-slice category annotation.
    #[must_use]
    pub const fn with_annotation(mut self) -> Self {
        self.annotate = true;
        self
    }

    /// Build an [`EntropyMap`] from `data`.
    #[must_use]
    pub fn build_map(&self, data: &[u8]) -> EntropyMap {
        EntropyMap::from_data(data, self.block_size)
    }

    /// Build named slices from a list of `(name, offset, size)` section
    /// descriptors and return an [`EntropyMap`] with one column.
    #[must_use]
    pub fn build_section_map(
        &self,
        data: &[u8],
        sections: &[(&str, usize, usize)],
    ) -> EntropyMap {
        let mut map = EntropyMap::new(1);
        map.set_col_label(0, "section");
        for &(name, off, size) in sections {
            let end = (off + size).min(data.len());
            let slice_data = if off < data.len() { &data[off..end] } else { &[] };
            let mut slice = EntropySlice::from_data(off as u64, slice_data);
            slice.label = Some(name.to_string());
            map.push_row(vec![slice]);
        }
        map
    }

    /// Render a full ASCII plot string for `data`.
    ///
    /// The output contains a header, the heat strip, and a summary table of
    /// the top high-entropy slices.
    #[must_use]
    pub fn render_plot(&self, data: &[u8]) -> String {
        let map = self.build_map(data);
        let mut out = String::new();

        out.push_str("=== Entropy Plot ===\n");
        writeln!(out, "  Data size   : {} bytes", data.len()).unwrap();
        writeln!(out, "  Block size  : {} bytes", self.block_size).unwrap();
        writeln!(out, "  Blocks      : {}", map.row_count()).unwrap();
        writeln!(out, "  Mean entropy: {:.3}", map.mean_entropy()).unwrap();
        writeln!(out, "  Max entropy : {:.3}", map.max_entropy()).unwrap();
        out.push('\n');
        out.push_str(&map.to_ascii_strip(self.plot_width));
        out.push('\n');

        let high = map.high_entropy_slices(self.high_entropy_threshold);
        if !high.is_empty() {
            writeln!(out, "  High-entropy blocks (>{:.1}): {}",
                self.high_entropy_threshold,
                high.len()).unwrap();
            for s in high.iter().take(10) {
                writeln!(out, "    offset={:#010x}  size={:6}  entropy={:.3}  category={}",
                    s.offset, s.size, s.entropy, s.category).unwrap();
            }
            if high.len() > 10 {
                writeln!(out, "    ... ({} more)", high.len() - 10).unwrap();
            }
        }
        out
    }

    /// Render a compact one-line summary for `data`.
    #[must_use]
    pub fn summarise(&self, data: &[u8]) -> String {
        let overall = shannon_entropy_f32(data);
        let category = EntropyCategory::classify(overall);
        format!(
            "size={} blocks={} overall={:.3} category={}",
            data.len(),
            data.chunks(self.block_size).count(),
            overall,
            category
        )
    }
}

impl Default for EntropyVisualizer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── to_ascii_plot ────────────────────────────────────────────────────────────

/// Render `data` as a compact ASCII entropy plot of `width` characters.
///
/// This is a standalone convenience wrapper around [`EntropyVisualizer`] for
/// callers that just want a quick plot without constructing the full type.
///
/// # Arguments
///
/// * `data`       — raw bytes to visualise.
/// * `block_size` — bytes per entropy block (≥ 1; clamped to 1 if zero).
/// * `width`      — number of characters in the horizontal strip.
///
/// # Returns
///
/// A multi-line `String` containing a bordered heat strip and scale legend.
#[must_use]
pub fn to_ascii_plot(data: &[u8], block_size: usize, width: usize) -> String {
    let vis = EntropyVisualizer::new()
        .with_block_size(block_size.max(1))
        .with_plot_width(width);
    vis.render_plot(data)
}

// ─── EntropyPlotConfig ────────────────────────────────────────────────────────

/// Full configuration for an [`EntropyVisualizer`] that can be serialised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyPlotConfig {
    /// Block size in bytes.
    pub block_size: usize,
    /// ASCII plot width.
    pub plot_width: usize,
    /// High-entropy flagging threshold.
    pub threshold: f32,
    /// Whether to show category annotations.
    pub annotate: bool,
}

impl Default for EntropyPlotConfig {
    fn default() -> Self {
        Self {
            block_size: 512,
            plot_width: 80,
            threshold: 7.0,
            annotate: false,
        }
    }
}

impl EntropyPlotConfig {
    /// Build an [`EntropyVisualizer`] from this configuration.
    #[must_use]
    pub const fn build_visualizer(&self) -> EntropyVisualizer {
        EntropyVisualizer {
            block_size: self.block_size,
            plot_width: self.plot_width,
            high_entropy_threshold: self.threshold,
            annotate: self.annotate,
        }
    }
}

// ─── ColourMap ────────────────────────────────────────────────────────────────

/// A simple entropy-to-RGB colour mapping table.
///
/// Suitable for feeding into GUI renderers or PNG output pipelines.
pub struct ColourMap {
    entries: Vec<(f32, [u8; 3])>,
}

impl ColourMap {
    /// Build the default `ColourMap` with five gradient stops.
    #[must_use]
    pub fn default_gradient() -> Self {
        Self {
            entries: vec![
                (0.0, [0, 0, 128]),    // dark blue  — empty
                (2.0, [0, 128, 255]),  // light blue — text
                (4.0, [0, 200, 0]),    // green      — code/data
                (6.0, [255, 200, 0]),  // amber      — compressed
                (7.0, [200, 0, 0]),    // red        — packed/encrypted
            ],
        }
    }

    /// Map `entropy` in `[0.0, 8.0]` to an interpolated RGB colour.
    #[must_use]
    pub fn map(&self, entropy: f32) -> [u8; 3] {
        let e = entropy.clamp(0.0, 8.0);
        // Find the two surrounding stops
        let n = self.entries.len();
        for i in 0..n.saturating_sub(1) {
            let (lo_e, lo_rgb) = self.entries[i];
            let (hi_e, hi_rgb) = self.entries[i + 1];
            if e >= lo_e && e <= hi_e {
                let t = if (hi_e - lo_e).abs() < 1e-6 {
                    0.0
                } else {
                    (e - lo_e) / (hi_e - lo_e)
                };
                return [
                    lerp_u8(lo_rgb[0], hi_rgb[0], t),
                    lerp_u8(lo_rgb[1], hi_rgb[1], t),
                    lerp_u8(lo_rgb[2], hi_rgb[2], t),
                ];
            }
        }
        // Above last stop
        self.entries.last().map_or([0, 0, 0], |(_, rgb)| *rgb)
    }

    /// Map an [`EntropyMap`] to a flat row-major RGB pixel buffer.
    #[must_use]
    pub fn map_entropy_map(&self, map: &EntropyMap) -> Vec<u8> {
        let mut pixels = Vec::with_capacity(map.rows.len() * map.cols * 3);
        for row in &map.rows {
            for slice in row {
                let rgb = self.map(slice.entropy);
                pixels.extend_from_slice(&rgb);
            }
        }
        pixels
    }
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    let result = (f32::from(b) - f32::from(a)).mul_add(t, f32::from(a));
    casts::f32_to_u8(result.clamp(0.0, 255.0))
}

// ─── EntropyTimeline ─────────────────────────────────────────────────────────

/// Records entropy measurements at discrete offsets for trend analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntropyTimeline {
    /// Ordered `(offset, entropy)` pairs.
    pub points: Vec<(u64, f32)>,
}

impl EntropyTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a measurement.
    pub fn record(&mut self, offset: u64, entropy: f32) {
        self.points.push((offset, entropy));
    }

    /// Build a timeline from `data` split into blocks of `block_size`.
    #[must_use]
    pub fn from_data(data: &[u8], block_size: usize) -> Self {
        let block_size = block_size.max(1);
        let mut tl = Self::new();
        for (i, chunk) in data.chunks(block_size).enumerate() {
            tl.record((i * block_size) as u64, shannon_entropy_f32(chunk));
        }
        tl
    }

    /// Return the moving average entropy over a window of `k` blocks.
    #[must_use]
    pub fn moving_average(&self, k: usize) -> Vec<f32> {
        if k == 0 || self.points.is_empty() {
            return Vec::new();
        }
        self.points
            .windows(k)
            .map(|w| w.iter().map(|(_, e)| e).sum::<f32>() / casts::usize_to_f32(k))
            .collect()
    }

    /// Return the index of the block with maximum entropy.
    #[must_use]
    pub fn peak_index(&self) -> Option<usize> {
        self.points
            .iter()
            .enumerate()
            .max_by(|(_, (_, a)), (_, (_, b))| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
    }

    /// Return how many blocks exceed `threshold`.
    #[must_use]
    pub fn count_above(&self, threshold: f32) -> usize {
        self.points.iter().filter(|(_, e)| *e > threshold).count()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_slice_zero_data() {
        let s = EntropySlice::from_data(0, &[0u8; 64]);
        assert!((s.entropy - (0.0)).abs() < f32::EPSILON);
        assert_eq!(s.category, EntropyCategory::Empty);
        assert!(!s.is_high_entropy());
    }

    #[test]
    fn entropy_slice_high_entropy() {
        let data: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let s = EntropySlice::from_data(0, &data);
        assert!(s.is_high_entropy());
    }

    #[test]
    fn entropy_slice_heat_char_zero() {
        let s = EntropySlice { offset: 0, size: 0, entropy: 0.0, category: EntropyCategory::Empty, label: None };
        assert_eq!(s.heat_char(), ' ');
    }

    #[test]
    fn entropy_slice_heat_char_max() {
        let s = EntropySlice { offset: 0, size: 0, entropy: 8.0, category: EntropyCategory::Random, label: None };
        assert_eq!(s.heat_char(), '#');
    }

    #[test]
    fn entropy_map_from_data() {
        let data = vec![0u8; 1024];
        let map = EntropyMap::from_data(&data, 256);
        assert_eq!(map.row_count(), 4);
        assert!((map.mean_entropy() - (0.0)).abs() < f32::EPSILON);
    }

    #[test]
    fn entropy_map_high_entropy_slices() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let map = EntropyMap::from_data(&data, 256);
        let high = map.high_entropy_slices(7.0);
        assert!(!high.is_empty());
    }

    #[test]
    fn entropy_map_ascii_strip_not_empty() {
        let data = vec![0u8; 512];
        let map = EntropyMap::from_data(&data, 64);
        let strip = map.to_ascii_strip(40);
        assert!(!strip.is_empty());
        assert!(strip.contains('|'));
    }

    #[test]
    fn visualizer_render_plot_smoke() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let vis = EntropyVisualizer::new().with_block_size(256).with_plot_width(40);
        let plot = vis.render_plot(&data);
        assert!(plot.contains("Entropy Plot"));
        assert!(plot.contains("High-entropy"));
    }

    #[test]
    fn to_ascii_plot_function() {
        let data = vec![42u8; 512];
        let plot = to_ascii_plot(&data, 64, 20);
        assert!(!plot.is_empty());
    }

    #[test]
    fn colour_map_black_at_zero() {
        let cm = ColourMap::default_gradient();
        let rgb = cm.map(0.0);
        assert_eq!(rgb, [0, 0, 128]);
    }

    #[test]
    fn colour_map_red_at_eight() {
        let cm = ColourMap::default_gradient();
        let rgb = cm.map(8.0);
        assert_eq!(rgb, [200, 0, 0]);
    }

    #[test]
    fn entropy_timeline_from_data() {
        let data = vec![0u8; 1024];
        let tl = EntropyTimeline::from_data(&data, 256);
        assert_eq!(tl.points.len(), 4);
        assert!(tl.points.iter().all(|(_, e)| *e == 0.0));
    }

    #[test]
    fn entropy_timeline_moving_average() {
        let mut tl = EntropyTimeline::new();
        tl.record(0, 2.0);
        tl.record(256, 4.0);
        tl.record(512, 6.0);
        let ma = tl.moving_average(2);
        assert_eq!(ma.len(), 2);
        assert!((ma[0] - 3.0).abs() < 1e-5);
    }

    #[test]
    fn entropy_timeline_peak() {
        let mut tl = EntropyTimeline::new();
        tl.record(0, 1.0);
        tl.record(100, 5.0);
        tl.record(200, 3.0);
        assert_eq!(tl.peak_index(), Some(1));
    }

    #[test]
    fn entropy_timeline_count_above() {
        let mut tl = EntropyTimeline::new();
        tl.record(0, 3.0);
        tl.record(0, 7.5);
        tl.record(0, 7.9);
        assert_eq!(tl.count_above(7.0), 2);
    }

    #[test]
    fn config_builds_visualizer() {
        let cfg = EntropyPlotConfig { block_size: 128, plot_width: 60, threshold: 6.5, annotate: true };
        let vis = cfg.build_visualizer();
        assert_eq!(vis.block_size, 128);
        assert_eq!(vis.plot_width, 60);
    }

    #[test]
    fn visualizer_summarise() {
        let data = vec![0u8; 256];
        let vis = EntropyVisualizer::new();
        let s = vis.summarise(&data);
        assert!(s.contains("size=256"));
    }

    #[test]
    fn visualizer_build_section_map() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let sections = [(".text", 0, 256), (".data", 256, 256)];
        let vis = EntropyVisualizer::new();
        let map = vis.build_section_map(&data, &sections);
        assert_eq!(map.row_count(), 2);
        assert_eq!(map.rows[0][0].label.as_deref(), Some(".text"));
    }
}
