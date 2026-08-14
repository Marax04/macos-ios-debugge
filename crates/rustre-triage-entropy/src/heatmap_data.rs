//! Entropy heatmap generation with sliding-window analysis and ASCII/SVG export.
//!
//! Key types:
//! - [`EntropyHeatmap`] — sliding window entropy over a binary buffer.
//! - [`HeatmapCell`] — one cell in the heatmap (offset, entropy, region type).
//! - [`RegionType`] — semantic label for the data in a region.
//! - [`HeatmapRenderer`] — ASCII colour-coded terminal output.
//! - [`BlockHeatmap`] — coarser 4 KiB block granularity view.
//! - [`HeatmapExport`] — serialise to JSON or SVG.

use crate::{EntropyCategory, shannon_entropy_f32, casts};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// RegionType
// ---------------------------------------------------------------------------

/// Semantic classification of a heatmap region.
use std::fmt::Write as _;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionType {
    /// Machine code / bytecode.
    Code,
    /// Plain structured binary data.
    Data,
    /// High-entropy compressed data.
    Compressed,
    /// High-entropy encrypted/packed data.
    Encrypted,
    /// Very high-entropy — indistinguishable from random.
    Packed,
    /// Near-zero entropy — null padding or sparse regions.
    Empty,
}

impl RegionType {
    /// Classify a region from its entropy value.
    #[must_use]
    pub fn from_entropy(e: f32) -> Self {
        if e < 1.0 {
            Self::Empty
        } else if e < 5.0 {
            Self::Code
        } else if e < 6.5 {
            Self::Data
        } else if e < 7.2 {
            Self::Compressed
        } else if e < 7.7 {
            Self::Encrypted
        } else {
            Self::Packed
        }
    }

    /// Map a coarse [`EntropyCategory`] onto the heatmap's region taxonomy.
    #[must_use]
    pub const fn from_category(c: &EntropyCategory) -> Self {
        match c {
            EntropyCategory::Empty => Self::Empty,
            EntropyCategory::Text | EntropyCategory::Data => Self::Data,
            EntropyCategory::Code => Self::Code,
            EntropyCategory::Compressed => Self::Compressed,
            EntropyCategory::Encrypted => Self::Encrypted,
            EntropyCategory::Random => Self::Packed,
        }
    }

    /// Single-character ASCII label.
    #[must_use]
    pub const fn ascii_char(self) -> char {
        match self {
            Self::Empty => '_',
            Self::Code => 'C',
            Self::Data => 'd',
            Self::Compressed => 'Z',
            Self::Encrypted => 'E',
            Self::Packed => 'P',
        }
    }

    /// ANSI 256-colour escape code for terminal output.
    #[must_use]
    pub const fn ansi_color(self) -> &'static str {
        match self {
            Self::Empty => "\x1b[38;5;238m",      // dark gray
            Self::Code => "\x1b[38;5;34m",        // green
            Self::Data => "\x1b[38;5;27m",        // blue
            Self::Compressed => "\x1b[38;5;220m", // yellow
            Self::Encrypted => "\x1b[38;5;208m",  // orange
            Self::Packed => "\x1b[38;5;196m",     // red
        }
    }

    /// SVG fill colour.
    #[must_use]
    pub const fn svg_color(self) -> &'static str {
        match self {
            Self::Empty => "#303030",
            Self::Code => "#22c55e",
            Self::Data => "#3b82f6",
            Self::Compressed => "#eab308",
            Self::Encrypted => "#f97316",
            Self::Packed => "#ef4444",
        }
    }
}

impl fmt::Display for RegionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::Code => write!(f, "Code"),
            Self::Data => write!(f, "Data"),
            Self::Compressed => write!(f, "Compressed"),
            Self::Encrypted => write!(f, "Encrypted"),
            Self::Packed => write!(f, "Packed"),
        }
    }
}

// ---------------------------------------------------------------------------
// HeatmapCell
// ---------------------------------------------------------------------------

/// A single cell in an entropy heatmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapCell {
    /// Byte offset in the source buffer.
    pub offset: u64,
    /// Shannon entropy (0.0 – 8.0).
    pub entropy: f32,
    /// Semantic region classification.
    pub region_type: RegionType,
    /// Number of bytes this cell represents.
    pub window_size: usize,
}

impl HeatmapCell {
    /// Create a cell by computing entropy over `data` at `offset`.
    #[must_use]
    pub fn from_slice(offset: u64, data: &[u8]) -> Self {
        let entropy = shannon_entropy_f32(data);
        Self {
            offset,
            entropy,
            region_type: RegionType::from_entropy(entropy),
            window_size: data.len(),
        }
    }

    /// Returns `true` if this cell is likely packed / encrypted.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        matches!(self.region_type, RegionType::Packed | RegionType::Encrypted)
    }

    /// Returns `true` if this cell is empty / zero padding.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self.region_type, RegionType::Empty)
    }
}

impl fmt::Display for HeatmapCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cell @ {:#x} entropy={:.3} ({}) win={}",
            self.offset, self.entropy, self.region_type, self.window_size
        )
    }
}

// ---------------------------------------------------------------------------
// EntropyHeatmap
// ---------------------------------------------------------------------------

/// Sliding-window entropy analysis of a binary buffer.
///
/// Default window: 256 bytes, step: 16 bytes.
///
/// # Example
///
/// ```rust,no_run
/// use rustre_triage_entropy::heatmap_data::EntropyHeatmap;
/// let data = std::fs::read("sample.bin").unwrap();
/// let hm = EntropyHeatmap::build(&data, 256, 16);
/// let ascii = hm.to_ascii(80);
/// println!("{ascii}");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyHeatmap {
    pub cells: Vec<HeatmapCell>,
    pub window_size: usize,
    pub step_size: usize,
    pub total_bytes: u64,
}

impl EntropyHeatmap {
    /// Build a sliding-window heatmap over `data`.
    ///
    /// - `window_size`: number of bytes per entropy window (e.g. 256).
    /// - `step_size`: stride between windows (e.g. 16).
    #[must_use]
    pub fn build(data: &[u8], window_size: usize, step_size: usize) -> Self {
        let window_size = window_size.max(1);
        let step_size = step_size.max(1);
        let mut cells = Vec::new();
        let mut offset = 0usize;

        while offset < data.len() {
            let end = (offset + window_size).min(data.len());
            let slice = &data[offset..end];
            cells.push(HeatmapCell::from_slice(offset as u64, slice));
            if end == data.len() {
                break;
            }
            offset += step_size;
        }

        Self {
            cells,
            window_size,
            step_size,
            total_bytes: data.len() as u64,
        }
    }

    /// Build with default parameters (window=256, step=16).
    #[must_use]
    pub fn build_default(data: &[u8]) -> Self {
        Self::build(data, 256, 16)
    }

    /// Render the heatmap as a colour-coded ASCII string of width `cols`.
    ///
    /// Uses ANSI 256-colour escape codes.
    #[must_use]
    pub fn to_ascii(&self, cols: usize) -> String {
        const RESET: &str = "\x1b[0m";
        if self.cells.is_empty() || cols == 0 {
            return String::new();
        }
        let n = self.cells.len();
        let mut line = String::new();
        for col in 0..cols {
            let start = col * n / cols;
            let end = ((col + 1) * n / cols).max(start + 1).min(n);
            let avg: f32 = self.cells[start..end]
                .iter()
                .map(|c| c.entropy)
                .sum::<f32>()
                / casts::usize_to_f32(end - start);
            let rt = RegionType::from_entropy(avg);
            line.push_str(rt.ansi_color());
            line.push(rt.ascii_char());
            line.push_str(RESET);
        }
        let border = "─".repeat(cols + 2);
        format!(
            "┌{border}┐\n│{line}│\n└{border}┘\nOffset 0{:^width$}{:#x}\n",
            "",
            self.total_bytes,
            width = cols.saturating_sub(8)
        )
    }

    /// Render without ANSI codes (plain text).
    #[must_use]
    pub fn to_plain_ascii(&self, cols: usize) -> String {
        if self.cells.is_empty() || cols == 0 {
            return String::new();
        }
        let n = self.cells.len();
        let line: String = (0..cols)
            .map(|col| {
                let start = col * n / cols;
                let end = ((col + 1) * n / cols).max(start + 1).min(n);
                let avg: f32 = self.cells[start..end]
                    .iter()
                    .map(|c| c.entropy)
                    .sum::<f32>()
                    / casts::usize_to_f32(end - start);
                RegionType::from_entropy(avg).ascii_char()
            })
            .collect();
        format!("|{line}|")
    }

    /// Count cells of each region type.
    #[must_use]
    pub fn region_counts(&self) -> [(RegionType, usize); 6] {
        let types = [
            RegionType::Empty,
            RegionType::Code,
            RegionType::Data,
            RegionType::Compressed,
            RegionType::Encrypted,
            RegionType::Packed,
        ];
        types.map(|rt| {
            let count = self.cells.iter().filter(|c| c.region_type == rt).count();
            (rt, count)
        })
    }

    /// Return cells whose entropy exceeds `threshold`.
    #[must_use]
    pub fn high_entropy_cells(&self, threshold: f32) -> Vec<&HeatmapCell> {
        self.cells
            .iter()
            .filter(|c| c.entropy >= threshold)
            .collect()
    }

    /// Overall entropy across all cells (mean).
    #[must_use]
    pub fn mean_entropy(&self) -> f32 {
        if self.cells.is_empty() {
            return 0.0;
        }
        self.cells.iter().map(|c| c.entropy).sum::<f32>() / casts::usize_to_f32(self.cells.len())
    }

    /// Peak entropy across all cells.
    #[must_use]
    pub fn peak_entropy(&self) -> f32 {
        self.cells.iter().map(|c| c.entropy).fold(0.0f32, f32::max)
    }

    /// Return suspicious cells (Packed or Encrypted).
    #[must_use]
    pub fn suspicious_cells(&self) -> Vec<&HeatmapCell> {
        self.cells.iter().filter(|c| c.is_suspicious()).collect()
    }

    /// Return a summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "EntropyHeatmap {{ cells={}, window={}, step={}, mean={:.3}, peak={:.3} }}",
            self.cells.len(),
            self.window_size,
            self.step_size,
            self.mean_entropy(),
            self.peak_entropy()
        )
    }
}

// ---------------------------------------------------------------------------
// BlockHeatmap — 4 KiB block granularity
// ---------------------------------------------------------------------------

/// 4 KiB block heatmap — faster for large files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeatmap {
    /// One cell per 4 KiB block.
    pub cells: Vec<HeatmapCell>,
    /// Block size in bytes (default 4096).
    pub block_size: usize,
}

impl BlockHeatmap {
    pub const DEFAULT_BLOCK_SIZE: usize = 4096;

    /// Build a block heatmap over `data` with `block_size` bytes per cell.
    #[must_use]
    pub fn build(data: &[u8], block_size: usize) -> Self {
        let block_size = block_size.max(1);
        let cells: Vec<HeatmapCell> = data
            .chunks(block_size)
            .enumerate()
            .map(|(i, chunk)| HeatmapCell::from_slice((i * block_size) as u64, chunk))
            .collect();
        Self { cells, block_size }
    }

    /// Build with default 4 KiB blocks.
    #[must_use]
    pub fn build_default(data: &[u8]) -> Self {
        Self::build(data, Self::DEFAULT_BLOCK_SIZE)
    }

    /// Number of blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.cells.len()
    }

    /// Percentage of packed/encrypted blocks.
    #[must_use]
    pub fn suspicious_ratio(&self) -> f64 {
        if self.cells.is_empty() {
            return 0.0;
        }
        let suspicious = self.cells.iter().filter(|c| c.is_suspicious()).count();
        casts::usize_to_f64(suspicious) / casts::usize_to_f64(self.cells.len())
    }

    /// Convert to a coarser [`EntropyHeatmap`] for rendering.
    #[must_use]
    pub fn to_entropy_heatmap(&self) -> EntropyHeatmap {
        EntropyHeatmap {
            cells: self.cells.clone(),
            window_size: self.block_size,
            step_size: self.block_size,
            total_bytes: self
                .cells
                .last()
                .map_or(0, |c| c.offset + c.window_size as u64),
        }
    }
}

// ---------------------------------------------------------------------------
// HeatmapRenderer
// ---------------------------------------------------------------------------

/// ASCII colour-coded heatmap renderer with a configurable width.
pub struct HeatmapRenderer {
    /// Terminal width in characters (default 80).
    pub width: usize,
    /// Whether to use ANSI colour codes.
    pub use_ansi: bool,
    /// Whether to show a per-region legend.
    pub show_legend: bool,
    /// Whether to show offset markers.
    pub show_offsets: bool,
}

impl Default for HeatmapRenderer {
    fn default() -> Self {
        Self {
            width: 80,
            use_ansi: true,
            show_legend: true,
            show_offsets: true,
        }
    }
}

impl HeatmapRenderer {
    /// Create a renderer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a plain-text renderer (no ANSI).
    #[must_use]
    pub const fn plain(width: usize) -> Self {
        Self {
            width,
            use_ansi: false,
            show_legend: false,
            show_offsets: false,
        }
    }

    /// Render `heatmap` to a multi-line string.
    #[must_use]
    pub fn render(&self, heatmap: &EntropyHeatmap) -> String {
        let mut out = String::new();
        if self.use_ansi {
            out.push_str(&heatmap.to_ascii(self.width));
        } else {
            out.push_str(&heatmap.to_plain_ascii(self.width));
            out.push('\n');
        }
        if self.show_legend {
            out.push_str(&self.legend());
        }
        if self.show_offsets {
            let total = heatmap.total_bytes;
            writeln!(out, "File size: {total} bytes ({total:#x})").unwrap();
        }
        out
    }

    /// Render `block_heatmap` to a multi-line string.
    #[must_use]
    pub fn render_blocks(&self, bh: &BlockHeatmap) -> String {
        self.render(&bh.to_entropy_heatmap())
    }

    fn legend(&self) -> String {
        const RESET: &str = "\x1b[0m";
        let entries = [
            (RegionType::Empty, "Empty/null padding"),
            (RegionType::Code, "Code/text"),
            (RegionType::Data, "Structured data"),
            (RegionType::Compressed, "Compressed"),
            (RegionType::Encrypted, "Encrypted"),
            (RegionType::Packed, "Packed/random"),
        ];
        let mut s = String::from("Legend: ");
        for (rt, label) in entries {
            if self.use_ansi {
                s.push_str(rt.ansi_color());
            }
            s.push(rt.ascii_char());
            if self.use_ansi {
                s.push_str(RESET);
            }
            s.push('=');
            s.push_str(label);
            s.push(' ');
        }
        s.push('\n');
        s
    }
}

// ---------------------------------------------------------------------------
// HeatmapExport
// ---------------------------------------------------------------------------

/// Serialise a heatmap to JSON or SVG.
pub struct HeatmapExport;

impl HeatmapExport {
    /// Export `heatmap` to a minimal JSON string.
    #[must_use]
    pub fn to_json(heatmap: &EntropyHeatmap) -> String {
        // Manual JSON to avoid requiring serde_json.
        let cells: Vec<String> = heatmap
            .cells
            .iter()
            .map(|c| {
                format!(
                    r#"{{"offset":{:#x},"entropy":{:.4},"type":"{}"}}"#,
                    c.offset, c.entropy, c.region_type
                )
            })
            .collect();
        format!(
            r#"{{"window_size":{},"step_size":{},"total_bytes":{},"cells":[{}]}}"#,
            heatmap.window_size,
            heatmap.step_size,
            heatmap.total_bytes,
            cells.join(",")
        )
    }

    /// Export `block_heatmap` to JSON.
    #[must_use]
    pub fn blocks_to_json(bh: &BlockHeatmap) -> String {
        Self::to_json(&bh.to_entropy_heatmap())
    }

    /// Export `heatmap` to an SVG string.
    ///
    /// The SVG is a horizontal bar of coloured rectangles, one per cell,
    /// scaled to `width × height` pixels.
    #[must_use]
    pub fn to_svg(heatmap: &EntropyHeatmap, width: u32, height: u32) -> String {
        if heatmap.cells.is_empty() {
            return format!(
                r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"/>"#
            );
        }
        let n = casts::usize_to_f64(heatmap.cells.len());
        let cell_w = f64::from(width) / n;
        let mut rects = String::new();
        for (i, cell) in heatmap.cells.iter().enumerate() {
            let x = casts::usize_to_f64(i) * cell_w;
            let color = cell.region_type.svg_color();
            let opacity = 0.6f64.mul_add(f64::from(cell.entropy / 8.0), 0.4);
            write!(rects, r#"<rect x="{:.1}" y="0" width="{:.1}" height="{height}" fill="{color}" opacity="{opacity:.2}" title="offset={:#x} entropy={:.3}"/>"#,
                x, cell_w, cell.offset, cell.entropy).unwrap();
        }
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" style="background:#1a1a1a">{rects}</svg>"#
        )
    }

    /// Export `block_heatmap` to SVG.
    #[must_use]
    pub fn blocks_to_svg(bh: &BlockHeatmap, width: u32, height: u32) -> String {
        Self::to_svg(&bh.to_entropy_heatmap(), width, height)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }

    fn uniform(n: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(n).collect()
    }

    #[test]
    fn test_region_type_from_entropy_empty() {
        assert_eq!(RegionType::from_entropy(0.0), RegionType::Empty);
        assert_eq!(RegionType::from_entropy(0.9), RegionType::Empty);
    }

    #[test]
    fn test_region_type_from_entropy_code() {
        assert_eq!(RegionType::from_entropy(3.0), RegionType::Code);
    }

    #[test]
    fn test_region_type_from_entropy_packed() {
        assert_eq!(RegionType::from_entropy(7.8), RegionType::Packed);
        assert_eq!(RegionType::from_entropy(8.0), RegionType::Packed);
    }

    #[test]
    fn test_region_type_display() {
        assert_eq!(RegionType::Packed.to_string(), "Packed");
        assert_eq!(RegionType::Empty.to_string(), "Empty");
    }

    #[test]
    fn test_heatmap_cell_from_slice_zeros() {
        let cell = HeatmapCell::from_slice(0, &zeros(256));
        assert!((cell.entropy - (0.0)).abs() < f32::EPSILON);
        assert_eq!(cell.region_type, RegionType::Empty);
    }

    #[test]
    fn test_heatmap_cell_from_slice_uniform() {
        let cell = HeatmapCell::from_slice(0, &uniform(256));
        assert!((cell.entropy - 8.0).abs() < 0.01);
        assert!(cell.is_suspicious());
    }

    #[test]
    fn test_heatmap_cell_display() {
        let cell = HeatmapCell::from_slice(0x1000, &zeros(64));
        let s = cell.to_string();
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_entropy_heatmap_build_basic() {
        let hm = EntropyHeatmap::build(&zeros(1024), 256, 64);
        // floor(1024/64) + partial last = 16 cells (1024/64 = 16 exact steps)
        assert!(!hm.cells.is_empty());
    }

    #[test]
    fn test_entropy_heatmap_build_empty() {
        let hm = EntropyHeatmap::build(&[], 256, 16);
        assert!(hm.cells.is_empty());
    }

    #[test]
    fn test_entropy_heatmap_mean_zeros() {
        let hm = EntropyHeatmap::build_default(&zeros(1024));
        assert!((hm.mean_entropy() - (0.0)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_entropy_heatmap_peak_uniform() {
        let hm = EntropyHeatmap::build_default(&uniform(1024));
        assert!((hm.peak_entropy() - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy_heatmap_suspicious_cells() {
        let hm = EntropyHeatmap::build_default(&uniform(1024));
        assert!(!hm.suspicious_cells().is_empty());
    }

    #[test]
    fn test_entropy_heatmap_to_plain_ascii() {
        let hm = EntropyHeatmap::build_default(&zeros(512));
        let s = hm.to_plain_ascii(40);
        assert!(s.starts_with('|'));
        assert!(s.ends_with('|'));
        assert_eq!(s.len(), 42); // 40 chars + 2 pipes
    }

    #[test]
    fn test_entropy_heatmap_to_ascii_non_empty() {
        let hm = EntropyHeatmap::build_default(&uniform(512));
        let s = hm.to_ascii(40);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_entropy_heatmap_high_entropy_cells() {
        let hm = EntropyHeatmap::build_default(&uniform(1024));
        let high = hm.high_entropy_cells(7.0);
        assert!(!high.is_empty());
    }

    #[test]
    fn test_entropy_heatmap_region_counts() {
        let hm = EntropyHeatmap::build_default(&zeros(512));
        let counts = hm.region_counts();
        // All cells should be Empty.
        let empty_count = counts
            .iter()
            .find(|(rt, _)| *rt == RegionType::Empty)
            .unwrap()
            .1;
        assert_eq!(empty_count, hm.cells.len());
    }

    #[test]
    fn test_entropy_heatmap_summary() {
        let hm = EntropyHeatmap::build_default(&zeros(256));
        let s = hm.summary();
        assert!(s.contains("EntropyHeatmap"));
    }

    #[test]
    fn test_block_heatmap_build() {
        let bh = BlockHeatmap::build(&zeros(8192), 4096);
        assert_eq!(bh.block_count(), 2);
    }

    #[test]
    fn test_block_heatmap_suspicious_ratio_zero() {
        let bh = BlockHeatmap::build_default(&zeros(8192));
        assert!((bh.suspicious_ratio() - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_block_heatmap_suspicious_ratio_packed() {
        let bh = BlockHeatmap::build_default(&uniform(8192));
        assert!(bh.suspicious_ratio() > 0.0);
    }

    #[test]
    fn test_block_heatmap_to_entropy_heatmap() {
        let bh = BlockHeatmap::build_default(&zeros(4096));
        let hm = bh.to_entropy_heatmap();
        assert_eq!(hm.cells.len(), 1);
    }

    #[test]
    fn test_heatmap_renderer_default() {
        let r = HeatmapRenderer::default();
        assert_eq!(r.width, 80);
        assert!(r.use_ansi);
    }

    #[test]
    fn test_heatmap_renderer_render_plain() {
        let r = HeatmapRenderer::plain(40);
        let hm = EntropyHeatmap::build_default(&zeros(256));
        let s = r.render(&hm);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_heatmap_export_to_json() {
        let hm = EntropyHeatmap::build_default(&zeros(256));
        let json = HeatmapExport::to_json(&hm);
        assert!(json.contains("window_size"));
        assert!(json.contains("cells"));
    }

    #[test]
    fn test_heatmap_export_to_svg() {
        let hm = EntropyHeatmap::build_default(&uniform(256));
        let svg = HeatmapExport::to_svg(&hm, 800, 40);
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("rect"));
    }

    #[test]
    fn test_heatmap_export_empty_svg() {
        let hm = EntropyHeatmap::build_default(&[]);
        let svg = HeatmapExport::to_svg(&hm, 800, 40);
        assert!(svg.contains("<svg"));
        assert!(!svg.contains("rect"));
    }

    #[test]
    fn test_region_type_ascii_chars() {
        assert_eq!(RegionType::Empty.ascii_char(), '_');
        assert_eq!(RegionType::Packed.ascii_char(), 'P');
        assert_eq!(RegionType::Encrypted.ascii_char(), 'E');
    }

    #[test]
    fn test_cell_is_empty() {
        let cell = HeatmapCell::from_slice(0, &zeros(64));
        assert!(cell.is_empty());
        assert!(!cell.is_suspicious());
    }
}
