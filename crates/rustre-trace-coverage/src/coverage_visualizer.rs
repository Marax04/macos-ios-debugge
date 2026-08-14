//! `coverage_visualizer` — annotate disassembly listings with coverage data.
//!
//! Provides:
//! - [`CoverageVisualizer`] — combines coverage data with a list of disassembly lines
//! - [`AnnotatedLine`] — a single disassembly line with its coverage annotation
//! - [`AnnotatedBlock`] — a basic block with coverage status and visit count
//! - [`CoverageColor`] — color classification for a block based on heat
//! - [`format_with_coverage`] — convenience function to produce a printable annotated listing

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::{BlockColorInfo, CoverageRun, FunctionStats};

// ─── CoverageColor ────────────────────────────────────────────────────────────

/// A color classification for coverage display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CoverageColor {
    /// Not covered at all.
    NotCovered,
    /// Covered but visited rarely (< 25 % of max).
    Cold,
    /// Covered with moderate frequency (25–75 % of max).
    Warm,
    /// Covered very frequently (> 75 % of max).
    Hot,
}

impl CoverageColor {
    /// Derive a color from a normalised heat value in [0.0, 1.0].
    #[must_use]
    pub fn from_heat(heat: f64) -> Self {
        if heat <= 0.0 {
            Self::NotCovered
        } else if heat < 0.25 {
            Self::Cold
        } else if heat < 0.75 {
            Self::Warm
        } else {
            Self::Hot
        }
    }

    /// ANSI escape code for this color (for terminal output).
    #[must_use]
    pub const fn ansi_color(self) -> &'static str {
        match self {
            Self::NotCovered => "\x1b[90m",  // dark grey
            Self::Cold       => "\x1b[34m",  // blue
            Self::Warm       => "\x1b[33m",  // yellow
            Self::Hot        => "\x1b[31m",  // red
        }
    }

    /// HTML hex color string.
    #[must_use]
    pub const fn html_color(self) -> &'static str {
        match self {
            Self::NotCovered => "#555555",
            Self::Cold       => "#4488ff",
            Self::Warm       => "#ffaa00",
            Self::Hot        => "#ff3333",
        }
    }

    /// Short label string for plain-text output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotCovered => "[ -- ]",
            Self::Cold       => "[COLD]",
            Self::Warm       => "[WARM]",
            Self::Hot        => "[HOT ]",
        }
    }
}

impl fmt::Display for CoverageColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ─── AnnotatedBlock ───────────────────────────────────────────────────────────

/// A basic block entry with coverage metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedBlock {
    /// Start address of this basic block.
    pub addr: u64,
    /// Size of the block in bytes (0 if unknown).
    pub size: u32,
    /// Whether this block was covered in the run.
    pub is_covered: bool,
    /// How many times this block was executed.
    pub visit_count: u64,
    /// Normalised heat value in [0.0, 1.0].
    pub heat: f64,
    /// Computed color category.
    pub color: CoverageColor,
    /// Optional disassembly text for this block.
    pub disasm: Option<String>,
}

impl AnnotatedBlock {
    /// Build an `AnnotatedBlock` from a `BlockColorInfo`.
    #[must_use]
    pub fn from_color_info(info: &BlockColorInfo, size: u32) -> Self {
        Self {
            addr: info.addr,
            size,
            is_covered: info.is_covered,
            visit_count: info.visit_count,
            heat: info.heat,
            color: CoverageColor::from_heat(info.heat),
            disasm: None,
        }
    }

    /// Attach a disassembly text string to this block.
    #[must_use]
    pub fn with_disasm(mut self, text: impl Into<String>) -> Self {
        self.disasm = Some(text.into());
        self
    }

    /// Render a one-line summary for this block.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} 0x{:08x}  size={:4}  visits={:6}  heat={:.3}",
            self.color.label(),
            self.addr,
            self.size,
            self.visit_count,
            self.heat
        )
    }

    /// Render a summary with ANSI color escape codes.
    #[must_use]
    pub fn summary_ansi(&self) -> String {
        const RESET: &str = "\x1b[0m";
        let ansi = self.color.ansi_color();
        format!(
            "{ansi}{} 0x{:08x}{RESET}  size={:4}  visits={:6}  heat={:.3}",
            self.color.label(),
            self.addr,
            self.size,
            self.visit_count,
            self.heat
        )
    }
}

// ─── AnnotatedLine ────────────────────────────────────────────────────────────

/// A single disassembly instruction line with coverage annotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotatedLine {
    /// Address of this instruction.
    pub addr: u64,
    /// Raw disassembly text.
    pub text: String,
    /// Coverage color for the block this instruction belongs to.
    pub color: CoverageColor,
    /// Visit count for the block.
    pub visit_count: u64,
}

impl AnnotatedLine {
    /// Render a plain-text annotated line.
    #[must_use]
    pub fn render_plain(&self) -> String {
        format!(
            "{} 0x{:08x}  {}",
            self.color.label(),
            self.addr,
            self.text
        )
    }

    /// Render with ANSI color codes.
    #[must_use]
    pub fn render_ansi(&self) -> String {
        const RESET: &str = "\x1b[0m";
        let ansi = self.color.ansi_color();
        format!(
            "{ansi}{}{RESET} 0x{:08x}  {}",
            self.color.label(),
            self.addr,
            self.text
        )
    }

    /// Render as an HTML table row.
    #[must_use]
    pub fn render_html_row(&self) -> String {
        let bg = self.color.html_color();
        let escaped = html_escape_str(&self.text);
        format!(
            "<tr style=\"background:{bg}\"><td>0x{:08x}</td><td>{escaped}</td><td>{}</td></tr>\n",
            self.addr, self.visit_count
        )
    }
}

// ─── CoverageVisualizer ───────────────────────────────────────────────────────

/// Combines a `CoverageRun` with disassembly data to produce annotated output.
///
/// Typical usage:
/// ```rust,ignore
/// let mut vis = CoverageVisualizer::new(&run);
/// vis.add_block(0x1000, 10, "push rbp\nmov rbp, rsp");
/// vis.add_block(0x100a, 5, "xor eax, eax\nret");
/// let listing = vis.render_plain();
/// println!("{listing}");
/// ```
pub struct CoverageVisualizer<'a> {
    run: &'a CoverageRun,
    /// Block-level annotations, keyed by start address.
    blocks: Vec<AnnotatedBlock>,
    /// Function table for per-function stats sidebar.
    functions: Vec<FunctionStats>,
    /// Whether to include visit counts in the output.
    show_counts: bool,
    /// Whether to use ANSI escape codes in plain-text output.
    use_ansi: bool,
}

impl<'a> CoverageVisualizer<'a> {
    /// Create a new visualizer backed by the given `CoverageRun`.
    #[must_use]
    pub const fn new(run: &'a CoverageRun) -> Self {
        Self {
            run,
            blocks: Vec::new(),
            functions: Vec::new(),
            show_counts: true,
            use_ansi: false,
        }
    }

    /// Enable or disable ANSI color codes.
    #[must_use]
    pub const fn with_ansi(mut self, enabled: bool) -> Self {
        self.use_ansi = enabled;
        self
    }

    /// Enable or disable visit-count display.
    #[must_use]
    pub const fn with_counts(mut self, enabled: bool) -> Self {
        self.show_counts = enabled;
        self
    }

    /// Set the function table used for per-function coverage sidebars.
    #[must_use]
    pub fn with_functions(mut self, functions: Vec<FunctionStats>) -> Self {
        self.functions = functions;
        self
    }

    /// Register a basic block with optional disassembly text.
    ///
    /// `addr` is the start address, `size` is the byte length of the block,
    /// and `disasm` is a newline-separated string of instruction lines.
    pub fn add_block(&mut self, addr: u64, size: u32, disasm: impl Into<String>) {
        let max_count = self.run.bb_hits.values().copied().max().unwrap_or(1);
        let visit_count = self.run.bb_hits.get(&addr).copied().unwrap_or(0);
        let heat = if max_count == 0 {
            0.0
        } else {
            crate::u64_to_f64(visit_count) / crate::u64_to_f64(max_count)
        };
        let info = BlockColorInfo {
            addr,
            is_covered: visit_count > 0,
            visit_count,
            heat,
        };
        let block = AnnotatedBlock::from_color_info(&info, size)
            .with_disasm(disasm);
        self.blocks.push(block);
    }

    /// Register a block without disassembly text (address + size only).
    pub fn add_block_stub(&mut self, addr: u64, size: u32) {
        self.add_block(addr, size, String::new());
    }

    /// Annotate a list of `(addr, text)` instruction lines using the
    /// coverage data of the most recently added block context.
    #[must_use]
    pub fn annotate_lines(&self, lines: &[(u64, &str)]) -> Vec<AnnotatedLine> {
        let max_count = self.run.bb_hits.values().copied().max().unwrap_or(1);
        // Build a fast addr → block lookup.
        let block_map: HashMap<u64, (CoverageColor, u64)> = self
            .blocks
            .iter()
            .map(|b| (b.addr, (b.color, b.visit_count)))
            .collect();

        lines
            .iter()
            .map(|&(addr, text)| {
                // Find the block this address belongs to.
                let (color, visit_count) = block_map
                    .get(&addr)
                    .copied()
                    .unwrap_or_else(|| {
                        // Fall back to direct run lookup.
                        let vc = self.run.bb_hits.get(&addr).copied().unwrap_or(0);
                        let heat = if max_count == 0 {
                            0.0
                        } else {
                            crate::u64_to_f64(vc) / crate::u64_to_f64(max_count)
                        };
                        (CoverageColor::from_heat(heat), vc)
                    });
                AnnotatedLine {
                    addr,
                    text: text.to_string(),
                    color,
                    visit_count,
                }
            })
            .collect()
    }

    /// Render all registered blocks as a plain-text annotated listing.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let mut out = String::new();
        let mut sorted = self.blocks.clone();
        sorted.sort_unstable_by_key(|b| b.addr);

        for block in &sorted {
            if self.use_ansi {
                out.push_str(&block.summary_ansi());
            } else {
                out.push_str(&block.summary());
            }
            out.push('\n');

            if let Some(disasm) = &block.disasm {
                for line in disasm.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    let color_tag = if self.use_ansi {
                        block.color.ansi_color().to_string()
                    } else {
                        String::new()
                    };
                    let reset = if self.use_ansi { "\x1b[0m" } else { "" };
                    if self.show_counts {
                        writeln!(out,
                            "  {color_tag}{:8}{reset}  {}",
                            block.visit_count, line
                        ).ok();
                    } else {
                        writeln!(out, "  {color_tag}{reset}  {line}").ok();
                    }
                }
            }
        }
        out
    }

    /// Render all blocks as an HTML page.
    #[must_use]
    pub fn render_html(&self, title: &str) -> String {
        let mut rows = String::new();
        let mut sorted = self.blocks.clone();
        sorted.sort_unstable_by_key(|b| b.addr);

        for block in &sorted {
            let bg = block.color.html_color();
            let disasm_html = block
                .disasm
                .as_deref()
                .unwrap_or("")
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| format!("<code>{}</code>", html_escape_str(l)))
                .collect::<Vec<_>>()
                .join("<br/>");

            writeln!(rows,
                "<tr style=\"background:{bg}\">\
                 <td>0x{:08x}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{disasm_html}</td>\
                 </tr>",
                block.addr,
                block.size,
                block.visit_count,
                block.heat
            ).ok();
        }

        let total = sorted.len();
        let covered = sorted.iter().filter(|b| b.is_covered).count();
        let pct = if total == 0 {
            100.0
        } else {
            crate::usize_to_f64(covered) / crate::usize_to_f64(total) * 100.0
        };

        format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{title}</title>
<style>
  body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 2em; }}
  h1 {{ color: #00d4ff; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #333; padding: 6px 10px; }}
  th {{ background: #16213e; color: #fff; }}
  .stat {{ display: inline-block; margin: 0.5em; padding: 0.5em 1em;
           background: #16213e; border-radius: 6px; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div>
  <span class="stat">Total blocks: <b>{total}</b></span>
  <span class="stat">Covered: <b>{covered}</b></span>
  <span class="stat">Coverage: <b>{pct:.1}%</b></span>
</div>
<h2>Block Listing</h2>
<table>
<tr><th>Address</th><th>Size</th><th>Visits</th><th>Heat</th><th>Disassembly</th></tr>
{rows}
</table>
</body>
</html>
"#
        )
    }

    /// Render a per-function coverage sidebar.
    #[must_use]
    pub fn render_function_sidebar(&self) -> String {
        if self.functions.is_empty() {
            return String::new();
        }
        let mut out = String::from("=== Function Coverage ===\n");
        for fs in &self.functions {
            // Compute covered BB count from run data in the function's range.
            let covered = self
                .run
                .bb_hits
                .keys()
                .filter(|&&addr| addr >= fs.start_addr && addr < fs.end_addr)
                .count();
            let total = fs.total_bb.max(covered);
            let pct = if total == 0 {
                100.0
            } else {
                crate::usize_to_f64(covered) / crate::usize_to_f64(total) * 100.0
            };
            let bar = progress_bar(pct, 20);
            writeln!(out,
                "  {:40}  [{bar}]  {:5.1}%  (visited={:4})",
                truncate_str(&fs.name, 40),
                pct,
                self.run.bb_hits.get(&fs.start_addr).copied().unwrap_or(0)
            ).ok();
        }
        out
    }

    /// Number of registered blocks.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of covered blocks.
    #[must_use]
    pub fn covered_count(&self) -> usize {
        self.blocks.iter().filter(|b| b.is_covered).count()
    }

    /// Overall block coverage percentage.
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.blocks.is_empty() {
            return 100.0;
        }
        crate::usize_to_f64(self.covered_count()) / crate::usize_to_f64(self.blocks.len()) * 100.0
    }

    /// Return a sorted list of all annotated blocks (sorted by address).
    #[must_use]
    pub fn sorted_blocks(&self) -> Vec<AnnotatedBlock> {
        let mut sorted = self.blocks.clone();
        sorted.sort_unstable_by_key(|b| b.addr);
        sorted
    }

    /// Find the hottest block (maximum visit count).
    #[must_use]
    pub fn hottest_block(&self) -> Option<&AnnotatedBlock> {
        self.blocks.iter().max_by_key(|b| b.visit_count)
    }

    /// Find all uncovered blocks (visit count == 0).
    #[must_use]
    pub fn uncovered_blocks(&self) -> Vec<&AnnotatedBlock> {
        self.blocks.iter().filter(|b| !b.is_covered).collect()
    }

    /// Return a heat-sorted list (hottest first).
    #[must_use]
    pub fn heat_sorted_blocks(&self) -> Vec<AnnotatedBlock> {
        let mut sorted = self.blocks.clone();
        sorted.sort_unstable_by(|a, b| {
            b.visit_count
                .cmp(&a.visit_count)
                .then(a.addr.cmp(&b.addr))
        });
        sorted
    }
}

// ─── format_with_coverage ────────────────────────────────────────────────────

/// Convenience function: given a `CoverageRun` and a list of `(addr, instruction_text)` pairs,
/// produce a plain-text annotated listing.
///
/// Each line is prefixed with a coverage label such as `[HOT ]` or `[ -- ]`.
#[must_use]
pub fn format_with_coverage(run: &CoverageRun, lines: &[(u64, &str)]) -> String {
    let vis = CoverageVisualizer::new(run);
    let annotated = vis.annotate_lines(lines);
    annotated
        .iter()
        .map(AnnotatedLine::render_plain)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Same as [`format_with_coverage`] but includes ANSI color codes.
#[must_use]
pub fn format_with_coverage_ansi(run: &CoverageRun, lines: &[(u64, &str)]) -> String {
    let vis = CoverageVisualizer::new(run).with_ansi(true);
    let annotated = vis.annotate_lines(lines);
    annotated
        .iter()
        .map(AnnotatedLine::render_ansi)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render an annotated listing as an HTML table fragment.
///
/// Returns the `<table>…</table>` HTML without the surrounding page structure.
#[must_use]
pub fn format_with_coverage_html(run: &CoverageRun, lines: &[(u64, &str)]) -> String {
    let vis = CoverageVisualizer::new(run);
    let annotated = vis.annotate_lines(lines);
    let mut out = String::from(
        "<table style=\"border-collapse:collapse;font-family:monospace\">\
         <tr><th>Coverage</th><th>Address</th><th>Instruction</th><th>Visits</th></tr>\n",
    );
    for line in &annotated {
        out.push_str(&line.render_html_row());
    }
    out.push_str("</table>");
    out
}

// ─── CoverageAnnotationConfig ─────────────────────────────────────────────────

/// Output rendering format for coverage annotations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Plain text, no color codes.
    #[default]
    Plain,
    /// ANSI terminal color escape codes.
    Ansi,
    /// HTML markup for browser display.
    Html,
}

/// Boolean render flags grouped to avoid the `struct_excessive_bools` lint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationFlags {
    /// Whether to show visit counts alongside each block.
    pub show_visit_counts: bool,
    /// Whether to append the normalised heat value to block summaries.
    pub show_heat: bool,
    /// Output format: plain text, ANSI-colored, or HTML.
    pub output_format: OutputFormat,
}

impl AnnotationFlags {
    /// Returns `true` when ANSI color escape codes should be emitted.
    #[must_use]
    pub fn use_ansi_colors(&self) -> bool {
        self.output_format == OutputFormat::Ansi
    }

    /// Returns `true` when HTML markup should be emitted.
    #[must_use]
    pub fn html_output(&self) -> bool {
        self.output_format == OutputFormat::Html
    }
}

impl Default for AnnotationFlags {
    fn default() -> Self {
        Self {
            show_visit_counts: true,
            show_heat: false,
            output_format: OutputFormat::Plain,
        }
    }
}

/// Configuration for how annotations are rendered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAnnotationConfig {
    /// Render flags (grouped to avoid excessive-bools lint).
    pub flags: AnnotationFlags,
    /// Minimum visit count to color as "warm".
    pub warm_threshold: u64,
    /// Minimum visit count to color as "hot".
    pub hot_threshold: u64,
}

impl Default for CoverageAnnotationConfig {
    fn default() -> Self {
        Self {
            flags: AnnotationFlags::default(),
            warm_threshold: 5,
            hot_threshold: 50,
        }
    }
}

impl CoverageAnnotationConfig {
    /// Create a new default config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ─── BlockAnnotator ───────────────────────────────────────────────────────────

/// A stateful annotator that applies a config to a stream of basic blocks.
pub struct BlockAnnotator {
    config: CoverageAnnotationConfig,
    max_count: u64,
}

impl BlockAnnotator {
    /// Create an annotator calibrated to a specific `CoverageRun`.
    #[must_use]
    pub fn new(run: &CoverageRun, config: CoverageAnnotationConfig) -> Self {
        let max_count = run.bb_hits.values().copied().max().unwrap_or(1);
        Self { config, max_count }
    }

    /// Annotate a single basic block.
    #[must_use]
    pub fn annotate(&self, addr: u64, visit_count: u64) -> AnnotatedBlock {
        let heat = if self.max_count == 0 {
            0.0
        } else {
            crate::u64_to_f64(visit_count) / crate::u64_to_f64(self.max_count)
        };
        let color = if visit_count == 0 {
            CoverageColor::NotCovered
        } else if visit_count < self.config.warm_threshold {
            CoverageColor::Cold
        } else if visit_count < self.config.hot_threshold {
            CoverageColor::Warm
        } else {
            CoverageColor::Hot
        };
        AnnotatedBlock {
            addr,
            size: 0,
            is_covered: visit_count > 0,
            visit_count,
            heat,
            color,
            disasm: None,
        }
    }

    /// Format a block using the stored config.
    ///
    /// When `flags.show_heat` is set, appends the normalised heat value.
    /// When `flags.html_output()` is set, wraps output in an HTML span.
    #[must_use]
    pub fn format_block(&self, block: &AnnotatedBlock) -> String {
        let base = if self.config.flags.use_ansi_colors() {
            block.summary_ansi()
        } else if self.config.flags.html_output() {
            format!(
                "<span style=\"color:{}\">{}</span>",
                block.color.html_color(),
                block.summary()
            )
        } else {
            block.summary()
        };
        if self.config.flags.show_heat {
            format!("{base}  heat={:.3}", block.heat)
        } else {
            base
        }
    }

    /// Format a block with a custom disassembly prefix.
    #[must_use]
    pub fn format_with_disasm(&self, block: &AnnotatedBlock, disasm_line: &str) -> String {
        let label = if self.config.flags.use_ansi_colors() {
            format!(
                "{}{}{}",
                block.color.ansi_color(),
                block.color.label(),
                "\x1b[0m"
            )
        } else {
            block.color.label().to_string()
        };
        if self.config.flags.show_visit_counts {
            format!("{label}  {:6}  0x{:08x}  {disasm_line}", block.visit_count, block.addr)
        } else {
            format!("{label}  0x{:08x}  {disasm_line}", block.addr)
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Truncate a string to at most `max_len` chars, appending `…` if needed.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}

/// Render a simple ASCII progress bar of width `width` for a percentage.
fn progress_bar(pct: f64, width: usize) -> String {
    let filled = crate::f64_to_usize_clamp(((pct / 100.0) * crate::usize_to_f64(width)).round());
    let empty = width.saturating_sub(filled);
    format!("{}{}", "#".repeat(filled), ".".repeat(empty))
}

/// Escape HTML special characters.
fn html_escape_str(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoverageRun;

    fn make_run() -> CoverageRun {
        let mut run = CoverageRun::new("test");
        run.record_bb_n(0x1000, 100);
        run.record_bb_n(0x1010, 10);
        run.record_bb_n(0x1020, 1);
        // 0x1030 is not covered
        run
    }

    #[test]
    fn test_coverage_color_from_heat() {
        assert_eq!(CoverageColor::from_heat(0.0), CoverageColor::NotCovered);
        assert_eq!(CoverageColor::from_heat(0.1), CoverageColor::Cold);
        assert_eq!(CoverageColor::from_heat(0.5), CoverageColor::Warm);
        assert_eq!(CoverageColor::from_heat(0.9), CoverageColor::Hot);
    }

    #[test]
    fn test_coverage_color_labels() {
        assert_eq!(CoverageColor::NotCovered.label(), "[ -- ]");
        assert_eq!(CoverageColor::Hot.label(), "[HOT ]");
    }

    #[test]
    fn test_coverage_visualizer_add_block() {
        let run = make_run();
        let mut vis = CoverageVisualizer::new(&run);
        vis.add_block(0x1000, 10, "push rbp");
        vis.add_block(0x1030, 5, "nop");
        assert_eq!(vis.block_count(), 2);
        assert_eq!(vis.covered_count(), 1);
    }

    #[test]
    fn test_coverage_visualizer_coverage_pct() {
        let run = make_run();
        let mut vis = CoverageVisualizer::new(&run);
        vis.add_block(0x1000, 10, "");
        vis.add_block(0x1030, 5, "");
        let pct = vis.coverage_pct();
        assert!((pct - 50.0).abs() < 1e-9, "pct={pct}");
    }

    #[test]
    fn test_coverage_visualizer_render_plain() {
        let run = make_run();
        let mut vis = CoverageVisualizer::new(&run);
        vis.add_block(0x1000, 10, "push rbp\nmov rbp, rsp");
        let output = vis.render_plain();
        assert!(output.contains("[HOT ]"));
        assert!(output.contains("push rbp"));
    }

    #[test]
    fn test_coverage_visualizer_hottest_block() {
        let run = make_run();
        let mut vis = CoverageVisualizer::new(&run);
        vis.add_block(0x1000, 10, "");
        vis.add_block(0x1010, 5, "");
        vis.add_block(0x1020, 4, "");
        let hottest = vis.hottest_block().expect("should have hottest block");
        assert_eq!(hottest.addr, 0x1000);
    }

    #[test]
    fn test_coverage_visualizer_uncovered_blocks() {
        let run = make_run();
        let mut vis = CoverageVisualizer::new(&run);
        vis.add_block(0x1000, 10, "");
        vis.add_block(0x1030, 5, ""); // not in run
        let uncovered = vis.uncovered_blocks();
        assert_eq!(uncovered.len(), 1);
        assert_eq!(uncovered[0].addr, 0x1030);
    }

    #[test]
    fn test_format_with_coverage() {
        let run = make_run();
        let lines = vec![(0x1000u64, "push rbp"), (0x1030u64, "nop")];
        let output = format_with_coverage(&run, &lines);
        assert!(output.contains("0x00001000"));
        assert!(output.contains("push rbp"));
        assert!(output.contains("[ -- ]") || output.contains("[HOT ]"));
    }

    #[test]
    fn test_annotated_line_render_html_row() {
        let line = AnnotatedLine {
            addr: 0x1000,
            text: "push rbp".to_string(),
            color: CoverageColor::Hot,
            visit_count: 42,
        };
        let html = line.render_html_row();
        assert!(html.contains("0x00001000"));
        assert!(html.contains("push rbp"));
        assert!(html.contains("42"));
    }

    #[test]
    fn test_annotated_block_summary() {
        let info = BlockColorInfo {
            addr: 0x2000,
            is_covered: true,
            visit_count: 7,
            heat: 0.5,
        };
        let block = AnnotatedBlock::from_color_info(&info, 16);
        let summary = block.summary();
        assert!(summary.contains("0x00002000"));
        assert!(summary.contains('7'));
    }

    #[test]
    fn test_block_annotator_custom_thresholds() {
        let run = make_run();
        let config = CoverageAnnotationConfig {
            warm_threshold: 2,
            hot_threshold: 20,
            ..Default::default()
        };
        let annotator = BlockAnnotator::new(&run, config);
        let b = annotator.annotate(0x1000, 100);
        assert_eq!(b.color, CoverageColor::Hot);
        let c = annotator.annotate(0x1020, 1);
        assert_eq!(c.color, CoverageColor::Cold);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape_str("<b>test</b>"), "&lt;b&gt;test&lt;/b&gt;");
    }

    #[test]
    fn test_render_html_contains_table() {
        let run = make_run();
        let mut vis = CoverageVisualizer::new(&run);
        vis.add_block(0x1000, 10, "nop");
        let html = vis.render_html("Test Coverage");
        assert!(html.contains("<table"));
        assert!(html.contains("Test Coverage"));
        assert!(html.contains("0x00001000"));
    }

    #[test]
    fn test_heat_sorted_blocks_order() {
        let run = make_run();
        let mut vis = CoverageVisualizer::new(&run);
        vis.add_block(0x1000, 10, "");
        vis.add_block(0x1010, 5, "");
        vis.add_block(0x1020, 4, "");
        let sorted = vis.heat_sorted_blocks();
        assert_eq!(sorted[0].addr, 0x1000);
    }

    #[test]
    fn test_format_with_coverage_html() {
        let run = make_run();
        let lines = vec![(0x1000u64, "push rbp"), (0x1030u64, "nop")];
        let html = format_with_coverage_html(&run, &lines);
        assert!(html.starts_with("<table"));
        assert!(html.contains("push rbp"));
    }
}
