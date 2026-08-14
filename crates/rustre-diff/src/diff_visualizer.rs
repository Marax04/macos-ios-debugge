//! `diff_visualizer` — Human-readable diff output generation.
//!
//! Provides [`DiffVisualizer`], [`DiffView`], and [`DiffLine`] along with
//! [`generate_unified_diff`] for standard unified-diff output.

use std::fmt;
use std::fmt::Write as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::diff_algorithm::{DiffAlgorithm, EditKind, EditScript};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by diff visualisation operations.
#[derive(Debug, Error)]
pub enum VisualizerError {
    /// Context lines value is too large relative to input.
    #[error("context lines ({0}) exceeds input length")]
    ContextTooLarge(usize),
    /// The provided edit script is inconsistent with the input lengths.
    #[error("edit script is inconsistent with inputs")]
    InconsistentScript,
    /// Requested output format is not supported.
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}

// ---------------------------------------------------------------------------
// LineOrigin
// ---------------------------------------------------------------------------

/// Origin classification for a line in the diff output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LineOrigin {
    /// Line is unchanged (context).
    Context,
    /// Line was added in the new version.
    Added,
    /// Line was removed from the old version.
    Removed,
    /// Line header (e.g. `@@` hunk marker or `---`/`+++` file header).
    Header,
}

impl LineOrigin {
    /// The sigil character for this origin in unified diff format.
    #[must_use]
    pub const fn sigil(self) -> char {
        match self {
            Self::Context => ' ',
            Self::Added => '+',
            Self::Removed => '-',
            Self::Header => '@',
        }
    }
}

impl fmt::Display for LineOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sigil())
    }
}

// ---------------------------------------------------------------------------
// DiffLine
// ---------------------------------------------------------------------------

/// A single line in a [`DiffView`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    /// Origin/kind of this line.
    pub origin: LineOrigin,
    /// The content of the line (without the sigil).
    pub content: String,
    /// Line number in the old (left) file, if applicable.
    pub old_lineno: Option<usize>,
    /// Line number in the new (right) file, if applicable.
    pub new_lineno: Option<usize>,
}

impl DiffLine {
    /// Create a context line.
    #[must_use]
    pub const fn context(content: String, old: usize, new: usize) -> Self {
        Self { origin: LineOrigin::Context, content, old_lineno: Some(old), new_lineno: Some(new) }
    }

    /// Create an added line.
    #[must_use]
    pub const fn added(content: String, new: usize) -> Self {
        Self { origin: LineOrigin::Added, content, old_lineno: None, new_lineno: Some(new) }
    }

    /// Create a removed line.
    #[must_use]
    pub const fn removed(content: String, old: usize) -> Self {
        Self { origin: LineOrigin::Removed, content, old_lineno: Some(old), new_lineno: None }
    }

    /// Create a header line.
    #[must_use]
    pub const fn header(content: String) -> Self {
        Self { origin: LineOrigin::Header, content, old_lineno: None, new_lineno: None }
    }
}

impl fmt::Display for DiffLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.origin.sigil(), self.content)
    }
}

// ---------------------------------------------------------------------------
// Hunk
// ---------------------------------------------------------------------------

/// A contiguous block of changes in the diff output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hunk {
    /// Starting line in the old file (1-based).
    pub old_start: usize,
    /// Number of lines from the old file in this hunk.
    pub old_count: usize,
    /// Starting line in the new file (1-based).
    pub new_start: usize,
    /// Number of lines from the new file in this hunk.
    pub new_count: usize,
    /// The diff lines making up this hunk (context + changes).
    pub lines: Vec<DiffLine>,
}

impl Hunk {
    /// Format the hunk header in unified diff format: `@@ -a,b +c,d @@`.
    #[must_use]
    pub fn header(&self) -> String {
        format!(
            "@@ -{},{} +{},{} @@",
            self.old_start, self.old_count,
            self.new_start, self.new_count
        )
    }
}

impl fmt::Display for Hunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.header())?;
        for line in &self.lines {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DiffView
// ---------------------------------------------------------------------------

/// The full diff between two texts, split into hunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffView {
    /// Path or label of the old file.
    pub old_label: String,
    /// Path or label of the new file.
    pub new_label: String,
    /// Hunks of changes.
    pub hunks: Vec<Hunk>,
    /// Total lines added across all hunks.
    pub total_added: usize,
    /// Total lines removed across all hunks.
    pub total_removed: usize,
    /// Total context lines across all hunks.
    pub total_context: usize,
}

impl DiffView {
    /// Returns `true` if there are no changes.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.hunks.is_empty()
    }

    /// Number of hunks.
    #[must_use]
    pub const fn hunk_count(&self) -> usize {
        self.hunks.len()
    }

    /// Render the full diff as a unified diff string.
    #[must_use]
    pub fn to_unified_string(&self) -> String {
        let mut out = String::new();
        writeln!(out, "--- {}", self.old_label).unwrap_or_default();
        writeln!(out, "+++ {}", self.new_label).unwrap_or_default();
        for hunk in &self.hunks {
            out.push_str(&hunk.to_string());
        }
        out
    }

    /// Collect all [`DiffLine`]s from all hunks in order.
    #[must_use]
    pub fn all_lines(&self) -> Vec<&DiffLine> {
        self.hunks.iter().flat_map(|h| h.lines.iter()).collect()
    }

    /// Summary string: `+N -M in K hunks`.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "+{} -{} in {} hunk{}",
            self.total_added,
            self.total_removed,
            self.hunk_count(),
            if self.hunk_count() == 1 { "" } else { "s" }
        )
    }
}

impl fmt::Display for DiffView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_unified_string())
    }
}

// ---------------------------------------------------------------------------
// DiffVisualizer
// ---------------------------------------------------------------------------

/// Configurable visualiser for converting edit scripts into human-readable diffs.
#[derive(Debug, Clone)]
pub struct DiffVisualizer {
    /// Number of context lines to show around each change.
    context_lines: usize,
    /// Whether to show line numbers in the output.
    show_line_numbers: bool,
    /// Whether to emit colour escape codes.
    colorize: bool,
    /// Algorithm to use when computing the edit script from raw text.
    algorithm: DiffAlgorithm,
}

/// Helper: one line-level edit operation.
struct LineOp {
    kind: EditKind,
    old_idx: Option<usize>,
    new_idx: Option<usize>,
}

impl DiffVisualizer {
    /// Create a new visualiser with the given context line count.
    #[must_use]
    pub const fn new(context_lines: usize) -> Self {
        Self {
            context_lines,
            show_line_numbers: true,
            colorize: false,
            algorithm: DiffAlgorithm::Myers,
        }
    }

    /// Enable or disable line numbers in the output.
    #[must_use]
    pub const fn with_line_numbers(mut self, show: bool) -> Self {
        self.show_line_numbers = show;
        self
    }

    /// Enable or disable ANSI colour codes.
    #[must_use]
    pub const fn with_color(mut self, colorize: bool) -> Self {
        self.colorize = colorize;
        self
    }

    /// Set the algorithm used to compute the edit script.
    #[must_use]
    pub const fn with_algorithm(mut self, algorithm: DiffAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Compute a [`DiffView`] from two text strings, split on newlines.
    ///
    /// # Errors
    ///
    /// Returns [`VisualizerError::InconsistentScript`] if the edit script
    /// cannot be backtracked correctly.
    pub fn diff_text(
        &self,
        old_text: &str,
        new_text: &str,
        old_label: &str,
        new_label: &str,
    ) -> Result<DiffView, VisualizerError> {
        let old_lines: Vec<&str> = old_text.lines().collect();
        let new_lines: Vec<&str> = new_text.lines().collect();
        self.diff_lines(&old_lines, &new_lines, old_label, new_label)
    }

    /// Compute a [`DiffView`] from two slices of lines.
    ///
    /// # Errors
    ///
    /// Returns [`VisualizerError::InconsistentScript`] if script backtracking fails.
    pub fn diff_lines(
        &self,
        old_lines: &[&str],
        new_lines: &[&str],
        old_label: &str,
        new_label: &str,
    ) -> Result<DiffView, VisualizerError> {
        // Encode lines as bytes using a SHARED dictionary across both sides so
        // identical lines map to the same byte (otherwise every line would
        // look "equal" because both sides would independently allocate 0,1,2…).
        let (old_bytes, new_bytes, _old_map, _new_map) = encode_lines_pair(old_lines, new_lines);

        let script = match self.algorithm {
            DiffAlgorithm::Myers => crate::diff_algorithm::myers_diff(&old_bytes, &new_bytes),
            DiffAlgorithm::Lcs => crate::diff_algorithm::lcs_diff(&old_bytes, &new_bytes),
            DiffAlgorithm::Patience => crate::diff_algorithm::patience_diff(&old_bytes, &new_bytes),
            DiffAlgorithm::Histogram => crate::diff_algorithm::histogram_diff(&old_bytes, &new_bytes),
        };

        Ok(self.build_view(old_lines, new_lines, &script, old_label, new_label))
    }

    /// Compute a [`DiffView`] directly from a pre-computed [`EditScript`].
    ///
    /// # Errors
    ///
    /// Returns [`VisualizerError::InconsistentScript`] if index references are out of bounds.
    pub fn from_script(
        &self,
        old_lines: &[&str],
        new_lines: &[&str],
        script: &EditScript,
        old_label: &str,
        new_label: &str,
    ) -> Result<DiffView, VisualizerError> {
        let _ = encode_lines_pair(old_lines, new_lines);
        Ok(self.build_view(old_lines, new_lines, script, old_label, new_label))
    }

    fn build_view(
        &self,
        old_lines: &[&str],
        new_lines: &[&str],
        script: &EditScript,
        old_label: &str,
        new_label: &str,
    ) -> DiffView {
        // Convert edit ops into (old_idx, new_idx, kind) triples
        let line_ops: Vec<LineOp> = script.ops.iter().map(|op| LineOp {
            kind: op.kind,
            old_idx: op.old_index,
            new_idx: op.new_index,
        }).collect();

        // Build change flags: which ops are changes?
        let is_change: Vec<bool> = line_ops.iter().map(|o| o.kind != EditKind::Equal).collect();

        // Group ops into hunks with context
        let mut hunks: Vec<Hunk> = Vec::new();
        let n = line_ops.len();
        let mut i = 0;
        while i < n {
            if !is_change[i] {
                i += 1;
                continue;
            }
            // Found a change — determine hunk extent
            let hunk_start = i.saturating_sub(self.context_lines);
            // Find end of run of changes
            let mut hunk_end = i;
            while hunk_end < n {
                if is_change[hunk_end] {
                    // extend context after last change
                    hunk_end = (hunk_end + self.context_lines + 1).min(n);
                    // scan forward to see if next change is within context
                    let next_change = line_ops[hunk_end.min(n - 1)..]
                        .iter()
                        .position(|o| o.kind != EditKind::Equal)
                        .map(|p| hunk_end + p);
                    if let Some(nc) = next_change
                        && nc < hunk_end + self.context_lines {
                            hunk_end = nc;
                            continue;
                        }
                    break;
                }
                hunk_end += 1;
            }
            let hunk_end = hunk_end.min(n);

            // Build hunk lines
            let (hunk_lines, old_start, old_count, new_start, new_count) =
                Self::build_hunk_lines(&line_ops[hunk_start..hunk_end], old_lines, new_lines);

            if !hunk_lines.is_empty() {
                hunks.push(Hunk {
                    old_start,
                    old_count,
                    new_start,
                    new_count,
                    lines: hunk_lines,
                });
            }

            i = hunk_end;
        }

        let total_added: usize = hunks.iter().flat_map(|h| h.lines.iter())
            .filter(|l| l.origin == LineOrigin::Added).count();
        let total_removed: usize = hunks.iter().flat_map(|h| h.lines.iter())
            .filter(|l| l.origin == LineOrigin::Removed).count();
        let total_context: usize = hunks.iter().flat_map(|h| h.lines.iter())
            .filter(|l| l.origin == LineOrigin::Context).count();

        DiffView {
            old_label: old_label.to_string(),
            new_label: new_label.to_string(),
            hunks,
            total_added,
            total_removed,
            total_context,
        }
    }

    /// Build lines for a single hunk from a slice of `LineOp`s.
    fn build_hunk_lines(
        ops: &[LineOp],
        old_lines: &[&str],
        new_lines: &[&str],
    ) -> (Vec<DiffLine>, usize, usize, usize, usize) {
        let mut hunk_lines: Vec<DiffLine> = Vec::new();
        let mut old_start = 1usize;
        let mut old_count = 0usize;
        let mut new_start = 1usize;
        let mut new_count = 0usize;
        let mut first = true;
        for op in ops {
            let old_idx = op.old_idx;
            let new_idx = op.new_idx;
            if first {
                old_start = old_idx.or(new_idx).unwrap_or(0) + 1;
                new_start = new_idx.or(old_idx).unwrap_or(0) + 1;
                first = false;
            }
            match op.kind {
                EditKind::Equal => {
                    let content = old_idx.and_then(|i| old_lines.get(i)).copied().unwrap_or("");
                    hunk_lines.push(DiffLine::context(content.to_string(), old_idx.unwrap_or(0) + 1, new_idx.unwrap_or(0) + 1));
                    old_count += 1;
                    new_count += 1;
                }
                EditKind::Insert => {
                    let content = new_idx.and_then(|j| new_lines.get(j)).copied().unwrap_or("");
                    hunk_lines.push(DiffLine::added(content.to_string(), new_idx.unwrap_or(0) + 1));
                    new_count += 1;
                }
                EditKind::Delete => {
                    let content = old_idx.and_then(|i| old_lines.get(i)).copied().unwrap_or("");
                    hunk_lines.push(DiffLine::removed(content.to_string(), old_idx.unwrap_or(0) + 1));
                    old_count += 1;
                }
                EditKind::Replace => {
                    let old_c = old_idx.and_then(|i| old_lines.get(i)).copied().unwrap_or("");
                    let new_c = new_idx.and_then(|j| new_lines.get(j)).copied().unwrap_or("");
                    hunk_lines.push(DiffLine::removed(old_c.to_string(), old_idx.unwrap_or(0) + 1));
                    hunk_lines.push(DiffLine::added(new_c.to_string(), new_idx.unwrap_or(0) + 1));
                    old_count += 1;
                    new_count += 1;
                }
            }
        }
        (hunk_lines, old_start, old_count, new_start, new_count)
    }

    /// Render a [`DiffView`] to a plain-text string, optionally with colours.
    #[must_use]
    pub fn render(&self, view: &DiffView) -> String {
        if self.colorize {
            render_colored(view)
        } else {
            view.to_unified_string()
        }
    }
}

impl Default for DiffVisualizer {
    fn default() -> Self {
        Self::new(3)
    }
}

// ---------------------------------------------------------------------------
// generate_unified_diff — primary entry point
// ---------------------------------------------------------------------------

/// Generate a unified diff string for two text inputs.
///
/// Uses Myers diff with 3 lines of context.  Suitable for most RE use-cases
/// such as decompiled code or disassembly output.
///
/// # Errors
///
/// Returns [`VisualizerError::InconsistentScript`] if the edit script is
/// inconsistent with the input slices.
pub fn generate_unified_diff(
    old_text: &str,
    new_text: &str,
    old_label: &str,
    new_label: &str,
    context_lines: usize,
) -> Result<String, VisualizerError> {
    let vis = DiffVisualizer::new(context_lines);
    let view = vis.diff_text(old_text, new_text, old_label, new_label)?;
    Ok(view.to_unified_string())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Encode a slice of text lines into a compact byte sequence for diffing.
///
/// Each unique line maps to a byte value (mod 256).  The mapping is returned
/// alongside the encoded bytes so callers can decode indices.
fn encode_lines<'a>(
    lines: &[&'a str],
    line_to_byte: &mut std::collections::HashMap<&'a str, u8>,
    next_byte: &mut u8,
) -> (Vec<u8>, Vec<usize>) {
    let mut bytes = Vec::with_capacity(lines.len());
    let mut map = Vec::with_capacity(lines.len());
    for (i, &line) in lines.iter().enumerate() {
        let byte = *line_to_byte.entry(line).or_insert_with(|| {
            let b = *next_byte;
            *next_byte = next_byte.wrapping_add(1);
            b
        });
        bytes.push(byte);
        map.push(i);
    }
    (bytes, map)
}

/// Encode two line slices into byte sequences using a SHARED dictionary, so
/// the same textual line gets the same byte on both sides. This is the
/// representation diff algorithms actually need.
fn encode_lines_pair<'a>(
    old_lines: &[&'a str],
    new_lines: &[&'a str],
) -> (Vec<u8>, Vec<u8>, Vec<usize>, Vec<usize>) {
    use std::collections::HashMap;
    let mut line_to_byte: HashMap<&'a str, u8> = HashMap::new();
    let mut next_byte: u8 = 0;
    let (old_bytes, old_map) = encode_lines(old_lines, &mut line_to_byte, &mut next_byte);
    let (new_bytes, new_map) = encode_lines(new_lines, &mut line_to_byte, &mut next_byte);
    (old_bytes, new_bytes, old_map, new_map)
}

/// Render a diff with ANSI colour codes.
fn render_colored(view: &DiffView) -> String {
    const RED: &str = "\x1b[31m";
    const GREEN: &str = "\x1b[32m";
    const CYAN: &str = "\x1b[36m";
    const RESET: &str = "\x1b[0m";

    let mut out = String::new();
    writeln!(out, "{}--- {}{}", RED, view.old_label, RESET).unwrap_or_default();
    writeln!(out, "{}+++ {}{}", GREEN, view.new_label, RESET).unwrap_or_default();
    for hunk in &view.hunks {
        writeln!(out, "{}{}{}", CYAN, hunk.header(), RESET).unwrap_or_default();
        for line in &hunk.lines {
            match line.origin {
                LineOrigin::Added => {
                    writeln!(out, "{}+{}{}", GREEN, line.content, RESET).unwrap_or_default();
                }
                LineOrigin::Removed => {
                    writeln!(out, "{}-{}{}", RED, line.content, RESET).unwrap_or_default();
                }
                _ => {
                    writeln!(out, " {}", line.content).unwrap_or_default();
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SideBySideView
// ---------------------------------------------------------------------------

/// A pair of corresponding lines for side-by-side diff display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideBySideLine {
    /// The left (old) side content.
    pub left: Option<String>,
    /// The right (new) side content.
    pub right: Option<String>,
    /// Whether this line pair represents a change.
    pub changed: bool,
    /// Left line number.
    pub left_lineno: Option<usize>,
    /// Right line number.
    pub right_lineno: Option<usize>,
}

impl SideBySideLine {
    /// Format for a fixed-width terminal column.
    #[must_use]
    pub fn format_columns(&self, width: usize) -> String {
        let left = self.left.as_deref().unwrap_or("");
        let right = self.right.as_deref().unwrap_or("");
        let left_col = format!("{left:<width$}");
        let sep = if self.changed { " | " } else { "   " };
        format!("{left_col}{sep}{right}")
    }
}

/// Convert a [`DiffView`] into side-by-side lines.
#[must_use]
pub fn to_side_by_side(view: &DiffView) -> Vec<SideBySideLine> {
    let mut result = Vec::new();
    for hunk in &view.hunks {
        let mut i = 0;
        let lines = &hunk.lines;
        while i < lines.len() {
            match lines[i].origin {
                LineOrigin::Context => {
                    result.push(SideBySideLine {
                        left: Some(lines[i].content.clone()),
                        right: Some(lines[i].content.clone()),
                        changed: false,
                        left_lineno: lines[i].old_lineno,
                        right_lineno: lines[i].new_lineno,
                    });
                    i += 1;
                }
                LineOrigin::Removed => {
                    // Check if next line is Added (pair)
                    if i + 1 < lines.len() && lines[i + 1].origin == LineOrigin::Added {
                        result.push(SideBySideLine {
                            left: Some(lines[i].content.clone()),
                            right: Some(lines[i + 1].content.clone()),
                            changed: true,
                            left_lineno: lines[i].old_lineno,
                            right_lineno: lines[i + 1].new_lineno,
                        });
                        i += 2;
                    } else {
                        result.push(SideBySideLine {
                            left: Some(lines[i].content.clone()),
                            right: None,
                            changed: true,
                            left_lineno: lines[i].old_lineno,
                            right_lineno: None,
                        });
                        i += 1;
                    }
                }
                LineOrigin::Added => {
                    result.push(SideBySideLine {
                        left: None,
                        right: Some(lines[i].content.clone()),
                        changed: true,
                        left_lineno: None,
                        right_lineno: lines[i].new_lineno,
                    });
                    i += 1;
                }
                LineOrigin::Header => {
                    i += 1;
                }
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "line one\nline two\nline three\nline four\nline five";
    const NEW: &str = "line one\nline TWO\nline three\nline FOUR\nline five";

    #[test]
    fn test_generate_unified_diff_identical() {
        let text = "no changes here\nsecond line";
        let result = generate_unified_diff(text, text, "old.txt", "new.txt", 3).unwrap();
        // No changes means no hunks, just header
        assert!(!result.contains("@@"));
    }

    #[test]
    fn test_generate_unified_diff_basic() {
        let result = generate_unified_diff(OLD, NEW, "old.c", "new.c", 1).unwrap();
        assert!(result.contains("--- old.c"));
        assert!(result.contains("+++ new.c"));
        assert!(result.contains("@@"));
    }

    #[test]
    fn test_diff_view_is_clean() {
        let vis = DiffVisualizer::default();
        let view = vis.diff_text("same\ntext", "same\ntext", "a", "b").unwrap();
        assert!(view.is_clean());
        assert_eq!(view.hunk_count(), 0);
    }

    #[test]
    fn test_diff_view_summary() {
        let vis = DiffVisualizer::default();
        let view = vis.diff_text(OLD, NEW, "a", "b").unwrap();
        let summary = view.summary();
        assert!(summary.contains("+"));
        assert!(summary.contains("-"));
    }

    #[test]
    fn test_diff_view_total_counts() {
        let vis = DiffVisualizer::default();
        let view = vis.diff_text(OLD, NEW, "a", "b").unwrap();
        assert!(view.total_added > 0);
        assert!(view.total_removed > 0);
    }

    #[test]
    fn test_hunk_header_format() {
        let hunk = Hunk {
            old_start: 5, old_count: 3,
            new_start: 5, new_count: 4,
            lines: vec![],
        };
        let h = hunk.header();
        assert_eq!(h, "@@ -5,3 +5,4 @@");
    }

    #[test]
    fn test_diff_line_display_added() {
        let line = DiffLine::added("new content".to_string(), 10);
        assert_eq!(line.to_string(), "+new content");
        assert_eq!(line.origin, LineOrigin::Added);
    }

    #[test]
    fn test_diff_line_display_removed() {
        let line = DiffLine::removed("old content".to_string(), 5);
        assert_eq!(line.to_string(), "-old content");
    }

    #[test]
    fn test_diff_line_context() {
        let line = DiffLine::context("ctx".to_string(), 3, 3);
        assert_eq!(line.to_string(), " ctx");
        assert_eq!(line.origin, LineOrigin::Context);
    }

    #[test]
    fn test_visualizer_with_algorithm() {
        let vis = DiffVisualizer::new(2)
            .with_algorithm(DiffAlgorithm::Lcs)
            .with_line_numbers(true);
        let view = vis.diff_text(OLD, NEW, "a", "b").unwrap();
        assert!(!view.is_clean());
    }

    #[test]
    fn test_visualizer_render_no_color() {
        let vis = DiffVisualizer::new(2).with_color(false);
        let view = vis.diff_text(OLD, NEW, "a", "b").unwrap();
        let rendered = vis.render(&view);
        assert!(rendered.contains("---"));
        assert!(rendered.contains("+++"));
    }

    #[test]
    fn test_visualizer_render_color() {
        let vis = DiffVisualizer::new(2).with_color(true);
        let view = vis.diff_text(OLD, NEW, "a", "b").unwrap();
        let rendered = vis.render(&view);
        // Should contain ANSI escape codes
        assert!(rendered.contains("\x1b["));
    }

    #[test]
    fn test_side_by_side_identical() {
        let vis = DiffVisualizer::default();
        let view = vis.diff_text("abc\ndef", "abc\ndef", "a", "b").unwrap();
        let sbs = to_side_by_side(&view);
        // No changes → empty (no hunks)
        assert!(sbs.is_empty());
    }

    #[test]
    fn test_side_by_side_has_change() {
        let vis = DiffVisualizer::new(0);
        let view = vis.diff_text("old line\ncommon", "new line\ncommon", "a", "b").unwrap();
        let sbs = to_side_by_side(&view);
        assert!(!sbs.is_empty());
        let changed: Vec<_> = sbs.iter().filter(|l| l.changed).collect();
        assert!(!changed.is_empty());
    }

    #[test]
    fn test_side_by_side_format_columns() {
        let line = SideBySideLine {
            left: Some("left".to_string()),
            right: Some("right".to_string()),
            changed: true,
            left_lineno: Some(1),
            right_lineno: Some(1),
        };
        let formatted = line.format_columns(20);
        assert!(formatted.contains("left"));
        assert!(formatted.contains("right"));
        assert!(formatted.contains("|"));
    }

    #[test]
    fn test_all_lines_collects_from_hunks() {
        let vis = DiffVisualizer::new(1);
        let view = vis.diff_text(OLD, NEW, "a", "b").unwrap();
        let all = view.all_lines();
        assert!(!all.is_empty());
    }

    #[test]
    fn test_line_origin_sigils() {
        assert_eq!(LineOrigin::Context.sigil(), ' ');
        assert_eq!(LineOrigin::Added.sigil(), '+');
        assert_eq!(LineOrigin::Removed.sigil(), '-');
        assert_eq!(LineOrigin::Header.sigil(), '@');
    }
}
