//! `c_diff_emit` — differential emission of decompiled C pseudocode.
//!
//! Given a previous version of a function's source and a new version, produces
//! a unified-diff patch that describes the changes. This is useful for:
//!
//! - Tracking how analysis improvements affect output.
//! - Reviewing the effect of user annotations.
//! - CI/CD diffing of decompiled output.
//!
//! The diff algorithm is a standard Myers-style LCS diff operating on lines.
//! Output format is compatible with standard unified-diff (patch(1)).

use serde::{Deserialize, Serialize};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// DiffOp
// ─────────────────────────────────────────────────────────────────────────────

/// A single operation in an edit script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffOp {
    /// Line present only in the old source (removed).
    Remove(String),
    /// Line present only in the new source (added).
    Add(String),
    /// Line present in both (context).
    Equal(String),
}

impl DiffOp {
    /// Return `true` if this is a Remove or Add.
    #[must_use]
    pub const fn is_change(&self) -> bool {
        matches!(self, Self::Remove(_) | Self::Add(_))
    }

    #[must_use]
    pub const fn text(&self) -> &str {
        match self {
            Self::Remove(s) | Self::Add(s) | Self::Equal(s) => s.as_str(),
        }
    }

    /// Character prefix for unified diff.
    #[must_use]
    pub const fn prefix(&self) -> char {
        match self {
            Self::Remove(_) => '-',
            Self::Add(_) => '+',
            Self::Equal(_) => ' ',
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffHunk
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous group of changes with surrounding context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    /// Old-source starting line (1-based).
    pub old_start: usize,
    /// Old-source line count for this hunk.
    pub old_count: usize,
    /// New-source starting line (1-based).
    pub new_start: usize,
    /// New-source line count for this hunk.
    pub new_count: usize,
    /// Operations in this hunk.
    pub ops: Vec<DiffOp>,
    /// Optional hunk header context string (e.g. function name).
    pub context: Option<String>,
}

impl DiffHunk {
    /// Render the hunk header line: `@@ -old_start,old_count +new_start,new_count @@`
    #[must_use]
    pub fn header(&self) -> String {
        let ctx = self
            .context
            .as_ref()
            .map(|c| format!(" {c}"))
            .unwrap_or_default();
        format!(
            "@@ -{},{} +{},{} @@{}",
            self.old_start, self.old_count, self.new_start, self.new_count, ctx
        )
    }

    /// Number of added lines in this hunk.
    #[must_use]
    pub fn add_count(&self) -> usize {
        self.ops.iter().filter(|o| matches!(o, DiffOp::Add(_))).count()
    }

    /// Number of removed lines in this hunk.
    #[must_use]
    pub fn remove_count(&self) -> usize {
        self.ops.iter().filter(|o| matches!(o, DiffOp::Remove(_))).count()
    }

    /// True if the hunk contains any actual changes.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.ops.iter().any(DiffOp::is_change)
    }
}

impl fmt::Display for DiffHunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.header())?;
        for op in &self.ops {
            writeln!(f, "{}{}", op.prefix(), op.text())?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UnifiedDiff
// ─────────────────────────────────────────────────────────────────────────────

/// A complete unified diff between two sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedDiff {
    /// Label for the old file (e.g. `a/function_name`).
    pub old_label: String,
    /// Label for the new file (e.g. `b/function_name`).
    pub new_label: String,
    /// All hunks in this diff.
    pub hunks: Vec<DiffHunk>,
}

impl UnifiedDiff {
    /// True if there are no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hunks.iter().all(|h| !h.has_changes())
    }

    /// Total added lines across all hunks.
    #[must_use]
    pub fn total_added(&self) -> usize {
        self.hunks.iter().map(DiffHunk::add_count).sum()
    }

    /// Total removed lines across all hunks.
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.hunks.iter().map(DiffHunk::remove_count).sum()
    }

    /// Net change in lines.
    #[must_use]
    pub fn net_change(&self) -> i64 {
        i64::try_from(self.total_added()).unwrap_or(i64::MAX) - i64::try_from(self.total_removed()).unwrap_or(i64::MAX)
    }
}

impl fmt::Display for UnifiedDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return Ok(());
        }
        writeln!(f, "--- {}", self.old_label)?;
        writeln!(f, "+++ {}", self.new_label)?;
        for hunk in &self.hunks {
            write!(f, "{hunk}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the diff algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffConfig {
    /// Number of context lines to include around each change (default 3).
    pub context_lines: usize,
    /// If true, ignore leading/trailing whitespace when comparing lines.
    pub ignore_whitespace: bool,
    /// If true, ignore blank lines entirely.
    pub ignore_blank_lines: bool,
    /// If true, ignore lines that consist only of comments.
    pub ignore_comment_lines: bool,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            context_lines: 3,
            ignore_whitespace: false,
            ignore_blank_lines: false,
            ignore_comment_lines: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Myers diff — LCS-based edit script
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the edit script between two slices of strings using Myers' algorithm.
/// Returns a list of [`DiffOp`]s covering the entire input.
fn myers_diff<'a>(old: &'a [&str], new: &'a [&str]) -> Vec<DiffOp> {
    let n = old.len();
    let m = new.len();

    // Fast paths.
    if n == 0 && m == 0 {
        return Vec::new();
    }
    if n == 0 {
        return new.iter().map(|l| DiffOp::Add(l.to_string())).collect();
    }
    if m == 0 {
        return old.iter().map(|l| DiffOp::Remove(l.to_string())).collect();
    }

    // Build LCS table.
    let lcs = compute_lcs(old, new);

    // Reconstruct edit script from LCS table.
    let mut ops = Vec::new();
    let mut i = n;
    let mut j = m;

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            ops.push(DiffOp::Equal(old[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || lcs[i][j - 1] >= lcs[i - 1][j]) {
            ops.push(DiffOp::Add(new[j - 1].to_string()));
            j -= 1;
        } else {
            ops.push(DiffOp::Remove(old[i - 1].to_string()));
            i -= 1;
        }
    }

    ops.reverse();
    ops
}

/// Compute LCS lengths table. Returns `lcs[i][j]` = LCS length for
/// `old[..i]` and `new[..j]`.
fn compute_lcs(old: &[&str], new: &[&str]) -> Vec<Vec<usize>> {
    let n = old.len();
    let m = new.len();
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = if old[i - 1] == new[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    dp
}

// ─────────────────────────────────────────────────────────────────────────────
// Hunk builder
// ─────────────────────────────────────────────────────────────────────────────

/// Build unified-diff hunks from a flat list of `DiffOp`s.
fn build_hunks(ops: &[DiffOp], context: usize) -> Vec<DiffHunk> {
    if ops.is_empty() {
        return Vec::new();
    }

    // Find change positions.
    let change_positions: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| op.is_change())
        .map(|(i, _)| i)
        .collect();

    if change_positions.is_empty() {
        return Vec::new();
    }

    // Group change positions into ranges with context.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut range_start = change_positions[0].saturating_sub(context);
    let mut range_end = (change_positions[0] + context).min(ops.len() - 1);

    for &pos in &change_positions[1..] {
        let new_start = pos.saturating_sub(context);
        let new_end = (pos + context).min(ops.len() - 1);
        if new_start <= range_end + 1 {
            // Merge with current range.
            range_end = range_end.max(new_end);
        } else {
            ranges.push((range_start, range_end));
            range_start = new_start;
            range_end = new_end;
        }
    }
    ranges.push((range_start, range_end));

    // Build hunks.
    let mut hunks = Vec::new();
    for (start, end) in ranges {
        let hunk_ops: Vec<DiffOp> = ops[start..=end].to_vec();

        // Count old and new line offsets.
        let mut old_start = 1usize;
        let mut new_start = 1usize;
        for op in &ops[..start] {
            match op {
                DiffOp::Remove(_) | DiffOp::Equal(_) => old_start += 1,
                DiffOp::Add(_) => {}
            }
            match op {
                DiffOp::Add(_) | DiffOp::Equal(_) => new_start += 1,
                DiffOp::Remove(_) => {}
            }
        }

        let old_count = hunk_ops.iter().filter(|o| !matches!(o, DiffOp::Add(_))).count();
        let new_count = hunk_ops.iter().filter(|o| !matches!(o, DiffOp::Remove(_))).count();

        hunks.push(DiffHunk {
            old_start,
            old_count,
            new_start,
            new_count,
            ops: hunk_ops,
            context: None,
        });
    }

    hunks
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffEmitter
// ─────────────────────────────────────────────────────────────────────────────

/// Generates unified diffs between versions of decompiled C source.
#[derive(Default)]
pub struct DiffEmitter {
    pub config: DiffConfig,
}


impl DiffEmitter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: DiffConfig) -> Self {
        Self { config }
    }

    /// Compute and return a [`UnifiedDiff`] between `old_src` and `new_src`.
    pub fn diff(
        &self,
        old_src: &str,
        new_src: &str,
        old_label: &str,
        new_label: &str,
    ) -> UnifiedDiff {
        let old_lines: Vec<&str> = old_src.lines().collect();
        let new_lines: Vec<&str> = new_src.lines().collect();

        // We do filtering on owned strings, then compare.
        let old_filtered: Vec<String> = old_lines
            .iter()
            .filter(|l| self.should_include(l))
            .map(|l| self.normalize_line(l))
            .collect();
        let new_filtered: Vec<String> = new_lines
            .iter()
            .filter(|l| self.should_include(l))
            .map(|l| self.normalize_line(l))
            .collect();

        let old_refs: Vec<&str> = old_filtered.iter().map(std::string::String::as_str).collect();
        let new_refs: Vec<&str> = new_filtered.iter().map(std::string::String::as_str).collect();

        let ops = myers_diff(&old_refs, &new_refs);
        let hunks = build_hunks(&ops, self.config.context_lines);

        UnifiedDiff {
            old_label: old_label.to_string(),
            new_label: new_label.to_string(),
            hunks,
        }
    }

    fn should_include(&self, line: &str) -> bool {
        if self.config.ignore_blank_lines && line.trim().is_empty() {
            return false;
        }
        if self.config.ignore_comment_lines {
            let t = line.trim();
            if t.starts_with("//") || (t.starts_with("/*") && t.ends_with("*/")) {
                return false;
            }
        }
        true
    }

    fn normalize_line(&self, line: &str) -> String {
        if self.config.ignore_whitespace {
            // Collapse all whitespace runs to nothing — treat lines as
            // equivalent if they differ only in whitespace.
            line.chars().filter(|c| !c.is_whitespace()).collect()
        } else {
            line.to_string()
        }
    }

    /// Compute a diff and return it formatted as a unified-diff string.
    #[must_use]
    pub fn diff_string(
        &self,
        old_src: &str,
        new_src: &str,
        old_label: &str,
        new_label: &str,
    ) -> String {
        let d = self.diff(old_src, new_src, old_label, new_label);
        d.to_string()
    }

    /// Return statistics about the diff.
    #[must_use]
    pub fn diff_stats(&self, old_src: &str, new_src: &str) -> DiffStats {
        let d = self.diff(old_src, new_src, "old", "new");
        DiffStats {
            hunks: d.hunks.len(),
            added_lines: d.total_added(),
            removed_lines: d.total_removed(),
            net_change: d.net_change(),
            changed: !d.is_empty(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics for a diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffStats {
    pub hunks: usize,
    pub added_lines: usize,
    pub removed_lines: usize,
    pub net_change: i64,
    pub changed: bool,
}

impl fmt::Display for DiffStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} hunks, +{} -{} lines (net {})",
            self.hunks, self.added_lines, self.removed_lines, self.net_change
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDiff — semantic diff of two function versions
// ─────────────────────────────────────────────────────────────────────────────

/// A higher-level diff that carries the function name alongside the raw diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDiff {
    pub function_name: String,
    pub diff: UnifiedDiff,
    pub old_line_count: usize,
    pub new_line_count: usize,
}

impl FunctionDiff {
    /// Create a function diff from two source strings.
    #[must_use]
    pub fn compute(
        func_name: &str,
        old_src: &str,
        new_src: &str,
        config: DiffConfig,
    ) -> Self {
        let emitter = DiffEmitter::with_config(config);
        let old_label = format!("a/{func_name}");
        let new_label = format!("b/{func_name}");
        let diff = emitter.diff(old_src, new_src, &old_label, &new_label);
        Self {
            function_name: func_name.to_string(),
            diff,
            old_line_count: old_src.lines().count(),
            new_line_count: new_src.lines().count(),
        }
    }

    /// Format a summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: {} hunks, +{} -{} ({}→{} lines)",
            self.function_name,
            self.diff.hunks.len(),
            self.diff.total_added(),
            self.diff.total_removed(),
            self.old_line_count,
            self.new_line_count,
        )
    }

    /// True if the function's source did not change.
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.diff.is_empty()
    }
}

impl fmt::Display for FunctionDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.diff)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchDiff — diff of a whole module/binary
// ─────────────────────────────────────────────────────────────────────────────

/// Holds diffs for multiple functions, as produced by a full-binary re-analysis.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BatchDiff {
    pub function_diffs: Vec<FunctionDiff>,
}

impl BatchDiff {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, fd: FunctionDiff) {
        self.function_diffs.push(fd);
    }

    /// Functions that changed.
    #[must_use]
    pub fn changed_functions(&self) -> Vec<&FunctionDiff> {
        self.function_diffs.iter().filter(|fd| !fd.is_unchanged()).collect()
    }

    /// Functions that are new (had no old version).
    #[must_use]
    pub fn only_added(&self) -> Vec<&FunctionDiff> {
        self.function_diffs
            .iter()
            .filter(|fd| fd.old_line_count == 0 && fd.new_line_count > 0)
            .collect()
    }

    /// Functions that were removed.
    #[must_use]
    pub fn only_removed(&self) -> Vec<&FunctionDiff> {
        self.function_diffs
            .iter()
            .filter(|fd| fd.old_line_count > 0 && fd.new_line_count == 0)
            .collect()
    }

    /// Total lines added across all functions.
    #[must_use]
    pub fn total_added(&self) -> usize {
        self.function_diffs.iter().map(|fd| fd.diff.total_added()).sum()
    }

    /// Total lines removed across all functions.
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.function_diffs.iter().map(|fd| fd.diff.total_removed()).sum()
    }

    /// Format a batch summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let changed = self.changed_functions().len();
        let total = self.function_diffs.len();
        format!(
            "{}/{} functions changed, +{} -{} lines total",
            changed,
            total,
            self.total_added(),
            self.total_removed()
        )
    }
}

impl fmt::Display for BatchDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for fd in &self.function_diffs {
            if !fd.is_unchanged() {
                write!(f, "{fd}")?;
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchApplier — apply a unified diff to source text
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a [`UnifiedDiff`] to a source string, producing the new version.
///
/// This is a best-effort applier: it processes hunks in order and patches
/// the source. Rejects non-matching hunks gracefully.
pub struct PatchApplier;

impl PatchApplier {
    /// Apply `diff` to `source` and return the patched string.
    ///
    /// # Errors
    /// Returns `Err` with a description if the patch cannot be applied cleanly.
    pub fn apply(source: &str, diff: &UnifiedDiff) -> Result<String, String> {
        let mut lines: Vec<String> = source.lines().map(std::string::ToString::to_string).collect();

        for hunk in &diff.hunks {
            lines = Self::apply_hunk(lines, hunk)?;
        }

        Ok(lines.join("\n"))
    }

    fn apply_hunk(
        mut lines: Vec<String>,
        hunk: &DiffHunk,
    ) -> Result<Vec<String>, String> {
        // Find the context in `lines` starting near hunk.old_start.
        // Extract context lines from hunk.
        let context_lines: Vec<&str> = hunk
            .ops
            .iter()
            .filter(|o| matches!(o, DiffOp::Equal(_) | DiffOp::Remove(_)))
            .map(DiffOp::text)
            .collect();

        if context_lines.is_empty() {
            // Pure insertion.
            let pos = (hunk.old_start - 1).min(lines.len());
            let new_lines: Vec<String> = hunk
                .ops
                .iter()
                .filter(|o| matches!(o, DiffOp::Add(_)))
                .map(|o| o.text().to_string())
                .collect();
            for (idx, line) in new_lines.into_iter().enumerate() {
                lines.insert(pos + idx, line);
            }
            return Ok(lines);
        }

        // Find the best matching position.
        let search_start = hunk.old_start.saturating_sub(1);
        let search_end = (hunk.old_start + hunk.old_count + 10).min(lines.len());
        let mut match_pos = None;

        'outer: for pos in search_start..=search_end.saturating_sub(context_lines.len()) {
            for (j, &ctx) in context_lines.iter().enumerate() {
                if pos + j >= lines.len() || lines[pos + j].trim() != ctx.trim() {
                    continue 'outer;
                }
            }
            match_pos = Some(pos);
            break;
        }

        let Some(pos) = match_pos else {
                return Err(format!(
                    "Could not find context for hunk at old line {}",
                    hunk.old_start
                ));
            };

        // Apply the hunk at `pos`.
        let mut new_lines: Vec<String> = lines[..pos].to_vec();
        let mut old_idx = pos;

        for op in &hunk.ops {
            match op {
                DiffOp::Equal(s) => {
                    new_lines.push(s.clone());
                    old_idx += 1;
                }
                DiffOp::Remove(_) => {
                    old_idx += 1;
                }
                DiffOp::Add(s) => {
                    new_lines.push(s.clone());
                }
            }
        }

        // Append remainder.
        if old_idx < lines.len() {
            new_lines.extend_from_slice(&lines[old_idx..]);
        }

        Ok(new_lines)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn emitter() -> DiffEmitter {
        DiffEmitter::new()
    }

    #[test]
    fn test_identical_sources_no_diff() {
        let src = "int foo() {\n    return 0;\n}\n";
        let d = emitter().diff(src, src, "a/foo", "b/foo");
        assert!(d.is_empty());
        assert_eq!(d.total_added(), 0);
        assert_eq!(d.total_removed(), 0);
    }

    #[test]
    fn test_add_line() {
        let old = "int foo() {\n    return 0;\n}\n";
        let new = "int foo() {\n    x = 1;\n    return 0;\n}\n";
        let d = emitter().diff(old, new, "a/foo", "b/foo");
        assert!(!d.is_empty());
        assert!(d.total_added() >= 1);
    }

    #[test]
    fn test_remove_line() {
        let old = "int foo() {\n    x = 1;\n    return 0;\n}\n";
        let new = "int foo() {\n    return 0;\n}\n";
        let d = emitter().diff(old, new, "a/foo", "b/foo");
        assert!(!d.is_empty());
        assert!(d.total_removed() >= 1);
    }

    #[test]
    fn test_diff_to_string_contains_markers() {
        let old = "a\nb\nc\n";
        let new = "a\nx\nc\n";
        let s = emitter().diff_string(old, new, "old", "new");
        assert!(s.contains("---"));
        assert!(s.contains("+++"));
        assert!(s.contains("@@"));
        assert!(s.contains("-b") || s.contains("+x"));
    }

    #[test]
    fn test_diff_stats() {
        let old = "line1\nline2\nline3\n";
        let new = "line1\nnewline\nline3\n";
        let stats = emitter().diff_stats(old, new);
        assert!(stats.changed);
        assert_eq!(stats.added_lines, 1);
        assert_eq!(stats.removed_lines, 1);
        assert_eq!(stats.net_change, 0);
    }

    #[test]
    fn test_function_diff_summary() {
        let old = "void foo() { return; }\n";
        let new = "void foo() { x = 1; return; }\n";
        let fd = FunctionDiff::compute("foo", old, new, DiffConfig::default());
        let summary = fd.summary();
        assert!(summary.contains("foo"));
    }

    #[test]
    fn test_batch_diff() {
        let mut bd = BatchDiff::new();
        let fd = FunctionDiff::compute("main", "a\nb\n", "a\nc\n", DiffConfig::default());
        bd.add(fd);
        assert_eq!(bd.changed_functions().len(), 1);
        assert!(bd.total_added() > 0);
    }

    #[test]
    fn test_hunk_header_format() {
        let h = DiffHunk {
            old_start: 10,
            old_count: 5,
            new_start: 10,
            new_count: 6,
            ops: vec![],
            context: Some("foo".to_string()),
        };
        let header = h.header();
        assert!(header.contains("-10,5"));
        assert!(header.contains("+10,6"));
        assert!(header.contains("foo"));
    }

    #[test]
    fn test_ignore_whitespace_option() {
        let old = "int x = 1 ;";
        let new = "int x = 1;";
        let config = DiffConfig {
            ignore_whitespace: true,
            ..DiffConfig::default()
        };
        let emitter = DiffEmitter::with_config(config);
        let d = emitter.diff(old, new, "a", "b");
        assert!(d.is_empty());
    }

    #[test]
    fn test_patch_applier_add_line() {
        let source = "line1\nline2\nline3";
        let diff = DiffEmitter::new().diff(source, "line1\nINSERTED\nline2\nline3", "a", "b");
        let patched = PatchApplier::apply(source, &diff).unwrap();
        assert!(patched.contains("INSERTED"), "patched: {patched}");
    }

    #[test]
    fn test_myers_diff_empty() {
        let ops = myers_diff(&[], &[]);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_myers_diff_add_all() {
        let new = vec!["a", "b", "c"];
        let ops = myers_diff(&[], &new);
        assert!(ops.iter().all(|o| matches!(o, DiffOp::Add(_))));
    }

    #[test]
    fn test_myers_diff_remove_all() {
        let old = vec!["a", "b", "c"];
        let ops = myers_diff(&old, &[]);
        assert!(ops.iter().all(|o| matches!(o, DiffOp::Remove(_))));
    }
}
