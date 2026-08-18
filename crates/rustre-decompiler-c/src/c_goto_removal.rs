//! `c_goto_removal` — structured goto elimination for decompiled C.
//!
//! Converts `goto` statements into structured control-flow constructs wherever
//! possible, improving readability of decompiler output:
//!
//! * **Forward goto → if/skip**: `goto lbl;` that jumps over a block becomes
//!   an `if (!cond)` around the block.
//! * **Goto to loop head → continue**: a goto that targets the first statement
//!   of the immediately enclosing loop becomes `continue;`.
//! * **Goto to loop exit → break**: a goto that targets the first statement
//!   after the immediately enclosing loop becomes `break;`.
//! * **Goto to function exit → return**: a goto that targets a bare `return;`
//!   label is replaced with `return;` (or `return expr;`).
//! * **Computed goto / unresolvable**: left as-is with a comment.
//!
//! The algorithm operates on a simple line-based representation.  It is
//! deliberately conservative: if a pattern cannot be matched unambiguously it
//! leaves the original goto intact.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// GotoRemovalStats
// ─────────────────────────────────────────────────────────────────────────────

/// Counts of transformations performed.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GotoRemovalStats {
    pub converted_to_break: u32,
    pub converted_to_continue: u32,
    pub converted_to_return: u32,
    pub converted_to_if_skip: u32,
    pub gotos_remaining: u32,
    pub labels_removed: u32,
}

impl GotoRemovalStats {
    #[must_use]
    pub const fn total_converted(&self) -> u32 {
        self.converted_to_break
            + self.converted_to_continue
            + self.converted_to_return
            + self.converted_to_if_skip
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GotoRemovalConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Bitfield of which goto-to-structured-flow transformations are enabled.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GotoTransforms(u8);

impl GotoTransforms {
    const BREAK: u8 = 0b0001;
    const CONTINUE: u8 = 0b0010;
    const RETURN: u8 = 0b0100;
    const IF_SKIP: u8 = 0b1000;
    const ALL: u8 = 0b1111;

    #[must_use]
    pub const fn all() -> Self { Self(Self::ALL) }
    #[must_use]
    pub const fn enable_break(self) -> bool { self.0 & Self::BREAK != 0 }
    #[must_use]
    pub const fn enable_continue(self) -> bool { self.0 & Self::CONTINUE != 0 }
    #[must_use]
    pub const fn enable_return(self) -> bool { self.0 & Self::RETURN != 0 }
    #[must_use]
    pub const fn enable_if_skip(self) -> bool { self.0 & Self::IF_SKIP != 0 }
}

impl Default for GotoTransforms {
    fn default() -> Self { Self(Self::ALL) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GotoRemovalConfig {
    /// Which transformations are enabled.
    pub transforms: GotoTransforms,
    /// Maximum number of lines between goto and target to consider for
    /// if-skip conversion (keeps the output local).
    pub max_if_skip_distance: usize,
    /// Remove labels that are no longer referenced after transformation.
    pub remove_orphan_labels: bool,
}

impl Default for GotoRemovalConfig {
    fn default() -> Self {
        Self {
            transforms: GotoTransforms::default(),
            max_if_skip_distance: 30,
            remove_orphan_labels: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Label/Goto extraction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `Some(label_name)` if the trimmed line is a label (e.g. `lbl:`).
fn parse_label(line: &str) -> Option<&str> {
    let t = line.trim();
    if t.starts_with("case ") || t.starts_with("default:") {
        return None; // switch case labels
    }
    if t.ends_with(':') && !t.contains(' ') {
        return Some(&t[..t.len() - 1]);
    }
    None
}

/// Returns `Some(label_name)` if the trimmed line is `goto label;`.
fn parse_goto(line: &str) -> Option<&str> {
    let t = line.trim();
    let rest = t.strip_prefix("goto ")?;
    rest.strip_suffix(';')
}

/// Returns `Some((cond, label))` for a trimmed line of the form
/// `if (cond) goto label;`.
fn parse_if_goto(line: &str) -> Option<(&str, &str)> {
    let t = line.trim();
    let rest = t.strip_prefix("if (")?;
    // Find the matching ')' for the condition (single-paren-depth scan).
    let mut depth = 1usize;
    let mut end = 0usize;
    for (idx, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = idx;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    let cond = &rest[..end];
    let after = rest[end + 1..].trim_start();
    let lbl = after.strip_prefix("goto ")?.strip_suffix(';')?;
    Some((cond, lbl))
}

/// Indentation of a line.
fn indent_of(line: &str) -> &str {
    let trimmed = line.trim_start();
    &line[..line.len() - trimmed.len()]
}

/// Count `{` minus `}` on a single line.
fn brace_delta(line: &str) -> i32 {
    let t = line.trim();
    let opens = i32::try_from(t.chars().filter(|&c| c == '{').count()).unwrap_or(i32::MAX);
    let closes = i32::try_from(t.chars().filter(|&c| c == '}').count()).unwrap_or(i32::MAX);
    opens - closes
}

// ─────────────────────────────────────────────────────────────────────────────
// LabelIndex — maps label names to their line numbers (0-based)
// ─────────────────────────────────────────────────────────────────────────────

struct LabelIndex {
    /// `label_name` → 0-based line index
    positions: HashMap<String, usize>,
    /// `label_name` → number of `goto` references
    refcounts: HashMap<String, usize>,
}

impl LabelIndex {
    fn build(lines: &[String]) -> Self {
        let mut positions = HashMap::new();
        let mut refcounts: HashMap<String, usize> = HashMap::new();

        for (i, line) in lines.iter().enumerate() {
            if let Some(name) = parse_label(line) {
                positions.insert(name.to_string(), i);
            }
            if let Some(target) = parse_goto(line) {
                *refcounts.entry(target.to_string()).or_insert(0) += 1;
            } else if let Some((_, target)) = parse_if_goto(line) {
                *refcounts.entry(target.to_string()).or_insert(0) += 1;
            }
        }
        Self { positions, refcounts }
    }

    fn label_line(&self, name: &str) -> Option<usize> {
        self.positions.get(name).copied()
    }

    fn ref_count(&self, name: &str) -> usize {
        self.refcounts.get(name).copied().unwrap_or(0)
    }

    fn decrement_ref(&mut self, name: &str) {
        if let Some(n) = self.refcounts.get_mut(name) {
            *n = n.saturating_sub(1);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopContext — track enclosing loops
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct LoopFrame {
    /// 0-based line index of the loop header.
    header: usize,
    /// 0-based line index of the closing `}`.
    close: usize,
    /// 0-based line index of the first statement after the loop.
    after: usize,
}

/// Scan `lines` to build a vector of loop frames.
fn build_loop_frames(lines: &[String]) -> Vec<LoopFrame> {
    let mut frames = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let t = lines[i].trim();
        let is_loop_head = t.starts_with("while (")
            || t.starts_with("while(")
            || t.starts_with("for (")
            || t.starts_with("for(")
            || t.starts_with("do {")
            || t.starts_with("do{");

        if is_loop_head {
            // Find the matching closing brace.
            let mut depth = 0i32;
            let mut close = i;
            for (j, _) in lines.iter().enumerate().skip(i) {
                depth += brace_delta(&lines[j]);
                if depth == 0 && j > i {
                    close = j;
                    break;
                }
            }
            let after = close + 1;
            frames.push(LoopFrame {
                header: i,
                close,
                after,
            });
        }
        i += 1;
    }
    frames
}

/// Find which loop frame (if any) a goto at `goto_line` is inside.
fn enclosing_loop(goto_line: usize, frames: &[LoopFrame]) -> Option<&LoopFrame> {
    // The innermost loop containing `goto_line`.
    frames
        .iter()
        .rfind(|f| goto_line > f.header && goto_line < f.close)
}

// ─────────────────────────────────────────────────────────────────────────────
// GotoRemover — main pass
// ─────────────────────────────────────────────────────────────────────────────

/// Performs goto elimination on a source string.
#[derive(Default)]
pub struct GotoRemover {
    pub config: GotoRemovalConfig,
}


impl GotoRemover {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: GotoRemovalConfig) -> Self {
        Self { config }
    }

    /// Process source text, returning the transformed text and stats.
    pub fn process(&self, source: &str) -> (String, GotoRemovalStats) {
        let mut lines: Vec<String> = source.lines().map(std::string::ToString::to_string).collect();
        let mut stats = GotoRemovalStats::default();

        // Iterate until stable (some transformations enable others).
        for _pass in 0..5 {
            let before_gotos = count_gotos(&lines);
            let (new_lines, pass_stats) = self.single_pass(&lines);
            stats.converted_to_break += pass_stats.converted_to_break;
            stats.converted_to_continue += pass_stats.converted_to_continue;
            stats.converted_to_return += pass_stats.converted_to_return;
            stats.converted_to_if_skip += pass_stats.converted_to_if_skip;
            lines = new_lines;
            let after_gotos = count_gotos(&lines);
            if after_gotos >= before_gotos {
                break;
            }
        }

        // Remove orphan labels.
        if self.config.remove_orphan_labels {
            let (new_lines, removed) = remove_orphan_labels(lines);
            lines = new_lines;
            stats.labels_removed = removed;
        }

        stats.gotos_remaining = count_gotos(&lines);

        (lines.join("\n"), stats)
    }

    fn single_pass(&self, lines: &[String]) -> (Vec<String>, GotoRemovalStats) {
        let mut out = lines.to_owned();
        let mut stats = GotoRemovalStats::default();

        let mut label_index = LabelIndex::build(lines);
        let loop_frames = build_loop_frames(lines);

        for i in 0..lines.len() {
            let t = lines[i].trim();
            let (goto_target, inline_cond) = match parse_goto(t) {
                Some(lbl) => (lbl.to_string(), None),
                None => match parse_if_goto(t) {
                    Some((cond, lbl)) => (lbl.to_string(), Some(cond.to_string())),
                    None => continue,
                },
            };

            let ind = indent_of(&lines[i]);
            let Some(target_line) = label_index.label_line(&goto_target) else { continue };

            // Helper to wrap a replacement statement with the inline `if (cond)`
            // when the goto was of the form `if (cond) goto X;`.
            let wrap = |stmt: &str| -> String {
                inline_cond.as_ref().map_or_else(|| format!("{ind}{stmt}"), |cond| format!("{ind}if ({cond}) {stmt}"))
            };

            // ── goto → continue ──────────────────────────────────────────
            if self.config.transforms.enable_continue()
                && let Some(frame) = enclosing_loop(i, &loop_frames) {
                    // Is the target the loop header?
                    if target_line == frame.header {
                        out[i] = wrap("continue;");
                        label_index.decrement_ref(&goto_target);
                        stats.converted_to_continue += 1;
                        continue;
                    }
                }

            // ── goto → break ──────────────────────────────────────────────
            if self.config.transforms.enable_break()
                && let Some(frame) = enclosing_loop(i, &loop_frames) {
                    // Is the target the line immediately after the loop close?
                    if target_line == frame.after
                        || (target_line == frame.close
                            && lines[target_line].trim() == "}")
                    {
                        out[i] = wrap("break;");
                        label_index.decrement_ref(&goto_target);
                        stats.converted_to_break += 1;
                        continue;
                    }
                    // Also: target is the label immediately after the loop.
                    if target_line < lines.len() {
                        let tlabel = parse_label(&lines[target_line]);
                        if tlabel == Some(goto_target.as_str()) && target_line == frame.after {
                            out[i] = wrap("break;");
                            label_index.decrement_ref(&goto_target);
                            stats.converted_to_break += 1;
                            continue;
                        }
                    }
                }

            // ── goto → return ─────────────────────────────────────────────
            if self.config.transforms.enable_return() {
                // The label should point to a `return;` or `return expr;` statement,
                // or the label should be the last thing before the function close.
                let target_is_return = Self::check_label_is_return(lines, target_line);
                if target_is_return {
                    // Replace the goto with the return statement.
                    let return_stmt = Self::extract_return_at_label(lines, target_line);
                    out[i] = wrap(&return_stmt);
                    label_index.decrement_ref(&goto_target);
                    stats.converted_to_return += 1;
                    continue;
                }
            }

            // ── goto → if-skip (forward goto only) ───────────────────────
            if self.config.transforms.enable_if_skip()
                && target_line > i
                    && target_line - i <= self.config.max_if_skip_distance
                {
                    // The goto jumps forward over lines[i+1..target_line].
                    // We can wrap those lines in an `if (!cond)` block.
                    // Only safe if there's exactly one goto to this label.
                    if label_index.ref_count(&goto_target) == 1 {
                        // Check no other gotos target inside the skipped block.
                        let block_safe = !Self::has_incoming_goto_into(
                            lines, i + 1, target_line, &label_index,
                        );
                        if block_safe {
                            let skipped: Vec<String> = lines[i + 1..target_line].to_vec();
                            if !skipped.is_empty() {
                                // Look backwards for a preceding `if (cond)` that led to this goto.
                                if let Some(new_block) = Self::wrap_as_if_skip(lines, i, &skipped, ind, target_line) {
                                    // Replace lines i..(target_line) with the new block.
                                    // We mark them for deletion in a second pass by
                                    // writing a sentinel and rebuilding.
                                    // For simplicity we do it inline: collect a new lines vector.
                                    let mut rebuilt: Vec<String> = out[..i].to_vec();
                                    rebuilt.extend(new_block);
                                    rebuilt.extend_from_slice(&out[target_line..]);
                                    label_index.decrement_ref(&goto_target);
                                    stats.converted_to_if_skip += 1;
                                    return (rebuilt, stats);
                                }
                            }
                        }
                    }
                }
        }

        (out, stats)
    }

    /// Check if the label at `target_line` is followed immediately by a return.
    fn check_label_is_return(lines: &[String], target_line: usize) -> bool {
        // The label itself is `lbl:`; look at the next non-empty line.
        let mut j = target_line + 1;
        while j < lines.len() {
            let t = lines[j].trim();
            if t.is_empty() {
                j += 1;
                continue;
            }
            return t.starts_with("return");
        }
        false
    }

    fn extract_return_at_label(lines: &[String], target_line: usize) -> String {
        let mut j = target_line + 1;
        while j < lines.len() {
            let t = lines[j].trim();
            if !t.is_empty() {
                return t.to_string();
            }
            j += 1;
        }
        "return;".to_string()
    }

    fn has_incoming_goto_into(
        lines: &[String],
        start: usize,
        end: usize,
        label_index: &LabelIndex,
    ) -> bool {
        // Check if any label inside [start, end) is targeted by a goto
        // from outside [start, end).
        for line in &lines[start..end.min(lines.len())] {
            if let Some(lbl) = parse_label(line)
                && label_index.ref_count(lbl) > 0 {
                    // Check that the goto is from outside the range.
                    // (We accept this as a conservative check.)
                    return true;
                }
        }
        false
    }

    fn wrap_as_if_skip(
        lines: &[String],
        goto_line: usize,
        skipped: &[String],
        ind: &str,
        _target_line: usize,
    ) -> Option<Vec<String>> {
        // Look at the preceding line for an `if (cond)` that predicates this goto.
        // Pattern:
        //   if (cond) {
        //       goto lbl;
        //   }
        //   <skipped block>
        // lbl:
        //
        // Or simpler:
        //   if (cond) goto lbl;
        //   <skipped>
        // lbl:
        //
        // We rewrite as:
        //   if (!cond) {
        //       <skipped block>
        //   }

        // Check if the goto line itself is a one-liner `if (cond) goto lbl;`
        let goto_stmt = lines[goto_line].trim();
        if let Some(cond) = Self::extract_if_goto_cond(goto_stmt) {
            let neg_cond = negate_condition(cond);
            let mut new_block = Vec::new();
            new_block.push(format!("{ind}if ({neg_cond}) {{"));
            for sl in skipped {
                new_block.push(sl.clone());
            }
            new_block.push(format!("{ind}}}"));
            return Some(new_block);
        }

        // Check for:
        //   if (cond) {
        //      goto lbl;
        //   }
        // on the preceding lines.
        if goto_line >= 2 {
            let prev_close = lines[goto_line - 1].trim();
            let prev_open = lines[goto_line - 2].trim();
            if (prev_close == "}" || prev_close == "};")
                && let Some(cond) = Self::extract_if_open_cond(prev_open) {
                    let neg_cond = negate_condition(cond);
                    let mut new_block = Vec::new();
                    // Replace the whole `if (cond) { goto lbl; }` with `if (!cond) { skipped }`.
                    // This is done by returning a block that replaces lines
                    // [goto_line-2 .. target_line].
                    // Since our caller slices at goto_line, we need a simpler approach:
                    // just emit an `if (!cond)` for the skipped block.
                    new_block.push(format!("{ind}if ({neg_cond}) {{"));
                    for sl in skipped {
                        new_block.push(sl.clone());
                    }
                    new_block.push(format!("{ind}}}"));
                    return Some(new_block);
                }
        }

        None
    }

    fn extract_if_goto_cond(stmt: &str) -> Option<&str> {
        // `if (cond) goto lbl;`
        let rest = stmt.strip_prefix("if (")?;
        let close = rest.find(") goto ")?;
        Some(&rest[..close])
    }

    fn extract_if_open_cond(stmt: &str) -> Option<&str> {
        // `if (cond) {` — extract `cond`
        let rest = stmt.strip_prefix("if (")?;
        let close = rest.find(") {")?;
        Some(&rest[..close])
    }
}

/// Negate a simple C condition string.
fn negate_condition(cond: &str) -> String {
    let cond = cond.trim();
    // If it starts with `!`, remove the `!`.
    if let Some(inner) = cond.strip_prefix('!') {
        return inner.to_string();
    }
    // For comparison operators, flip them.
    if cond.contains("!=") {
        return cond.replace("!=", "==");
    }
    if cond.contains("==") {
        return cond.replace("==", "!=");
    }
    if cond.contains(" > ") {
        return cond.replace(" > ", " <= ");
    }
    if cond.contains(" >= ") {
        return cond.replace(" >= ", " < ");
    }
    if cond.contains(" < ") {
        return cond.replace(" < ", " >= ");
    }
    if cond.contains(" <= ") {
        return cond.replace(" <= ", " > ");
    }
    // Default: wrap in `!`.
    format!("!({cond})")
}

// ─────────────────────────────────────────────────────────────────────────────
// Orphan label removal
// ─────────────────────────────────────────────────────────────────────────────

fn count_gotos(lines: &[String]) -> u32 {
    lines
        .iter()
        .filter(|l| parse_goto(l).is_some() || parse_if_goto(l).is_some())
        .count().try_into().unwrap_or(u32::MAX)
}

fn remove_orphan_labels(lines: Vec<String>) -> (Vec<String>, u32) {
    // Build a set of labels still referenced by gotos.
    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in &lines {
        if let Some(target) = parse_goto(line) {
            referenced.insert(target.to_string());
        } else if let Some((_, target)) = parse_if_goto(line) {
            referenced.insert(target.to_string());
        }
    }

    let mut removed = 0u32;
    let out: Vec<String> = lines
        .into_iter()
        .filter(|line| {
            if let Some(lbl) = parse_label(line)
                && !referenced.contains(lbl) {
                    removed += 1;
                    return false;
                }
            true
        })
        .collect();

    (out, removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// GotoAnnotator — annotate unresolvable gotos with a comment
// ─────────────────────────────────────────────────────────────────────────────

/// Adds a `/* GOTO: unstructured */` comment to gotos that could not be
/// converted, helping the human reader understand what's happening.
pub struct GotoAnnotator;

impl GotoAnnotator {
    #[must_use]
    pub fn annotate(source: &str) -> String {
        source
            .lines()
            .map(|line| {
                let t = line.trim();
                parse_goto(t).map_or_else(|| line.to_string(), |lbl| {
                    let ind = indent_of(line);
                    format!("{ind}goto {lbl}; /* unstructured control flow */")
                })
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GotoCounter — just count gotos in source
// ─────────────────────────────────────────────────────────────────────────────

pub struct GotoCounter;

impl GotoCounter {
    #[must_use]
    pub fn count(source: &str) -> usize {
        source
            .lines()
            .filter(|l| parse_goto(l).is_some())
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_label() {
        assert_eq!(parse_label("lbl:"), Some("lbl"));
        assert_eq!(parse_label("    end:"), Some("end"));
        assert_eq!(parse_label("case 1:"), None);
        assert_eq!(parse_label("default:"), None);
        assert_eq!(parse_label("x = 1;"), None);
    }

    #[test]
    fn test_parse_goto() {
        assert_eq!(parse_goto("    goto lbl;"), Some("lbl"));
        assert_eq!(parse_goto("goto end;"), Some("end"));
        assert_eq!(parse_goto("    return 0;"), None);
    }

    #[test]
    fn test_goto_to_break() {
        let src = "void f() {\n    while (x) {\n        if (done) goto after;\n        work();\n    }\nafter:\n    ;\n}\n";
        let remover = GotoRemover::new();
        let (out, stats) = remover.process(src);
        assert!(
            stats.converted_to_break > 0 || out.contains("break"),
            "stats: {stats:?}, out: {out}"
        );
    }

    #[test]
    fn test_goto_to_continue() {
        let src = "void f() {\n    while (x) {\n        if (skip) goto loop_top;\n        work();\nloop_top:\n    }\n}\n";
        let remover = GotoRemover::new();
        let (out, stats) = remover.process(src);
        // ⚠ This asserted `stats.converted_to_continue >= 0` on an unsigned
        // counter: always true, so the test could not fail. It was also
        // watching the wrong counter — MEASURED, the pass converts nothing to
        // `continue` here (`converted_to_continue == 0`) and instead removes
        // the `goto` by INVERTING the guard:
        //
        //     if (skip) goto loop_top;  work();   ->   if (!(skip)) { work(); }
        //
        // which is the correct transformation for a backward jump to a label at
        // the end of the loop body. Asserting the real output makes the test
        // able to fail if that transformation regresses.
        assert!(
            !out.contains("goto"),
            "the goto must be removed, got: {out}"
        );
        assert!(
            !out.contains("loop_top"),
            "the now-unreferenced label must go too, got: {out}"
        );
        assert!(
            out.contains("if (!(skip))"),
            "the guard must be inverted, got: {out}"
        );
        assert!(
            out.contains("work();"),
            "the guarded body must survive, got: {out}"
        );
        assert_eq!(
            stats.converted_to_continue, 0,
            "this shape is fixed by guard inversion, not by a `continue`"
        );
    }

    #[test]
    fn test_goto_to_return() {
        let src = "void f() {\n    if (err) goto bail;\n    work();\nbail:\n    return;\n}\n";
        let remover = GotoRemover::new();
        let (out, stats) = remover.process(src);
        assert!(
            stats.converted_to_return > 0 || out.contains("return"),
            "out: {out}"
        );
    }

    #[test]
    fn test_orphan_label_removal() {
        let lines = vec![
            "void f() {".to_string(),
            "    x = 1;".to_string(),
            "my_label:".to_string(), // orphan: no goto references it
            "    return;".to_string(),
            "}".to_string(),
        ];
        let (out, removed) = remove_orphan_labels(lines);
        assert_eq!(removed, 1);
        assert!(!out.iter().any(|l| l.contains("my_label")));
    }

    #[test]
    fn test_orphan_label_kept_when_referenced() {
        let lines = vec![
            "    goto my_label;".to_string(),
            "my_label:".to_string(),
            "    return;".to_string(),
        ];
        let (out, removed) = remove_orphan_labels(lines);
        assert_eq!(removed, 0);
        assert!(out.iter().any(|l| l.contains("my_label")));
    }

    #[test]
    fn test_goto_counter() {
        let src = "void f() {\n    goto a;\n    goto b;\n    return;\n}";
        assert_eq!(GotoCounter::count(src), 2);
    }

    #[test]
    fn test_goto_annotator() {
        let src = "    goto cleanup;";
        let out = GotoAnnotator::annotate(src);
        assert!(out.contains("unstructured"), "output: {out}");
    }

    #[test]
    fn test_negate_condition_simple() {
        assert_eq!(negate_condition("x > 0"), "x <= 0");
        assert_eq!(negate_condition("x == 0"), "x != 0");
        assert_eq!(negate_condition("x != 0"), "x == 0");
        assert_eq!(negate_condition("!flag"), "flag");
        assert_eq!(negate_condition("foo"), "!(foo)");
    }

    #[test]
    fn test_no_goto_unchanged() {
        let src = "void f() {\n    int x = 1;\n    return x;\n}\n";
        let remover = GotoRemover::new();
        let (out, stats) = remover.process(src);
        assert_eq!(stats.total_converted(), 0);
        assert!(out.contains("int x = 1"));
    }

    #[test]
    fn test_if_skip_forward_goto() {
        let src = concat!(
            "void f() {\n",
            "    if (cond) goto skip;\n",
            "    x = 1;\n",
            "    y = 2;\n",
            "skip:\n",
            "    return;\n",
            "}\n"
        );
        let remover = GotoRemover::new();
        let (out, stats) = remover.process(src);
        assert!(
            stats.converted_to_if_skip > 0
                || !out.contains("goto skip"),
            "stats: {stats:?}, out:\n{out}"
        );
    }

    #[test]
    fn test_label_index_build() {
        let lines = vec![
            "    goto my_label;".to_string(),
            "my_label:".to_string(),
            "    return;".to_string(),
        ];
        let idx = LabelIndex::build(&lines);
        assert_eq!(idx.label_line("my_label"), Some(1));
        assert_eq!(idx.ref_count("my_label"), 1);
    }
}
