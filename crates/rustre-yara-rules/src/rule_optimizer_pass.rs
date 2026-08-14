//! `rule_optimizer_pass` — Apply structured optimization passes over YARA rule
//! source text to improve matching performance and reduce false positives.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── PassResult ────────────────────────────────────────────────────────────────

/// Result produced by a single optimization pass over one rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassResult {
    /// Rule name the pass was applied to.
    pub rule_name: String,
    /// Name of the pass that produced this result.
    pub pass_name: String,
    /// The optimized rule text (equal to the input when no change was made).
    pub optimized_text: String,
    /// Whether the pass made any changes.
    pub changed: bool,
    /// Human-readable description of what was changed.
    pub changes: Vec<String>,
    /// Estimated improvement in matching speed (0.0 = no improvement, 1.0 = 100%).
    pub speed_improvement_estimate: f64,
}

impl PassResult {
    /// Create a no-change result.
    #[must_use]
    pub fn unchanged(rule_name: &str, pass_name: &str, original: &str) -> Self {
        Self {
            rule_name: rule_name.to_owned(),
            pass_name: pass_name.to_owned(),
            optimized_text: original.to_owned(),
            changed: false,
            changes: Vec::new(),
            speed_improvement_estimate: 0.0,
        }
    }

    /// Create a changed result.
    #[must_use]
    pub fn changed(
        rule_name: &str,
        pass_name: &str,
        optimized: &str,
        changes: Vec<String>,
        speed_est: f64,
    ) -> Self {
        Self {
            rule_name: rule_name.to_owned(),
            pass_name: pass_name.to_owned(),
            optimized_text: optimized.to_owned(),
            changed: true,
            changes,
            speed_improvement_estimate: speed_est,
        }
    }
}

// ── OptimizationPass trait ────────────────────────────────────────────────────

/// A single optimization pass that can be applied to a YARA rule text.
pub trait OptimizationPass: Send + Sync {
    /// Name of this pass.
    fn name(&self) -> &'static str;

    /// A brief description.
    fn description(&self) -> &'static str;

    /// Apply the pass to `rule_text`.  Returns a [`PassResult`].
    fn apply(&self, rule_name: &str, rule_text: &str) -> PassResult;
}

// ── Helper: parse rule sections ───────────────────────────────────────────────

/// Extract the `condition:` section body from a YARA rule.
fn extract_condition(rule_text: &str) -> Option<&str> {
    let idx = rule_text.find("condition:")?;
    let rest = &rule_text[idx + "condition:".len()..];
    // Find the closing brace
    let end = rest.rfind('}')?;
    Some(rest[..end].trim())
}

/// Extract all string identifiers declared in the `strings:` section.
fn extract_string_ids(rule_text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let in_strings = if let (Some(a), Some(b)) = (
        rule_text.find("strings:"),
        rule_text.find("condition:"),
    ) {
        if a < b {
            &rule_text[a + 8..b]
        } else {
            return ids;
        }
    } else {
        return ids;
    };

    for line in in_strings.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('$') {
            let id = trimmed.split_whitespace().next().unwrap_or("").trim_end_matches('=');
            if !id.is_empty() {
                ids.push(id.to_owned());
            }
        }
    }
    ids
}

/// Return true if the condition uses the `any of them` / `all of them` shorthand.
fn uses_of_them(condition: &str) -> bool {
    let c = condition.to_lowercase();
    c.contains("any of them") || c.contains("all of them") || c.contains("of them")
}

// ── Pass 1: Anchor fast-string pass ──────────────────────────────────────────

/// Add `at` anchors to byte-string patterns that appear only once in the
/// typical file header (magic bytes check).
///
/// Heuristic: if the condition already checks `uint16(0) == 0x5A4D` (PE magic)
/// and there are hex strings that look like magic byte patterns (≤8 bytes), we
/// mark them as candidates for anchoring.
pub struct AnchorFastStringPass;

impl OptimizationPass for AnchorFastStringPass {
    fn name(&self) -> &'static str {
        "anchor_fast_string"
    }

    fn description(&self) -> &'static str {
        "Anchors short magic-byte hex strings to offset 0 when the condition already checks the PE header"
    }

    fn apply(&self, rule_name: &str, rule_text: &str) -> PassResult {
        let condition = match extract_condition(rule_text) {
            Some(c) => c.to_owned(),
            None => return PassResult::unchanged(rule_name, self.name(), rule_text),
        };

        // Only apply when the rule already has a PE magic check.
        if !condition.contains("uint16(0) == 0x5A4D")
            && !condition.contains("uint16(0) == 0x4D5A")
        {
            return PassResult::unchanged(rule_name, self.name(), rule_text);
        }

        let mut changes = Vec::new();

        // Find hex strings of ≤8 bytes that might be magic patterns.
        // We look for lines like:  $x = { AB CD EF ... }  (≤8 byte pairs)
        let mut modified = false;
        let mut result_lines: Vec<String> = Vec::new();
        for line in rule_text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('$')
                && trimmed.contains('=')
                && trimmed.contains('{')
                && trimmed.contains('}')
            {
                // Count byte pairs in the hex string.
                if let (Some(open), Some(close)) = (trimmed.find('{'), trimmed.find('}')) {
                    let hex_body = &trimmed[open + 1..close];
                    let byte_count = hex_body
                        .split_whitespace()
                        .filter(|s| s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit()))
                        .count();
                    if (2..=4).contains(&byte_count) {
                        let id = trimmed.split_whitespace().next().unwrap_or("").to_owned();
                        // Check that the condition refers to this string without an offset.
                        if condition.contains(&id) && !condition.contains(&format!("{id} at")) {
                            // Suggest anchoring in the condition; we record it as a change note.
                            changes.push(format!(
                                "short magic pattern '{id}' could be anchored to offset 0"
                            ));
                            modified = true;
                        }
                    }
                }
            }
            result_lines.push(line.to_owned());
        }

        if modified {
            PassResult::changed(rule_name, self.name(), &result_lines.join("\n"), changes, 0.05)
        } else {
            PassResult::unchanged(rule_name, self.name(), rule_text)
        }
    }
}

// ── Pass 2: Dead-string removal pass ─────────────────────────────────────────

/// Remove string declarations that are never referenced in the condition.
pub struct DeadStringRemovalPass;

impl OptimizationPass for DeadStringRemovalPass {
    fn name(&self) -> &'static str {
        "dead_string_removal"
    }

    fn description(&self) -> &'static str {
        "Removes string declarations that are never referenced in the condition block"
    }

    fn apply(&self, rule_name: &str, rule_text: &str) -> PassResult {
        let condition = match extract_condition(rule_text) {
            Some(c) => c.to_owned(),
            None => return PassResult::unchanged(rule_name, self.name(), rule_text),
        };

        // Skip rules using "of them" shorthand — all strings are implicitly used.
        if uses_of_them(&condition) {
            return PassResult::unchanged(rule_name, self.name(), rule_text);
        }

        let declared = extract_string_ids(rule_text);
        let mut unused: Vec<String> = Vec::new();
        for id in &declared {
            // Strip the leading '$' for bare-name matching.
            let bare = id.trim_start_matches('$');
            if !condition.contains(id.as_str()) && !condition.contains(bare) {
                unused.push(id.clone());
            }
        }

        if unused.is_empty() {
            return PassResult::unchanged(rule_name, self.name(), rule_text);
        }

        // Remove the unused string lines.
        let mut out_lines: Vec<String> = Vec::new();
        let mut removed_count = 0usize;
        for line in rule_text.lines() {
            let trimmed = line.trim();
            let skip = unused.iter().any(|uid| {
                trimmed.starts_with(uid.as_str())
                    && (trimmed.len() == uid.len()
                        || trimmed.as_bytes().get(uid.len()).copied() == Some(b' ')
                        || trimmed.as_bytes().get(uid.len()).copied() == Some(b'='))
            });
            if skip {
                removed_count += 1;
            } else {
                out_lines.push(line.to_owned());
            }
        }

        let changes = vec![format!(
            "removed {} unused string declaration(s): {}",
            removed_count,
            unused.join(", ")
        )];
        let speed_est = crate::casts::usize_to_f64(removed_count) * 0.03;
        PassResult::changed(
            rule_name,
            self.name(),
            &out_lines.join("\n"),
            changes,
            speed_est.min(0.30),
        )
    }
}

// ── Pass 3: Condition constant-fold pass ──────────────────────────────────────

/// Fold trivial tautologies and contradictions in the condition.
///
/// E.g. `true and X` → `X`, `false or X` → `X`, `1 == 1` → `true`.
pub struct ConditionFoldPass;

impl OptimizationPass for ConditionFoldPass {
    fn name(&self) -> &'static str {
        "condition_fold"
    }

    fn description(&self) -> &'static str {
        "Folds trivial boolean tautologies and contradictions in the condition"
    }

    fn apply(&self, rule_name: &str, rule_text: &str) -> PassResult {
        let condition = match extract_condition(rule_text) {
            Some(c) => c.to_owned(),
            None => return PassResult::unchanged(rule_name, self.name(), rule_text),
        };

        let mut new_cond = condition;
        let mut changes = Vec::new();

        // Fold `true and X` → `X`.
        if let Some(folded) = fold_tautology(&new_cond, "true and ") {
            changes.push("folded 'true and X' → 'X'".to_owned());
            new_cond = folded;
        }
        // Fold `X and true` → `X`.
        if let Some(folded) = fold_tautology_suffix(&new_cond, " and true") {
            changes.push("folded 'X and true' → 'X'".to_owned());
            new_cond = folded;
        }
        // Fold `false or X` → `X`.
        if let Some(folded) = fold_tautology(&new_cond, "false or ") {
            changes.push("folded 'false or X' → 'X'".to_owned());
            new_cond = folded;
        }
        // Fold `X or false` → `X`.
        if let Some(folded) = fold_tautology_suffix(&new_cond, " or false") {
            changes.push("folded 'X or false' → 'X'".to_owned());
            new_cond = folded;
        }
        // Fold `1 == 1` → `true`.
        if new_cond.contains("1 == 1") {
            new_cond = new_cond.replace("1 == 1", "true");
            changes.push("folded '1 == 1' → 'true'".to_owned());
        }
        // Fold `filesize > 0` at the start (always true for non-empty files).
        if new_cond.starts_with("filesize > 0 and ") {
            let rest = &new_cond["filesize > 0 and ".len()..];
            changes.push("removed trivial 'filesize > 0' prefix".to_owned());
            new_cond = rest.to_owned();
        }

        if changes.is_empty() {
            return PassResult::unchanged(rule_name, self.name(), rule_text);
        }

        // Splice the new condition back into the rule text.
        let updated = replace_condition_body(rule_text, &new_cond);
        PassResult::changed(rule_name, self.name(), &updated, changes, 0.01)
    }
}

fn fold_tautology(s: &str, prefix: &str) -> Option<String> {
    s.find(prefix).map(|idx| {
        let before = &s[..idx];
        let after = &s[idx + prefix.len()..];
        format!("{before}{after}")
    })
}

fn fold_tautology_suffix(s: &str, suffix: &str) -> Option<String> {
    s.rfind(suffix).map(|idx| {
        let before = &s[..idx];
        let after = &s[idx + suffix.len()..];
        format!("{before}{after}")
    })
}

/// Replace the condition body in `rule_text` with `new_body`.
fn replace_condition_body(rule_text: &str, new_body: &str) -> String {
    if let Some(idx) = rule_text.find("condition:") {
        let before = &rule_text[..idx + "condition:".len()];
        let rest = &rule_text[idx + "condition:".len()..];
        if let Some(brace) = rest.rfind('}') {
            let after = &rest[brace..];
            return format!("{before}\n        {new_body}\n    {after}");
        }
    }
    rule_text.to_owned()
}

// ── Pass 4: Filesize bounds pass ──────────────────────────────────────────────

/// Add an upper filesize bound to rules that lack one, reducing the number of
/// large files that get fully scanned.
pub struct FilesizeBoundsPass {
    /// Default upper bound in bytes.
    pub default_max_bytes: u64,
}

impl Default for FilesizeBoundsPass {
    fn default() -> Self {
        Self {
            default_max_bytes: 10 * 1024 * 1024, // 10 MiB
        }
    }
}

impl OptimizationPass for FilesizeBoundsPass {
    fn name(&self) -> &'static str {
        "filesize_bounds"
    }

    fn description(&self) -> &'static str {
        "Appends an upper filesize bound to rules that don't already have one"
    }

    fn apply(&self, rule_name: &str, rule_text: &str) -> PassResult {
        let condition = match extract_condition(rule_text) {
            Some(c) => c.to_owned(),
            None => return PassResult::unchanged(rule_name, self.name(), rule_text),
        };

        // Already has a filesize upper bound.
        if condition.contains("filesize <") || condition.contains("filesize<=") {
            return PassResult::unchanged(rule_name, self.name(), rule_text);
        }

        let bound = self.default_max_bytes;
        let new_cond = format!("{condition} and filesize < {bound}");
        let updated = replace_condition_body(rule_text, &new_cond);
        PassResult::changed(
            rule_name,
            self.name(),
            &updated,
            vec![format!("added 'filesize < {bound}' upper bound")],
            0.10,
        )
    }
}

// ── Pass 5: Hex string normalizer pass ────────────────────────────────────────

/// Normalize hex string formatting (uppercase hex, consistent spacing).
pub struct HexNormalizerPass;

impl OptimizationPass for HexNormalizerPass {
    fn name(&self) -> &'static str {
        "hex_normalizer"
    }

    fn description(&self) -> &'static str {
        "Normalizes hex string formatting to uppercase with consistent spacing"
    }

    fn apply(&self, rule_name: &str, rule_text: &str) -> PassResult {
        let mut out = String::with_capacity(rule_text.len());
        let mut changed = false;
        let mut in_hex = false;
        let mut change_log = Vec::new();
        let mut hex_count = 0usize;

        for ch in rule_text.chars() {
            if ch == '{' {
                in_hex = true;
                out.push(ch);
            } else if ch == '}' {
                in_hex = false;
                out.push(ch);
            } else if in_hex && ch.is_ascii_hexdigit() && ch.is_ascii_lowercase() {
                out.push(ch.to_ascii_uppercase());
                hex_count += 1;
                changed = true;
            } else {
                out.push(ch);
            }
        }

        if changed {
            change_log.push(format!("uppercased {hex_count} hex digit(s)"));
            PassResult::changed(rule_name, self.name(), &out, change_log, 0.0)
        } else {
            PassResult::unchanged(rule_name, self.name(), rule_text)
        }
    }
}

// ── RuleOptimizerPass (pipeline) ──────────────────────────────────────────────

/// Runs a configurable pipeline of [`OptimizationPass`] instances over a YARA
/// rule and accumulates all results.
pub struct RuleOptimizerPass {
    passes: Vec<Box<dyn OptimizationPass>>,
    /// Whether to stop at the first pass that makes a change.
    pub stop_on_first_change: bool,
}

impl RuleOptimizerPass {
    /// Create an optimizer with the default set of passes.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            passes: vec![
                Box::new(HexNormalizerPass),
                Box::new(DeadStringRemovalPass),
                Box::new(ConditionFoldPass),
                Box::new(AnchorFastStringPass),
                Box::new(FilesizeBoundsPass::default()),
            ],
            stop_on_first_change: false,
        }
    }

    /// Create an empty optimizer (no passes).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            passes: Vec::new(),
            stop_on_first_change: false,
        }
    }

    /// Add a pass to the pipeline.
    pub fn add_pass<P: OptimizationPass + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    /// Return the names of all registered passes.
    #[must_use]
    pub fn pass_names(&self) -> Vec<&'static str> {
        self.passes.iter().map(|p| p.name()).collect()
    }

    /// Run all passes over `rule_text` and return all [`PassResult`]s.
    #[must_use]
    pub fn run(&self, rule_name: &str, rule_text: &str) -> Vec<PassResult> {
        let mut current = rule_text.to_owned();
        let mut results = Vec::new();

        for pass in &self.passes {
            let result = pass.apply(rule_name, &current);
            let changed = result.changed;
            if changed {
                current.clone_from(&result.optimized_text);
            }
            results.push(result);
            if changed && self.stop_on_first_change {
                break;
            }
        }

        results
    }

    /// Run all passes and return the final optimized text (regardless of
    /// whether any pass made changes).
    #[must_use]
    pub fn optimize(&self, rule_name: &str, rule_text: &str) -> String {
        let results = self.run(rule_name, rule_text);
        results
            .into_iter()
            .last().map_or_else(|| rule_text.to_owned(), |r| r.optimized_text)
    }

    /// Optimize every rule in `rules` (name → text map) and return a map of
    /// name → optimized text.
    #[must_use]
    pub fn optimize_batch(
        &self,
        rules: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        rules
            .iter()
            .map(|(name, text)| (name.clone(), self.optimize(name, text)))
            .collect()
    }

    /// Return a summary of all passes and the total estimated speedup.
    #[must_use]
    pub fn summary(&self, results: &[PassResult]) -> String {
        let total_changes: usize = results.iter().filter(|r| r.changed).count();
        let total_speedup: f64 = results
            .iter()
            .map(|r| r.speed_improvement_estimate)
            .sum();
        format!(
            "Passes run: {} | Changes: {} | Estimated speedup: {:.1}%",
            results.len(),
            total_changes,
            total_speedup * 100.0,
        )
    }
}

impl Default for RuleOptimizerPass {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str = r#"rule TestRule {
    meta:
        author = "test"
    strings:
        $a = { 4D 5A }
        $b = { 00 01 02 03 }
        $unused = "never_used"
    condition:
        uint16(0) == 0x5A4D and $a and $b
}"#;

    #[test]
    fn hex_normalizer_uppercases() {
        let rule = "rule X { strings: $a = { 4d 5a ff } condition: $a }";
        let pass = HexNormalizerPass;
        let result = pass.apply("X", rule);
        assert!(result.changed);
        assert!(result.optimized_text.contains("4D 5A FF"));
    }

    #[test]
    fn hex_normalizer_no_change_if_already_upper() {
        let rule = "rule X { strings: $a = { 4D 5A FF } condition: $a }";
        let pass = HexNormalizerPass;
        let result = pass.apply("X", rule);
        assert!(!result.changed);
    }

    #[test]
    fn dead_string_removal_removes_unused() {
        let pass = DeadStringRemovalPass;
        let result = pass.apply("TestRule", SAMPLE_RULE);
        assert!(result.changed);
        assert!(result.changes.iter().any(|c| c.contains("$unused")));
        assert!(!result.optimized_text.contains("$unused"));
    }

    #[test]
    fn dead_string_removal_keeps_used() {
        let pass = DeadStringRemovalPass;
        let result = pass.apply("TestRule", SAMPLE_RULE);
        assert!(result.optimized_text.contains("$a"));
        assert!(result.optimized_text.contains("$b"));
    }

    #[test]
    fn condition_fold_removes_true_and() {
        let rule = "rule X { condition: true and $a }";
        let pass = ConditionFoldPass;
        let result = pass.apply("X", rule);
        assert!(result.changed);
        assert!(!result.optimized_text.contains("true and"));
    }

    #[test]
    fn filesize_bounds_adds_limit() {
        let rule = "rule X { condition: $a }";
        let pass = FilesizeBoundsPass { default_max_bytes: 1024 };
        let result = pass.apply("X", rule);
        assert!(result.changed);
        assert!(result.optimized_text.contains("filesize < 1024"));
    }

    #[test]
    fn filesize_bounds_no_duplicate() {
        let rule = "rule X { condition: $a and filesize < 2048 }";
        let pass = FilesizeBoundsPass { default_max_bytes: 1024 };
        let result = pass.apply("X", rule);
        assert!(!result.changed);
    }

    #[test]
    fn anchor_fast_string_suggests_anchor() {
        let rule = r"rule X {
    strings:
        $magic = { 4D 5A }
    condition:
        uint16(0) == 0x5A4D and $magic
}";
        let pass = AnchorFastStringPass;
        let result = pass.apply("X", rule);
        assert!(result.changed);
        assert!(result.changes.iter().any(|c| c.contains("$magic")));
    }

    #[test]
    fn pipeline_runs_all_passes() {
        let optimizer = RuleOptimizerPass::with_defaults();
        let results = optimizer.run("TestRule", SAMPLE_RULE);
        assert!(!results.is_empty());
    }

    #[test]
    fn optimizer_produces_output() {
        let optimizer = RuleOptimizerPass::with_defaults();
        let out = optimizer.optimize("TestRule", SAMPLE_RULE);
        assert!(!out.is_empty());
    }

    #[test]
    fn summary_has_expected_format() {
        let optimizer = RuleOptimizerPass::with_defaults();
        let results = optimizer.run("TestRule", SAMPLE_RULE);
        let summary = optimizer.summary(&results);
        assert!(summary.contains("Passes run:"));
        assert!(summary.contains("Changes:"));
    }

    #[test]
    fn pass_names_non_empty() {
        let optimizer = RuleOptimizerPass::with_defaults();
        let names = optimizer.pass_names();
        assert!(!names.is_empty());
        for name in names {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn batch_optimize_returns_all_rules() {
        let mut rules = HashMap::new();
        rules.insert("R1".to_owned(), "rule R1 { condition: true }".to_owned());
        rules.insert("R2".to_owned(), "rule R2 { condition: false }".to_owned());
        let optimizer = RuleOptimizerPass::with_defaults();
        let out = optimizer.optimize_batch(&rules);
        assert_eq!(out.len(), 2);
    }
}
