//! YARA rule optimizer.
//!
//! Provides `RuleOptimizer` which runs configurable optimization passes over
//! a parsed `YaraRuleAst`, deduplicates strings, removes dead code, folds
//! constant conditions, adds anchors, and estimates the resulting speedup.

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// YaraString / YaraRuleAst
// ---------------------------------------------------------------------------

/// A single string declaration inside a YARA rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraString {
    /// Identifier (without leading `$`), e.g. `"str1"`.
    pub id: String,
    /// The pattern text or hex literal, e.g. `"\"MZ\""` or `"{ 4D 5A }"`  .
    pub pattern: String,
    /// Modifiers such as `"nocase"`, `"ascii"`, `"wide"`, `"fullword"`.
    pub modifiers: Vec<String>,
}

impl YaraString {
    /// Create a simple string declaration.
    #[must_use]
    pub fn new(id: &str, pattern: &str) -> Self {
        Self {
            id: id.to_owned(),
            pattern: pattern.to_owned(),
            modifiers: Vec::new(),
        }
    }

    /// Returns `true` if both have the same normalised pattern text and
    /// the same set of modifiers (order-insensitive).
    #[must_use]
    pub fn pattern_eq(&self, other: &Self) -> bool {
        if self.pattern != other.pattern {
            return false;
        }
        let mut a = self.modifiers.clone();
        let mut b = other.modifiers.clone();
        a.sort();
        b.sort();
        a == b
    }

    /// Return the approximate byte length of the underlying pattern.
    #[must_use]
    pub fn pattern_byte_len(&self) -> usize {
        let s = &self.pattern;
        // Strip surrounding quotes / braces
        let inner = s.trim_matches(|c| c == '"' || c == '{' || c == '}').trim();
        if s.starts_with('{') {
            // Hex string: count pairs of hex digits
            inner.split_whitespace().count()
        } else {
            inner.len()
        }
    }
}

/// A lightweight AST representation of a YARA rule.
#[derive(Debug, Clone)]
pub struct YaraRuleAst {
    /// Rule name.
    pub name: String,
    /// Rule tags (e.g. `["PE", "packed"]`).
    pub tags: Vec<String>,
    /// Meta declarations (key-value pairs).
    pub meta: Vec<(String, String)>,
    /// String declarations.
    pub strings: Vec<YaraString>,
    /// Condition expression as a raw string.
    pub condition: String,
}

impl YaraRuleAst {
    /// Create a minimal rule.
    #[must_use]
    pub fn new(name: &str, condition: &str) -> Self {
        Self {
            name: name.to_owned(),
            tags: Vec::new(),
            meta: Vec::new(),
            strings: Vec::new(),
            condition: condition.to_owned(),
        }
    }

    /// Returns all string identifiers referenced in the condition.
    #[must_use]
    pub fn referenced_ids(&self) -> HashSet<String> {
        let mut refs = HashSet::new();
        let mut i = 0;
        let bytes = self.condition.as_bytes();
        while i < bytes.len() {
            if bytes[i] == b'$' {
                i += 1;
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                if i > start {
                    refs.insert(self.condition[start..i].to_owned());
                }
            } else {
                i += 1;
            }
        }
        refs
    }

    /// Emit a canonical YARA rule text.
    #[must_use]
    pub fn to_yara_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("rule ");
        out.push_str(&self.name);
        if !self.tags.is_empty() {
            out.push_str(" : ");
            out.push_str(&self.tags.join(" "));
        }
        out.push_str(" {\n");
        if !self.meta.is_empty() {
            out.push_str("  meta:\n");
            for (k, v) in &self.meta {
                let _ = writeln!(out, "    {k} = \"{v}\"");
            }
        }
        if !self.strings.is_empty() {
            out.push_str("  strings:\n");
            for s in &self.strings {
                let mods = if s.modifiers.is_empty() {
                    String::new()
                } else {
                    format!(" {}", s.modifiers.join(" "))
                };
                let _ = writeln!(out, "    ${} = {}{mods}", s.id, s.pattern);
            }
        }
        out.push_str("  condition:\n");
        let _ = writeln!(out, "    {}", self.condition);
        out.push_str("}\n");
        out
    }
}

// ---------------------------------------------------------------------------
// OptimizationPass
// ---------------------------------------------------------------------------

/// A single optimization pass that can be applied to a rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OptimizationPass {
    /// Remove duplicate string patterns, rewriting the condition to use the
    /// canonical identifier.
    DeduplicateStrings,
    /// Remove string declarations that are never referenced in the condition.
    RemoveUnusedStrings,
    /// Merge alternatives like `$a = "foo" $b = "foo"` into a single regex.
    MergeAlternatives,
    /// Constant-fold trivial condition expressions.
    OptimizeCondition,
    /// Add a `uint16(0) == 0x5A4D` PE anchor if PE tags are present.
    AddAnchors,
}

// ---------------------------------------------------------------------------
// OptimizationResult
// ---------------------------------------------------------------------------

/// Summary of changes made by the optimizer.
#[derive(Debug, Clone, Default)]
pub struct OptimizationResult {
    /// Number of string declarations before optimization.
    pub original_string_count: u32,
    /// Number of string declarations after optimization.
    pub optimized_string_count: u32,
    /// Identifiers that were removed.
    pub removed_strings: Vec<String>,
    /// Number of anchors added.
    pub added_anchors: u32,
    /// Rough speedup factor (1.0 = no change, 2.0 = twice as fast).
    pub estimated_speedup: f64,
    /// Human-readable notes from each pass.
    pub pass_notes: Vec<String>,
}

impl OptimizationResult {
    /// Returns `true` if any change was made.
    #[must_use]
    pub const fn any_change(&self) -> bool {
        self.original_string_count != self.optimized_string_count
            || self.added_anchors > 0
    }

    /// Returns the number of strings that were removed.
    #[must_use]
    pub const fn strings_removed(&self) -> u32 {
        self.original_string_count.saturating_sub(self.optimized_string_count)
    }
}

// ---------------------------------------------------------------------------
// RuleOptimizer
// ---------------------------------------------------------------------------

/// YARA rule optimizer.
///
/// Apply passes individually or use `optimize_all()` to run the full set.
///
/// # Example
/// ```rust
/// use rustre_triage_yara::yara_rule_optimizer::{RuleOptimizer, YaraRuleAst, OptimizationPass};
///
/// let mut rule = YaraRuleAst::new("example", "$s1");
/// let optimizer = RuleOptimizer::new();
/// let (optimized, result) = optimizer.optimize_all(&rule);
/// assert!(!result.pass_notes.is_empty());
/// ```
pub struct RuleOptimizer {
    /// Passes to apply (in order).
    passes: Vec<OptimizationPass>,
}

impl RuleOptimizer {
    /// Create a new optimizer with the default set of passes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passes: vec![
                OptimizationPass::DeduplicateStrings,
                OptimizationPass::RemoveUnusedStrings,
                OptimizationPass::OptimizeCondition,
                OptimizationPass::AddAnchors,
            ],
        }
    }

    /// Create an optimizer with an explicit ordered list of passes.
    #[must_use]
    pub fn with_passes(passes: Vec<OptimizationPass>) -> Self {
        Self { passes }
    }

    /// Run all configured passes on the given rule.
    ///
    /// Returns the optimized rule and an aggregated `OptimizationResult`.
    #[must_use]
    pub fn optimize_all(&self, rule: &YaraRuleAst) -> (YaraRuleAst, OptimizationResult) {
        let mut current = rule.clone();
        let initial_count = u32::try_from(rule.strings.len()).unwrap_or(u32::MAX);
        let mut result = OptimizationResult {
            original_string_count: initial_count,
            optimized_string_count: initial_count,
            ..Default::default()
        };

        for pass in &self.passes {
            match pass {
                OptimizationPass::DeduplicateStrings => {
                    let (r, note, removed) = self.deduplicate_strings(&current);
                    result.removed_strings.extend(removed);
                    result.pass_notes.push(note);
                    current = r;
                }
                OptimizationPass::RemoveUnusedStrings => {
                    let (r, note, removed) = self.remove_unused_strings(&current);
                    result.removed_strings.extend(removed);
                    result.pass_notes.push(note);
                    current = r;
                }
                OptimizationPass::MergeAlternatives => {
                    let (r, note) = self.merge_alternatives(&current);
                    result.pass_notes.push(note);
                    current = r;
                }
                OptimizationPass::OptimizeCondition => {
                    let (r, note) = self.optimize_condition(&current);
                    result.pass_notes.push(note);
                    current = r;
                }
                OptimizationPass::AddAnchors => {
                    let (r, anchors_added, note) = self.add_anchors(&current);
                    result.added_anchors += anchors_added;
                    result.pass_notes.push(note);
                    current = r;
                }
            }
        }

        result.optimized_string_count = u32::try_from(current.strings.len()).unwrap_or(u32::MAX);
        result.estimated_speedup = self.estimate_speedup(rule, &current, &result);
        (current, result)
    }

    // ── individual passes ──────────────────────────────────────────────────

    /// Deduplicate string declarations that have identical patterns.
    ///
    /// The first occurrence is kept; subsequent duplicates are removed and all
    /// condition references to them are rewritten to the canonical identifier.
    #[must_use]
    pub fn deduplicate_strings(
        &self,
        rule: &YaraRuleAst,
    ) -> (YaraRuleAst, String, Vec<String>) {
        let mut canonical: Vec<YaraString> = Vec::new(); // kept strings
        // Maps removed_id → canonical_id
        let mut redirect: HashMap<String, String> = HashMap::new();
        let mut removed_ids: Vec<String> = Vec::new();

        'outer: for s in &rule.strings {
            for c in &canonical {
                if c.pattern_eq(s) {
                    redirect.insert(s.id.clone(), c.id.clone());
                    removed_ids.push(s.id.clone());
                    continue 'outer;
                }
            }
            canonical.push(s.clone());
        }

        let mut new_condition = rule.condition.clone();
        for (old, new) in &redirect {
            new_condition = replace_identifier_in_condition(&new_condition, old, new);
        }

        let note = if removed_ids.is_empty() {
            "DeduplicateStrings: no duplicates found".to_owned()
        } else {
            format!(
                "DeduplicateStrings: removed {} duplicate(s): {}",
                removed_ids.len(),
                removed_ids.join(", ")
            )
        };

        let mut new_rule = rule.clone();
        new_rule.strings = canonical;
        new_rule.condition = new_condition;
        (new_rule, note, removed_ids)
    }

    /// Remove string declarations that are not referenced in the condition.
    #[must_use]
    pub fn remove_unused_strings(
        &self,
        rule: &YaraRuleAst,
    ) -> (YaraRuleAst, String, Vec<String>) {
        let refs = rule.referenced_ids();
        let mut kept = Vec::new();
        let mut removed_ids = Vec::new();

        for s in &rule.strings {
            if refs.contains(&s.id) {
                kept.push(s.clone());
            } else {
                removed_ids.push(s.id.clone());
            }
        }

        let note = if removed_ids.is_empty() {
            "RemoveUnusedStrings: all strings are referenced".to_owned()
        } else {
            format!(
                "RemoveUnusedStrings: removed {} unreferenced string(s): {}",
                removed_ids.len(),
                removed_ids.join(", ")
            )
        };

        let mut new_rule = rule.clone();
        new_rule.strings = kept;
        (new_rule, note, removed_ids)
    }

    /// Merge identical patterns into a single string and update the condition.
    ///
    /// This pass is more aggressive than `DeduplicateStrings`: it also rewrites
    /// `($a or $b)` into a single `$merged_N` entry.
    #[must_use]
    pub fn merge_alternatives(&self, rule: &YaraRuleAst) -> (YaraRuleAst, String) {
        // Group strings by normalised pattern
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for s in &rule.strings {
            groups.entry(s.pattern.clone()).or_default().push(s.id.clone());
        }

        let mut keep: Vec<YaraString> = Vec::new();
        let mut redirect: HashMap<String, String> = HashMap::new();
        let mut merge_count = 0usize;

        for s in &rule.strings {
            let group = &groups[&s.pattern];
            if group.len() > 1 {
                let canonical_id = group[0].clone();
                if s.id == canonical_id {
                    keep.push(s.clone());
                } else {
                    redirect.insert(s.id.clone(), canonical_id.clone());
                    merge_count += 1;
                }
            } else {
                keep.push(s.clone());
            }
        }

        let mut new_condition = rule.condition.clone();
        for (old, new) in &redirect {
            new_condition = replace_identifier_in_condition(&new_condition, old, new);
        }

        let note = format!("MergeAlternatives: merged {merge_count} duplicate pattern(s)");
        let mut new_rule = rule.clone();
        new_rule.strings = keep;
        new_rule.condition = new_condition;
        (new_rule, note)
    }

    /// Constant-fold the condition expression.
    ///
    /// Handles:
    /// - `true and X` → `X`
    /// - `X and true` → `X`
    /// - `false or X` → `X`
    /// - `X or false` → `X`
    /// - `not not X` → `X`
    #[must_use]
    pub fn optimize_condition(&self, rule: &YaraRuleAst) -> (YaraRuleAst, String) {
        let original = rule.condition.clone();
        let mut cond = original.clone();

        // Apply substitutions repeatedly until stable
        for _ in 0..16 {
            let prev = cond.clone();
            cond = cond.replace("true and ", "");
            cond = cond.replace(" and true", "");
            cond = cond.replace("false or ", "");
            cond = cond.replace(" or false", "");
            cond = cond.replace("not not ", "");
            // Remove redundant parens around a single token
            cond = strip_redundant_parens(&cond);
            if cond == prev {
                break;
            }
        }
        cond = cond.trim().to_owned();

        let note = if cond == original {
            "OptimizeCondition: no constant-fold opportunities".to_owned()
        } else {
            format!("OptimizeCondition: simplified '{original}' → '{cond}'")
        };

        let mut new_rule = rule.clone();
        new_rule.condition = cond;
        (new_rule, note)
    }

    /// Add a PE magic anchor (`uint16(0) == 0x5A4D`) to PE rules that lack one.
    ///
    /// A rule is considered a PE rule if:
    /// - It has a `"PE"` tag, OR
    /// - Its condition already references `pe.` module attributes.
    ///
    /// The anchor is prepended to the condition with ` and `.
    #[must_use]
    pub fn add_anchors(&self, rule: &YaraRuleAst) -> (YaraRuleAst, u32, String) {
        let is_pe_rule = rule.tags.iter().any(|t| t.eq_ignore_ascii_case("pe"))
            || rule.condition.contains("pe.")
            || rule.condition.contains("uint16(0)");

        if rule.condition.contains("uint16(0) == 0x5A4D") {
            return (
                rule.clone(),
                0,
                "AddAnchors: PE anchor already present".to_owned(),
            );
        }

        if !is_pe_rule {
            return (
                rule.clone(),
                0,
                "AddAnchors: rule is not a PE rule, no anchor added".to_owned(),
            );
        }

        let new_condition = format!("uint16(0) == 0x5A4D and ({})", rule.condition.trim());
        let mut new_rule = rule.clone();
        new_rule.condition = new_condition;
        (new_rule, 1, "AddAnchors: added PE magic anchor".to_owned())
    }

    // ── speedup estimation ─────────────────────────────────────────────────

    /// Estimate the scanning speedup achieved by the optimization.
    ///
    /// Heuristic:
    /// - Each removed string contributes +15 % speedup.
    /// - An anchor contributes +30 % speedup.
    /// - Shorter average pattern lengths contribute +5 % per byte saved.
    #[must_use]
    pub fn estimate_speedup(
        &self,
        original: &YaraRuleAst,
        optimized: &YaraRuleAst,
        result: &OptimizationResult,
    ) -> f64 {
        let mut speedup = 1.0f64;

        let orig_len = f64::from(u32::try_from(original.strings.len()).unwrap_or(u32::MAX));
        if orig_len > 0.0 {
            let removed_fraction = f64::from(result.strings_removed()) / orig_len;
            speedup += removed_fraction * 0.15 * orig_len;
        }

        if result.added_anchors > 0 {
            speedup += 0.30;
        }

        // Average pattern length improvement
        let avg_orig = average_pattern_len(&original.strings);
        let avg_opt = average_pattern_len(&optimized.strings);
        if avg_orig > 0.0 && avg_opt < avg_orig {
            speedup += (avg_orig - avg_opt) * 0.05;
        }

        speedup
    }
}

impl Default for RuleOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Replace all occurrences of `$old_id` (as a whole identifier) with `$new_id`
/// in a YARA condition string.
fn replace_identifier_in_condition(condition: &str, old_id: &str, new_id: &str) -> String {
    let old_token = format!("${old_id}");
    let new_token = format!("${new_id}");
    let mut result = String::with_capacity(condition.len());
    let mut rest = condition;
    while let Some(pos) = rest.find(&old_token) {
        // Check that the char after the match is not alphanumeric / '_'
        let after_pos = pos + old_token.len();
        let is_boundary = rest[after_pos..]
            .chars()
            .next()
            .map(|c| !c.is_alphanumeric() && c != '_')
            .unwrap_or(true);
        result.push_str(&rest[..pos]);
        if is_boundary {
            result.push_str(&new_token);
        } else {
            result.push_str(&old_token);
        }
        rest = &rest[after_pos..];
    }
    result.push_str(rest);
    result
}

/// Strip one layer of outer parentheses if they wrap the entire expression.
fn strip_redundant_parens(s: &str) -> String {
    let s = s.trim();
    if !s.starts_with('(') || !s.ends_with(')') {
        return s.to_owned();
    }
    // Verify the opening paren matches the closing paren
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
        }
        if depth == 0 && i < bytes.len() - 1 {
            // The opening paren closed before the end — it's not wrapping everything
            return s.to_owned();
        }
    }
    // Safe to strip
    s[1..s.len() - 1].trim().to_owned()
}

/// Compute the average pattern byte length across a slice of strings.
fn average_pattern_len(strings: &[YaraString]) -> f64 {
    if strings.is_empty() {
        return 0.0;
    }
    let total: usize = strings.iter().map(|s| s.pattern_byte_len()).sum();
    f64::from(u32::try_from(total).unwrap_or(u32::MAX)) / f64::from(u32::try_from(strings.len()).unwrap_or(u32::MAX))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(condition: &str, strings: Vec<(&str, &str)>) -> YaraRuleAst {
        let mut rule = YaraRuleAst::new("test_rule", condition);
        for (id, pat) in strings {
            rule.strings.push(YaraString::new(id, pat));
        }
        rule
    }

    #[test]
    fn test_yara_string_pattern_eq_same() {
        let a = YaraString::new("s1", "\"hello\"");
        let b = YaraString::new("s2", "\"hello\"");
        assert!(a.pattern_eq(&b));
    }

    #[test]
    fn test_yara_string_pattern_eq_different() {
        let a = YaraString::new("s1", "\"hello\"");
        let b = YaraString::new("s2", "\"world\"");
        assert!(!a.pattern_eq(&b));
    }

    #[test]
    fn test_yara_string_modifier_order_independent() {
        let mut a = YaraString::new("s1", "\"x\"");
        a.modifiers = vec!["wide".to_owned(), "ascii".to_owned()];
        let mut b = YaraString::new("s2", "\"x\"");
        b.modifiers = vec!["ascii".to_owned(), "wide".to_owned()];
        assert!(a.pattern_eq(&b));
    }

    #[test]
    fn test_referenced_ids() {
        let rule = make_rule("$a and $b", vec![("a", "\"foo\""), ("b", "\"bar\""), ("c", "\"baz\"")]);
        let refs = rule.referenced_ids();
        assert!(refs.contains("a"));
        assert!(refs.contains("b"));
        assert!(!refs.contains("c"));
    }

    #[test]
    fn test_deduplicate_strings_no_dups() {
        let rule = make_rule("$a and $b", vec![("a", "\"foo\""), ("b", "\"bar\"")]);
        let optimizer = RuleOptimizer::new();
        let (opt, note, removed) = optimizer.deduplicate_strings(&rule);
        assert_eq!(opt.strings.len(), 2);
        assert!(removed.is_empty());
        assert!(note.contains("no duplicates"));
    }

    #[test]
    fn test_deduplicate_strings_with_dup() {
        let rule = make_rule(
            "$a and $b",
            vec![("a", "\"foo\""), ("b", "\"foo\"")],
        );
        let optimizer = RuleOptimizer::new();
        let (opt, _note, removed) = optimizer.deduplicate_strings(&rule);
        assert_eq!(opt.strings.len(), 1);
        assert_eq!(removed.len(), 1);
        // Condition should be rewritten to $a
        assert!(!opt.condition.contains("$b"));
    }

    #[test]
    fn test_remove_unused_strings() {
        let rule = make_rule("$a", vec![("a", "\"foo\""), ("b", "\"bar\""), ("c", "\"baz\"")]);
        let optimizer = RuleOptimizer::new();
        let (opt, _note, removed) = optimizer.remove_unused_strings(&rule);
        assert_eq!(opt.strings.len(), 1);
        assert!(removed.contains(&"b".to_owned()));
        assert!(removed.contains(&"c".to_owned()));
    }

    #[test]
    fn test_optimize_condition_true_and() {
        let rule = make_rule("true and $a", vec![("a", "\"x\"")]);
        let optimizer = RuleOptimizer::new();
        let (opt, note) = optimizer.optimize_condition(&rule);
        assert!(!opt.condition.contains("true and"), "condition: {}", opt.condition);
        assert!(note.contains("simplified"));
    }

    #[test]
    fn test_optimize_condition_false_or() {
        let rule = make_rule("false or $a", vec![("a", "\"x\"")]);
        let optimizer = RuleOptimizer::new();
        let (opt, _note) = optimizer.optimize_condition(&rule);
        assert!(!opt.condition.contains("false or"), "condition: {}", opt.condition);
    }

    #[test]
    fn test_optimize_condition_no_change() {
        let rule = make_rule("$a and $b", vec![("a", "\"x\""), ("b", "\"y\"")]);
        let optimizer = RuleOptimizer::new();
        let (opt, note) = optimizer.optimize_condition(&rule);
        assert_eq!(opt.condition, "$a and $b");
        assert!(note.contains("no constant-fold"));
    }

    #[test]
    fn test_add_anchors_pe_tag() {
        let mut rule = make_rule("$a", vec![("a", "\"MZ\"")]);
        rule.tags.push("PE".to_owned());
        let optimizer = RuleOptimizer::new();
        let (opt, added, note) = optimizer.add_anchors(&rule);
        assert_eq!(added, 1);
        assert!(opt.condition.contains("uint16(0) == 0x5A4D"));
        assert!(note.contains("added PE magic anchor"));
    }

    #[test]
    fn test_add_anchors_not_pe() {
        let rule = make_rule("$a", vec![("a", "\"hello\"")]);
        let optimizer = RuleOptimizer::new();
        let (opt, added, _note) = optimizer.add_anchors(&rule);
        assert_eq!(added, 0);
        assert!(!opt.condition.contains("uint16(0)"));
    }

    #[test]
    fn test_add_anchors_already_present() {
        let rule = make_rule(
            "uint16(0) == 0x5A4D and $a",
            vec![("a", "\"MZ\"")],
        );
        let optimizer = RuleOptimizer::new();
        let (_opt, added, note) = optimizer.add_anchors(&rule);
        assert_eq!(added, 0);
        assert!(note.contains("already present"));
    }

    #[test]
    fn test_optimize_all_combined() {
        let mut rule = make_rule(
            "true and $a and $b",
            vec![("a", "\"evil\""), ("b", "\"evil\""), ("c", "\"unused\"")],
        );
        rule.tags.push("PE".to_owned());
        let optimizer = RuleOptimizer::new();
        let (opt, result) = optimizer.optimize_all(&rule);
        // c removed, b deduplicated, true and folded, anchor added
        assert!(result.any_change());
        assert!(opt.strings.len() < 3);
        assert!(!opt.condition.contains("true and"), "condition: {}", opt.condition);
    }

    #[test]
    fn test_optimization_result_strings_removed() {
        let result = OptimizationResult {
            original_string_count: 5,
            optimized_string_count: 3,
            ..Default::default()
        };
        assert_eq!(result.strings_removed(), 2);
    }

    #[test]
    fn test_estimate_speedup_increases_with_removals() {
        let original = make_rule("$a and $b", vec![("a", "\"x\""), ("b", "\"y\"")]);
        let optimized = make_rule("$a", vec![("a", "\"x\"")]);
        let result = OptimizationResult {
            original_string_count: 2,
            optimized_string_count: 1,
            ..Default::default()
        };
        let optimizer = RuleOptimizer::new();
        let speedup = optimizer.estimate_speedup(&original, &optimized, &result);
        assert!(speedup > 1.0, "speedup = {}", speedup);
    }

    #[test]
    fn test_to_yara_text_roundtrip() {
        let mut rule = YaraRuleAst::new("my_rule", "$s1 and $s2");
        rule.tags.push("PE".to_owned());
        rule.meta.push(("author".to_owned(), "tester".to_owned()));
        rule.strings.push(YaraString::new("s1", "\"MZ\""));
        rule.strings.push(YaraString::new("s2", "{ 90 90 }"));
        let text = rule.to_yara_text();
        assert!(text.contains("rule my_rule"));
        assert!(text.contains("$s1 = \"MZ\""));
        assert!(text.contains("$s2 = { 90 90 }"));
        assert!(text.contains("author = \"tester\""));
    }

    #[test]
    fn test_strip_redundant_parens() {
        assert_eq!(strip_redundant_parens("(abc)"), "abc");
        assert_eq!(strip_redundant_parens("(a and b)"), "a and b");
        // Should not strip when parens don't wrap the whole thing
        assert_eq!(strip_redundant_parens("(a) and (b)"), "(a) and (b)");
    }
}
