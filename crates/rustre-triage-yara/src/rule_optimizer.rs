//! YARA rule optimiser.
//!
//! Analyses rules for performance bottlenecks, extracts best 4+ byte atoms for
//! fast pre-filtering, ranks rules by specificity, de-duplicates overlapping
//! rules, and groups rules by malware family for parallel execution.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{EnhancedYaraRule, NamedPattern, PatternKind};

// ── RuleStats ─────────────────────────────────────────────────────────────────

/// Performance statistics for a single YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    /// Name of the rule.
    pub rule_name: String,
    /// Estimated relative scan time (1.0 = baseline).
    pub estimated_scan_cost: f64,
    /// Estimated false-positive rate in [0.0, 1.0].
    pub false_positive_rate: f64,
    /// Average byte complexity of the rule's strings (higher = more specific).
    pub avg_string_complexity: f64,
    /// Number of string patterns.
    pub string_count: usize,
    /// Whether the rule has at least one 4-byte atom.
    pub has_good_atom: bool,
    /// Best atom found for this rule (longest high-entropy 4+ byte sequence).
    pub best_atom: Option<Vec<u8>>,
    /// Specificity score (0–100): higher is better.
    pub specificity_score: u8,
}

impl RuleStats {
    /// Return `true` if the rule is considered "fast" (low cost, good atom).
    #[must_use]
    pub fn is_fast(&self) -> bool {
        self.has_good_atom && self.estimated_scan_cost < 2.0
    }

    /// Return `true` if the rule is likely to produce many false positives.
    #[must_use]
    pub fn is_high_fp(&self) -> bool {
        self.false_positive_rate > 0.1
    }
}

// ── StringComplexityScore ─────────────────────────────────────────────────────

/// Computes a complexity score for a byte string pattern.
///
/// Higher complexity → more specific → faster scan and fewer false positives.
pub struct StringComplexityScore;

impl StringComplexityScore {
    /// Score a byte slice.
    ///
    /// - Short patterns (<4 bytes) → very low score.
    /// - Patterns with repeating bytes → lower score.
    /// - Long patterns with diverse bytes → high score.
    ///
    /// Result is in [0.0, 100.0].
    #[must_use]
    pub fn score(pattern: &[u8]) -> f64 {
        if pattern.is_empty() {
            return 0.0;
        }
        if pattern.len() < 4 {
            return f64::from(u32::try_from(pattern.len()).unwrap_or(3)) * 5.0;
        }

        // Byte diversity: unique byte count / total length
        let unique: HashSet<u8> = pattern.iter().copied().collect();
        let diversity = f64::from(u32::try_from(unique.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(pattern.len()).unwrap_or(u32::MAX));

        // Entropy
        let mut freq = [0u64; 256];
        for &b in pattern {
            freq[b as usize] += 1;
        }
        let n = f64::from(u32::try_from(pattern.len()).unwrap_or(u32::MAX));
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                -p * p.log2()
            })
            .sum();

        // Length bonus (capped at 32 bytes)
        let len_bonus = (f64::from(u32::try_from(pattern.len()).unwrap_or(u32::MAX)) / 32.0).min(1.0) * 20.0;

        let score = diversity.mul_add(40.0, (entropy / 8.0) * 30.0) + len_bonus + 10.0;
        score.min(100.0)
    }

    /// Score a wildcard hex pattern (`None` = wildcard).
    #[must_use]
    pub fn score_hex(pattern: &[Option<u8>]) -> f64 {
        if pattern.is_empty() {
            return 0.0;
        }
        let wildcards = pattern.iter().filter(|b| b.is_none()).count();
        let concrete: Vec<u8> = pattern.iter().filter_map(|b| *b).collect();
        let base = Self::score(&concrete);
        // Each wildcard reduces specificity
        let wc_penalty = (f64::from(u32::try_from(wildcards).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(pattern.len()).unwrap_or(u32::MAX))) * 30.0;
        (base - wc_penalty).max(0.0)
    }
}

// ── AtomExtractor ─────────────────────────────────────────────────────────────

/// Extracts the best 4+ byte atom from a pattern for use in pre-filtering.
///
/// YARA and similar engines use short "atoms" (typically 4 bytes) to rapidly
/// skip files that cannot match a rule, before running the full match.
pub struct AtomExtractor;

impl AtomExtractor {
    /// Extract the best atom from a literal byte slice.
    ///
    /// Finds the 4–8 byte sub-window with the highest complexity score.
    #[must_use]
    pub fn extract_from_bytes(pattern: &[u8]) -> Option<Vec<u8>> {
        if pattern.len() < 4 {
            return None;
        }
        let max_len = pattern.len().min(8);
        let min_len = 4usize;

        let mut best_score = -1.0f64;
        let mut best_atom: Option<Vec<u8>> = None;

        for start in 0..pattern.len() {
            for end in (start + min_len)..=(start + max_len).min(pattern.len()) {
                let sub = &pattern[start..end];
                let s = StringComplexityScore::score(sub);
                if s > best_score {
                    best_score = s;
                    best_atom = Some(sub.to_vec());
                }
            }
        }
        best_atom
    }

    /// Extract the best atom from a wildcard hex pattern.
    ///
    /// Finds the longest run of concrete (non-wildcard) bytes of at least 4,
    /// then picks the window with the highest complexity.
    #[must_use]
    pub fn extract_from_hex(pattern: &[Option<u8>]) -> Option<Vec<u8>> {
        // Collect contiguous runs of concrete bytes
        let mut runs: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        for b in pattern {
            if let Some(v) = b {
                current.push(*v);
            } else {
                if current.len() >= 4 {
                    runs.push(current.clone());
                }
                current.clear();
            }
        }
        if current.len() >= 4 {
            runs.push(current);
        }

        // Pick best run
        runs.into_iter()
            .max_by(|a, b| {
                StringComplexityScore::score(a)
                    .partial_cmp(&StringComplexityScore::score(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .and_then(|run| Self::extract_from_bytes(&run))
    }

    /// Extract a best atom from a text string.
    #[must_use]
    pub fn extract_from_text(text: &str) -> Option<Vec<u8>> {
        Self::extract_from_bytes(text.as_bytes())
    }

    /// Extract a best atom from a [`NamedPattern`].
    #[must_use]
    pub fn extract_from_named_pattern(np: &NamedPattern) -> Option<Vec<u8>> {
        match &np.kind {
            PatternKind::Text(t) => Self::extract_from_text(t),
            PatternKind::Hex(h) => Self::extract_from_hex(h),
            PatternKind::Regex(_) => None, // regex atoms require more analysis
        }
    }
}

// ── RuleRanker ────────────────────────────────────────────────────────────────

/// Ranks a list of [`EnhancedYaraRule`]s by estimated scanning performance.
pub struct RuleRanker;

impl RuleRanker {
    /// Compute [`RuleStats`] for a single rule.
    #[must_use]
    pub fn stats_for_rule(rule: &EnhancedYaraRule) -> RuleStats {
        let string_count = rule.strings.len();

        let mut total_complexity = 0.0f64;
        let mut best_atom: Option<Vec<u8>> = None;
        let mut best_atom_score = 0.0f64;

        for np in &rule.strings {
            let complexity = match &np.kind {
                PatternKind::Text(t) => StringComplexityScore::score(t.as_bytes()),
                PatternKind::Hex(h) => StringComplexityScore::score_hex(h),
                PatternKind::Regex(r) => f64::from(u32::try_from(r.len()).unwrap_or(u32::MAX)) * 2.0, // rough heuristic
            };
            total_complexity += complexity;

            if let Some(atom) = AtomExtractor::extract_from_named_pattern(np) {
                let atom_score = StringComplexityScore::score(&atom);
                if atom_score > best_atom_score {
                    best_atom_score = atom_score;
                    best_atom = Some(atom);
                }
            }
        }

        let avg_complexity = if string_count == 0 {
            0.0
        } else {
            total_complexity / f64::from(u32::try_from(string_count).unwrap_or(u32::MAX))
        };

        // Heuristic scan cost: more strings = more work; bad atoms = more work
        let has_good_atom = best_atom.is_some();
        let estimated_scan_cost = if string_count == 0 {
            0.1
        } else {
            let atom_factor = if has_good_atom { 0.3 } else { 3.0 };
            f64::from(u32::try_from(string_count).unwrap_or(u32::MAX)).mul_add(atom_factor, (1.0 / (avg_complexity + 1.0)) * 5.0)
        };

        // False-positive rate heuristic: low-complexity strings = more FPs
        let false_positive_rate = if avg_complexity < 20.0 {
            0.3
        } else if avg_complexity < 50.0 {
            0.05
        } else {
            0.01
        };

        // Specificity score: combines complexity, atom quality, string count
        let specificity_raw = (avg_complexity * 0.5)
            + (if has_good_atom { 30.0 } else { 0.0 })
            + (f64::from(u32::try_from(string_count).unwrap_or(u32::MAX)) * 2.0).min(20.0);
        let specificity_score = u8::try_from(specificity_raw.min(100.0).max(0.0) as u64).unwrap_or(u8::MAX);

        RuleStats {
            rule_name: rule.name.clone(),
            estimated_scan_cost,
            false_positive_rate,
            avg_string_complexity: avg_complexity,
            string_count,
            has_good_atom,
            best_atom,
            specificity_score,
        }
    }

    /// Rank a slice of rules by specificity (highest first).
    #[must_use]
    pub fn rank(rules: &[EnhancedYaraRule]) -> Vec<(&EnhancedYaraRule, RuleStats)> {
        let mut ranked: Vec<(&EnhancedYaraRule, RuleStats)> = rules
            .iter()
            .map(|r| {
                let s = Self::stats_for_rule(r);
                (r, s)
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.1.specificity_score.cmp(&a.1.specificity_score).then(
                b.1.estimated_scan_cost
                    .partial_cmp(&a.1.estimated_scan_cost)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .reverse(),
            )
        });
        ranked
    }

    /// Rank by ascending estimated scan cost (fastest-first execution order).
    #[must_use]
    pub fn rank_by_speed(rules: &[EnhancedYaraRule]) -> Vec<(&EnhancedYaraRule, RuleStats)> {
        let mut ranked: Vec<(&EnhancedYaraRule, RuleStats)> =
            rules.iter().map(|r| (r, Self::stats_for_rule(r))).collect();
        ranked.sort_by(|a, b| {
            a.1.estimated_scan_cost
                .partial_cmp(&b.1.estimated_scan_cost)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        ranked
    }
}

// ── RuleDeduplicator ──────────────────────────────────────────────────────────

/// Finds pairs of rules whose pattern sets overlap significantly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverlap {
    /// Name of the first rule.
    pub rule_a: String,
    /// Name of the second rule.
    pub rule_b: String,
    /// Jaccard similarity of their string sets.
    pub similarity: f64,
    /// Patterns shared between the two rules.
    pub shared_patterns: Vec<String>,
}

/// Detects overlapping / near-duplicate rules.
pub struct RuleDeduplicator;

impl RuleDeduplicator {
    /// Build a normalised string key for a pattern.
    fn pattern_key(np: &NamedPattern) -> String {
        match &np.kind {
            PatternKind::Text(t) => format!("text:{t}"),
            PatternKind::Hex(h) => {
                let s: String = h
                    .iter()
                    .map(|b| b.as_ref().map_or_else(|| "??".to_owned(), |v| format!("{v:02x}")))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("hex:{s}")
            }
            PatternKind::Regex(r) => format!("regex:{r}"),
        }
    }

    /// Compute pairwise overlaps for a slice of rules.
    ///
    /// Only returns pairs with Jaccard similarity above `min_similarity`.
    #[must_use]
    pub fn find_overlaps(rules: &[EnhancedYaraRule], min_similarity: f64) -> Vec<RuleOverlap> {
        let mut overlaps = Vec::new();

        for i in 0..rules.len() {
            let keys_a: HashSet<String> = rules[i].strings.iter().map(Self::pattern_key).collect();

            for j in (i + 1)..rules.len() {
                let keys_b: HashSet<String> =
                    rules[j].strings.iter().map(Self::pattern_key).collect();

                let shared: Vec<String> = keys_a.intersection(&keys_b).cloned().collect();
                let union_size = keys_a.union(&keys_b).count();

                let similarity = if union_size == 0 {
                    0.0
                } else {
                    f64::from(u32::try_from(shared.len()).unwrap_or(u32::MAX))
                        / f64::from(u32::try_from(union_size).unwrap_or(u32::MAX))
                };

                if similarity >= min_similarity {
                    overlaps.push(RuleOverlap {
                        rule_a: rules[i].name.clone(),
                        rule_b: rules[j].name.clone(),
                        similarity,
                        shared_patterns: shared,
                    });
                }
            }
        }

        overlaps.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        overlaps
    }

    /// Return indices of rules that are duplicates of another rule in the slice.
    #[must_use]
    pub fn find_duplicate_indices(rules: &[EnhancedYaraRule]) -> Vec<usize> {
        let overlaps = Self::find_overlaps(rules, 1.0);
        let mut dupes: HashSet<usize> = HashSet::new();
        for ov in &overlaps {
            if let Some(pos) = rules.iter().position(|r| r.name == ov.rule_b) {
                dupes.insert(pos);
            }
        }
        let mut v: Vec<usize> = dupes.into_iter().collect();
        v.sort_unstable();
        v
    }
}

// ── RuleGrouper ───────────────────────────────────────────────────────────────

/// Groups rules by malware family for parallel execution.
///
/// Rules sharing a tag are considered to belong to the same family group.
pub struct RuleGrouper;

impl RuleGrouper {
    /// Group rules by their first tag (family).
    ///
    /// Rules with no tags go into the `"untagged"` group.
    #[must_use]
    pub fn group_by_family(rules: &[EnhancedYaraRule]) -> HashMap<String, Vec<&EnhancedYaraRule>> {
        let mut groups: HashMap<String, Vec<&EnhancedYaraRule>> = HashMap::new();
        for rule in rules {
            let family = rule
                .tags
                .first()
                .map_or("untagged", String::as_str)
                .to_owned();
            groups.entry(family).or_default().push(rule);
        }
        groups
    }

    /// Group rules by meta key `family` (if present), falling back to first tag.
    #[must_use]
    pub fn group_by_meta_family(
        rules: &[EnhancedYaraRule],
    ) -> HashMap<String, Vec<&EnhancedYaraRule>> {
        let mut groups: HashMap<String, Vec<&EnhancedYaraRule>> = HashMap::new();
        for rule in rules {
            let family = rule
                .meta
                .get("family")
                .or_else(|| rule.meta.get("author"))
                .map(String::as_str)
                .or_else(|| rule.tags.first().map(String::as_str))
                .unwrap_or("untagged")
                .to_owned();
            groups.entry(family).or_default().push(rule);
        }
        groups
    }

    /// Return groups sorted by descending rule count.
    #[must_use]
    pub fn sorted_groups(
        groups: HashMap<String, Vec<&EnhancedYaraRule>>,
    ) -> Vec<(String, Vec<&EnhancedYaraRule>)> {
        let mut v: Vec<(String, Vec<&EnhancedYaraRule>)> = groups.into_iter().collect();
        v.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        v
    }
}

// ── RuleOptimizer ─────────────────────────────────────────────────────────────

/// High-level facade that orchestrates analysis, ranking, deduplication, and
/// grouping of a rule set.
pub struct RuleOptimizer {
    /// Rules under optimisation.
    pub rules: Vec<EnhancedYaraRule>,
}

impl RuleOptimizer {
    /// Create an optimiser for the given rule set.
    #[must_use]
    pub const fn new(rules: Vec<EnhancedYaraRule>) -> Self {
        Self { rules }
    }

    /// Compute stats for every rule.
    #[must_use]
    pub fn all_stats(&self) -> Vec<RuleStats> {
        self.rules.iter().map(RuleRanker::stats_for_rule).collect()
    }

    /// Return rules ranked by specificity (best first).
    #[must_use]
    pub fn ranked_by_specificity(&self) -> Vec<(&EnhancedYaraRule, RuleStats)> {
        RuleRanker::rank(&self.rules)
    }

    /// Return rules ranked by speed (fastest first).
    #[must_use]
    pub fn ranked_by_speed(&self) -> Vec<(&EnhancedYaraRule, RuleStats)> {
        RuleRanker::rank_by_speed(&self.rules)
    }

    /// Find overlapping / near-duplicate rules.
    #[must_use]
    pub fn find_overlaps(&self, min_similarity: f64) -> Vec<RuleOverlap> {
        RuleDeduplicator::find_overlaps(&self.rules, min_similarity)
    }

    /// Return a deduplicated copy of the rule set.
    #[must_use]
    pub fn deduplicate(&self) -> Vec<&EnhancedYaraRule> {
        let dupe_indices = RuleDeduplicator::find_duplicate_indices(&self.rules);
        let dupe_set: HashSet<usize> = dupe_indices.into_iter().collect();
        self.rules
            .iter()
            .enumerate()
            .filter(|(i, _)| !dupe_set.contains(i))
            .map(|(_, r)| r)
            .collect()
    }

    /// Group rules by family tag.
    #[must_use]
    pub fn group_by_family(&self) -> HashMap<String, Vec<&EnhancedYaraRule>> {
        RuleGrouper::group_by_family(&self.rules)
    }

    /// Return an optimisation report.
    #[must_use]
    pub fn report(&self) -> OptimizationReport {
        let all_stats = self.all_stats();
        let slow_rules: Vec<String> = all_stats
            .iter()
            .filter(|s| !s.is_fast())
            .map(|s| s.rule_name.clone())
            .collect();
        let high_fp_rules: Vec<String> = all_stats
            .iter()
            .filter(|s| s.is_high_fp())
            .map(|s| s.rule_name.clone())
            .collect();
        let overlaps = self.find_overlaps(0.5);
        let groups = self.group_by_family();

        OptimizationReport {
            total_rules: self.rules.len(),
            slow_rules,
            high_fp_rules,
            overlapping_pairs: overlaps.len(),
            family_groups: groups.len(),
            stats: all_stats,
        }
    }
}

/// Summary of an optimisation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    /// Total number of rules analysed.
    pub total_rules: usize,
    /// Rules identified as slow (no good atom or high string count).
    pub slow_rules: Vec<String>,
    /// Rules with estimated high false-positive rate.
    pub high_fp_rules: Vec<String>,
    /// Number of overlapping rule pairs.
    pub overlapping_pairs: usize,
    /// Number of distinct family groups.
    pub family_groups: usize,
    /// Per-rule statistics.
    pub stats: Vec<RuleStats>,
}

impl OptimizationReport {
    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "RuleOptimizer: {} rules, {} slow, {} high-FP, {} overlap pairs, {} families",
            self.total_rules,
            self.slow_rules.len(),
            self.high_fp_rules.len(),
            self.overlapping_pairs,
            self.family_groups,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnhancedYaraRule, NamedPattern, YaraCondition};

    fn make_rule(name: &str, strings: &[(&str, &str)]) -> EnhancedYaraRule {
        let mut r = EnhancedYaraRule::new(name);
        r.condition = YaraCondition::Any;
        for (id, text) in strings {
            r.add_pattern(NamedPattern::text(*id, *text));
        }
        r
    }

    // ── StringComplexityScore ─────────────────────────────────────────────────

    #[test]
    fn test_score_empty() {
        assert_eq!(StringComplexityScore::score(&[]), 0.0);
    }

    #[test]
    fn test_score_short_low() {
        let s = StringComplexityScore::score(&[0x01, 0x02]);
        assert!(s < 20.0, "expected low score for 2-byte pattern, got {s}");
    }

    #[test]
    fn test_score_diverse_bytes_high() {
        let diverse: Vec<u8> = (0u8..32).collect();
        let s = StringComplexityScore::score(&diverse);
        assert!(s > 50.0, "expected high score for diverse bytes, got {s}");
    }

    #[test]
    fn test_score_repeated_bytes_low() {
        let repeated = vec![0x41u8; 32]; // "AAAA..."
        let s = StringComplexityScore::score(&repeated);
        assert!(s < 50.0, "expected lower score for repeated bytes, got {s}");
    }

    #[test]
    fn test_score_hex_wildcard_penalty() {
        let no_wc: Vec<Option<u8>> = (0u8..8).map(Some).collect();
        let with_wc: Vec<Option<u8>> = {
            let mut v = no_wc.clone();
            v[2] = None;
            v[4] = None;
            v
        };
        let s_no_wc = StringComplexityScore::score_hex(&no_wc);
        let s_with_wc = StringComplexityScore::score_hex(&with_wc);
        assert!(s_no_wc > s_with_wc);
    }

    // ── AtomExtractor ─────────────────────────────────────────────────────────

    #[test]
    fn test_extract_bytes_min_4() {
        let data = b"ABCDEFGH";
        let atom = AtomExtractor::extract_from_bytes(data);
        assert!(atom.is_some());
        assert!(atom.unwrap().len() >= 4);
    }

    #[test]
    fn test_extract_bytes_short_returns_none() {
        let data = b"ABC";
        let atom = AtomExtractor::extract_from_bytes(data);
        assert!(atom.is_none());
    }

    #[test]
    fn test_extract_hex_concrete_run() {
        let pattern: Vec<Option<u8>> = vec![
            Some(0x41),
            Some(0x42),
            Some(0x43),
            Some(0x44),
            None,
            None,
            Some(0x45),
            Some(0x46),
            Some(0x47),
            Some(0x48),
        ];
        let atom = AtomExtractor::extract_from_hex(&pattern);
        assert!(atom.is_some());
    }

    #[test]
    fn test_extract_hex_all_wildcard_returns_none() {
        let pattern: Vec<Option<u8>> = vec![None; 8];
        let atom = AtomExtractor::extract_from_hex(&pattern);
        assert!(atom.is_none());
    }

    #[test]
    fn test_extract_text() {
        let atom = AtomExtractor::extract_from_text("mimikatz");
        assert!(atom.is_some());
    }

    #[test]
    fn test_extract_named_pattern_text() {
        let np = NamedPattern::text("$s", "mimikatz");
        let atom = AtomExtractor::extract_from_named_pattern(&np);
        assert!(atom.is_some());
    }

    #[test]
    fn test_extract_named_pattern_hex() {
        let pattern = vec![Some(0x4D), Some(0x5A), Some(0x90), Some(0x00)];
        let np = NamedPattern::hex("$mz", pattern);
        let atom = AtomExtractor::extract_from_named_pattern(&np);
        assert!(atom.is_some());
    }

    // ── RuleRanker ────────────────────────────────────────────────────────────

    #[test]
    fn test_stats_for_rule_has_atom() {
        let r = make_rule("test", &[("$s", "VirtualAllocEx")]);
        let stats = RuleRanker::stats_for_rule(&r);
        assert!(stats.has_good_atom);
        assert!(stats.best_atom.is_some());
    }

    #[test]
    fn test_stats_for_empty_rule() {
        let r = EnhancedYaraRule::new("empty");
        let stats = RuleRanker::stats_for_rule(&r);
        assert_eq!(stats.string_count, 0);
    }

    #[test]
    fn test_rank_order_high_specificity_first() {
        let r_long = make_rule("long_string", &[("$s", "WriteProcessMemory")]);
        let r_short = make_rule("short_string", &[("$s", "abc")]);
        let rules = vec![r_short.clone(), r_long.clone()];
        let ranked = RuleRanker::rank(&rules);
        // The rule with the longer/more specific string should rank first
        assert_eq!(ranked[0].0.name, "long_string");
    }

    #[test]
    fn test_rank_by_speed() {
        let r_no_strings = EnhancedYaraRule::new("no_strings");
        let r_many = make_rule(
            "many_strings",
            &[("$a", "aaaa"), ("$b", "bbbb"), ("$c", "cccc")],
        );
        let rules = vec![r_many, r_no_strings];
        let ranked = RuleRanker::rank_by_speed(&rules);
        // No-string rule should have lowest cost
        assert_eq!(ranked[0].0.name, "no_strings");
    }

    // ── RuleDeduplicator ──────────────────────────────────────────────────────

    #[test]
    fn test_find_overlaps_identical_rules() {
        let r1 = make_rule("r1", &[("$s", "mimikatz")]);
        let r2 = make_rule("r2", &[("$s", "mimikatz")]);
        let overlaps = RuleDeduplicator::find_overlaps(&[r1, r2], 0.9);
        assert_eq!(overlaps.len(), 1);
        assert!((overlaps[0].similarity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_find_overlaps_different_rules() {
        let r1 = make_rule("r1", &[("$s", "VirtualAlloc")]);
        let r2 = make_rule("r2", &[("$s", "mimikatz")]);
        let overlaps = RuleDeduplicator::find_overlaps(&[r1, r2], 0.5);
        assert!(overlaps.is_empty());
    }

    #[test]
    fn test_find_duplicate_indices() {
        let r1 = make_rule("r1", &[("$s", "token")]);
        let r2 = make_rule("r2", &[("$s", "token")]);
        let dupes = RuleDeduplicator::find_duplicate_indices(&[r1, r2]);
        // r2 is a duplicate of r1
        assert_eq!(dupes, vec![1]);
    }

    #[test]
    fn test_find_no_duplicates() {
        let r1 = make_rule("r1", &[("$a", "alpha")]);
        let r2 = make_rule("r2", &[("$b", "beta")]);
        let dupes = RuleDeduplicator::find_duplicate_indices(&[r1, r2]);
        assert!(dupes.is_empty());
    }

    // ── RuleGrouper ───────────────────────────────────────────────────────────

    #[test]
    fn test_group_by_family_tags() {
        let mut r1 = make_rule("upx", &[]);
        r1.add_tag("packer");
        let mut r2 = make_rule("upx2", &[]);
        r2.add_tag("packer");
        let mut r3 = make_rule("mimi", &[]);
        r3.add_tag("credential-theft");

        let rules = [r1, r2, r3];
        let groups = RuleGrouper::group_by_family(&rules);
        assert_eq!(groups["packer"].len(), 2);
        assert_eq!(groups["credential-theft"].len(), 1);
    }

    #[test]
    fn test_group_untagged() {
        let r = make_rule("no_tags", &[]);
        let rules = [r];
        let groups = RuleGrouper::group_by_family(&rules);
        assert!(groups.contains_key("untagged"));
    }

    #[test]
    fn test_sorted_groups_descending() {
        let mut r1 = make_rule("r1", &[]);
        r1.add_tag("big");
        let mut r2 = make_rule("r2", &[]);
        r2.add_tag("big");
        let mut r3 = make_rule("r3", &[]);
        r3.add_tag("small");
        let rules = [r1, r2, r3];
        let groups = RuleGrouper::group_by_family(&rules);
        let sorted = RuleGrouper::sorted_groups(groups);
        assert_eq!(sorted[0].0, "big");
    }

    // ── RuleOptimizer ─────────────────────────────────────────────────────────

    #[test]
    fn test_optimizer_all_stats() {
        let r = make_rule("r", &[("$s", "hello world")]);
        let opt = RuleOptimizer::new(vec![r]);
        let stats = opt.all_stats();
        assert_eq!(stats.len(), 1);
    }

    #[test]
    fn test_optimizer_deduplicate() {
        let r1 = make_rule("r1", &[("$s", "dup_token")]);
        let r2 = make_rule("r2", &[("$s", "dup_token")]);
        let opt = RuleOptimizer::new(vec![r1, r2]);
        let deduped = opt.deduplicate();
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_optimizer_group_by_family() {
        let mut r1 = make_rule("r1", &[]);
        r1.add_tag("malware");
        let opt = RuleOptimizer::new(vec![r1]);
        let groups = opt.group_by_family();
        assert!(groups.contains_key("malware"));
    }

    #[test]
    fn test_optimizer_report() {
        let r = make_rule("r", &[("$s", "mimikatz")]);
        let opt = RuleOptimizer::new(vec![r]);
        let report = opt.report();
        assert_eq!(report.total_rules, 1);
        let summary = report.summary();
        assert!(summary.contains("1 rules"), "{summary}");
    }

    #[test]
    fn test_rule_stats_is_fast() {
        let r = make_rule("fast_rule", &[("$s", "WriteProcessMemoryEx")]);
        let stats = RuleRanker::stats_for_rule(&r);
        // With a long, diverse string a good atom should be found
        if stats.has_good_atom {
            // estimated_scan_cost should be lower
            assert!(stats.estimated_scan_cost < 10.0);
        }
    }
}
