// rule_optimizer.rs — YARA rule set optimization and analysis

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::rule_compiler::{CompiledPattern, CompiledPatternKind, CompiledRule, CompiledRuleSet, HexToken};

// ── Optimization results ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub original_rule_count: usize,
    pub original_pattern_count: usize,
    pub redundant_rules: Vec<RedundantRule>,
    pub overlapping_patterns: Vec<OverlappingPattern>,
    pub cost_estimates: Vec<RuleCostEstimate>,
    pub suggestions: Vec<OptimizationSuggestion>,
    pub total_savings_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedundantRule {
    pub rule_name: String,
    pub namespace: String,
    pub reason: RedundancyReason,
    pub superseded_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RedundancyReason {
    AlwaysTrue,
    AlwaysFalse,
    DuplicateCondition(String),
    SubsetOf(String),
    SupersetOf(String),
    IdenticalPatterns(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlappingPattern {
    pub rule_a: String,
    pub pattern_a: String,
    pub rule_b: String,
    pub pattern_b: String,
    pub overlap_type: OverlapType,
    pub shared_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverlapType {
    Identical,
    OneSubsetOfOther,
    PartialOverlap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCostEstimate {
    pub rule_name: String,
    pub namespace: String,
    pub estimated_scan_cost: f64,
    pub pattern_count: usize,
    pub avg_atom_quality: f64,
    pub has_regex: bool,
    pub has_wildcard_heavy_hex: bool,
    pub recommendation: CostRecommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CostRecommendation {
    Optimal,
    AddAtoms,
    SplitRule,
    RefineRegex(String),
    ReduceJumps,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    pub rule_name: String,
    pub severity: SuggestionSeverity,
    pub message: String,
    pub suggested_fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuggestionSeverity {
    Info,
    Warning,
    Critical,
}

// ── Optimizer ─────────────────────────────────────────────────────────────────

pub struct RuleOptimizer {
    min_atom_quality: u8,
    max_cost_threshold: f64,
}

impl Default for RuleOptimizer {
    fn default() -> Self {
        Self {
            min_atom_quality: 10,
            max_cost_threshold: 100.0,
        }
    }
}

impl RuleOptimizer {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn analyze(&self, rule_set: &CompiledRuleSet) -> OptimizationReport {
        let all_rules: Vec<&CompiledRule> = rule_set.all_rules().collect();
        let original_rule_count = all_rules.len();
        let original_pattern_count: usize = all_rules.iter().map(|r| r.patterns.len()).sum();

        let redundant_rules = Self::find_redundant_rules(&all_rules);
        let overlapping_patterns = Self::find_overlapping_patterns(&all_rules);
        let cost_estimates = self.estimate_costs(&all_rules);
        let suggestions = Self::generate_suggestions(&all_rules, &cost_estimates);

        let redundant_count = redundant_rules.len();
        let total_savings_pct = if original_rule_count > 0 {
            f64::from(u32::try_from(redundant_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(original_rule_count).unwrap_or(u32::MAX)) * 100.0
        } else {
            0.0
        };

        OptimizationReport {
            original_rule_count,
            original_pattern_count,
            redundant_rules,
            overlapping_patterns,
            cost_estimates,
            suggestions,
            total_savings_pct,
        }
    }

    fn find_redundant_rules(rules: &[&CompiledRule]) -> Vec<RedundantRule> {
        let mut redundant = Vec::new();

        // Detect always-false: rules with no patterns but condition references patterns
        for rule in rules {
            if rule.patterns.is_empty() {
                // If condition references $* patterns but none exist, always false
                let refs_patterns = Self::condition_refs_patterns(&rule.condition_bytecode);
                if refs_patterns {
                    redundant.push(RedundantRule {
                        rule_name: rule.name.clone(),
                        namespace: rule.namespace.clone(),
                        reason: RedundancyReason::AlwaysFalse,
                        superseded_by: None,
                    });
                    continue;
                }
            }

            // Check for duplicate conditions (simple hash-based)
            let cond_hash = Self::hash_condition(&rule.condition_bytecode);
            for other in rules {
                if other.name == rule.name && other.namespace == rule.namespace {
                    continue;
                }
                let other_hash = Self::hash_condition(&other.condition_bytecode);
                if cond_hash == other_hash && Self::patterns_equivalent(&rule.patterns, &other.patterns) {
                    redundant.push(RedundantRule {
                        rule_name: rule.name.clone(),
                        namespace: rule.namespace.clone(),
                        reason: RedundancyReason::DuplicateCondition(other.name.clone()),
                        superseded_by: Some(other.name.clone()),
                    });
                    break;
                }
            }
        }

        redundant
    }

    fn condition_refs_patterns(bytecode: &[crate::rule_compiler::ConditionOp]) -> bool {
        use crate::rule_compiler::ConditionOp;
        bytecode.iter().any(|op| {
            matches!(op,
                ConditionOp::PatternMatch(_)
                | ConditionOp::PatternCount(_)
                | ConditionOp::PatternMatchAt { .. }
                | ConditionOp::PatternMatchIn { .. }
                | ConditionOp::Of { .. }
                | ConditionOp::ForAll { .. }
                | ConditionOp::ForAny { .. }
            )
        })
    }

    fn hash_condition(bytecode: &[crate::rule_compiler::ConditionOp]) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        format!("{bytecode:?}").hash(&mut h);
        h.finish()
    }

    fn patterns_equivalent(a: &[CompiledPattern], b: &[CompiledPattern]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        for (pa, pb) in a.iter().zip(b.iter()) {
            match (&pa.kind, &pb.kind) {
                (CompiledPatternKind::ByteString(ba), CompiledPatternKind::ByteString(bb)) => {
                    if ba != bb {
                        return false;
                    }
                }
                (CompiledPatternKind::Regex(ra), CompiledPatternKind::Regex(rb)) => {
                    if ra != rb {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    fn find_overlapping_patterns(rules: &[&CompiledRule]) -> Vec<OverlappingPattern> {
        let mut overlaps = Vec::new();

        for i in 0..rules.len() {
            for j in (i + 1)..rules.len() {
                for pa in &rules[i].patterns {
                    for pb in &rules[j].patterns {
                        if let Some(overlap) = Self::check_pattern_overlap(
                            &rules[i].name, &pa.id, &pa.kind,
                            &rules[j].name, &pb.id, &pb.kind,
                        ) {
                            overlaps.push(overlap);
                        }
                    }
                }
            }
        }

        overlaps
    }

    fn check_pattern_overlap(
        rule_a: &str, pat_a: &str, kind_a: &CompiledPatternKind,
        rule_b: &str, pat_b: &str, kind_b: &CompiledPatternKind,
    ) -> Option<OverlappingPattern> {
        match (kind_a, kind_b) {
            (CompiledPatternKind::ByteString(a), CompiledPatternKind::ByteString(b)) => {
                if a == b {
                    return Some(OverlappingPattern {
                        rule_a: rule_a.to_string(),
                        pattern_a: pat_a.to_string(),
                        rule_b: rule_b.to_string(),
                        pattern_b: pat_b.to_string(),
                        overlap_type: OverlapType::Identical,
                        shared_bytes: a.clone(),
                    });
                }
                // Check subset
                if a.len() > b.len() && contains_subslice(a, b) {
                    return Some(OverlappingPattern {
                        rule_a: rule_a.to_string(),
                        pattern_a: pat_a.to_string(),
                        rule_b: rule_b.to_string(),
                        pattern_b: pat_b.to_string(),
                        overlap_type: OverlapType::OneSubsetOfOther,
                        shared_bytes: b.clone(),
                    });
                }
                if b.len() > a.len() && contains_subslice(b, a) {
                    return Some(OverlappingPattern {
                        rule_a: rule_a.to_string(),
                        pattern_a: pat_a.to_string(),
                        rule_b: rule_b.to_string(),
                        pattern_b: pat_b.to_string(),
                        overlap_type: OverlapType::OneSubsetOfOther,
                        shared_bytes: a.clone(),
                    });
                }
                // Check common prefix >= 4 bytes
                let common: Vec<u8> = a.iter().zip(b.iter())
                    .take_while(|(x, y)| x == y)
                    .map(|(&x, _)| x)
                    .collect();
                if common.len() >= 4 {
                    return Some(OverlappingPattern {
                        rule_a: rule_a.to_string(),
                        pattern_a: pat_a.to_string(),
                        rule_b: rule_b.to_string(),
                        pattern_b: pat_b.to_string(),
                        overlap_type: OverlapType::PartialOverlap,
                        shared_bytes: common,
                    });
                }
                None
            }
            _ => None,
        }
    }

    fn estimate_costs(&self, rules: &[&CompiledRule]) -> Vec<RuleCostEstimate> {
        rules.iter().map(|rule| {
            let has_regex = rule.patterns.iter().any(|p| matches!(p.kind, CompiledPatternKind::Regex(_)));
            let has_wildcard_heavy_hex = rule.patterns.iter().any(|p| {
                if let CompiledPatternKind::HexString(tokens) = &p.kind {
                    let wildcard_count = tokens.iter().filter(|t| matches!(t, HexToken::Wildcard | HexToken::Jump { .. })).count();
                    let total = tokens.len();
                    total > 0 && f64::from(u32::try_from(wildcard_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX)) > 0.4
                } else {
                    false
                }
            });

            let avg_atom_quality = if rule.patterns.is_empty() {
                0.0
            } else {
                rule.patterns.iter().flat_map(|p| p.compiled_atoms.iter()).map(|a| f64::from(a.quality)).sum::<f64>()
                    / f64::from(u32::try_from(rule.patterns.iter().flat_map(|p| p.compiled_atoms.iter()).count().max(1)).unwrap_or(u32::MAX))
            };

            // Cost model: base cost + per-pattern + regex penalty + wildcard penalty
            let base_cost = 1.0;
            let pattern_cost = f64::from(u32::try_from(rule.patterns.len()).unwrap_or(u32::MAX)) * 0.5;
            let regex_cost = if has_regex { 20.0 } else { 0.0 };
            let wildcard_cost = if has_wildcard_heavy_hex { 15.0 } else { 0.0 };
            let atom_quality_bonus = -(avg_atom_quality / 10.0).min(5.0);
            let estimated_scan_cost = base_cost + pattern_cost + regex_cost + wildcard_cost + atom_quality_bonus;

            let recommendation = if has_regex && avg_atom_quality < f64::from(self.min_atom_quality) {
                CostRecommendation::AddAtoms
            } else if estimated_scan_cost > self.max_cost_threshold {
                CostRecommendation::SplitRule
            } else if has_wildcard_heavy_hex {
                CostRecommendation::ReduceJumps
            } else {
                CostRecommendation::Optimal
            };

            RuleCostEstimate {
                rule_name: rule.name.clone(),
                namespace: rule.namespace.clone(),
                estimated_scan_cost,
                pattern_count: rule.patterns.len(),
                avg_atom_quality,
                has_regex,
                has_wildcard_heavy_hex,
                recommendation,
            }
        }).collect()
    }

    fn generate_suggestions(
        rules: &[&CompiledRule],
        costs: &[RuleCostEstimate],
    ) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        for (rule, cost) in rules.iter().zip(costs.iter()) {
            // No patterns
            if rule.patterns.is_empty() {
                suggestions.push(OptimizationSuggestion {
                    rule_name: rule.name.clone(),
                    severity: SuggestionSeverity::Warning,
                    message: "Rule has no string patterns — relies entirely on metadata/condition; may be slow".to_string(),
                    suggested_fix: None,
                });
            }

            // Patterns with zero-quality atoms
            for pat in &rule.patterns {
                if pat.compiled_atoms.is_empty() {
                    suggestions.push(OptimizationSuggestion {
                        rule_name: rule.name.clone(),
                        severity: SuggestionSeverity::Critical,
                        message: format!(
                            "Pattern '{}' has no usable atoms — will scan every byte",
                            pat.id
                        ),
                        suggested_fix: Some(format!("Add a fixed-byte anchor to pattern '{}'", pat.id)),
                    });
                }
            }

            // Very high-cost rules
            if cost.estimated_scan_cost > 50.0 {
                suggestions.push(OptimizationSuggestion {
                    rule_name: rule.name.clone(),
                    severity: SuggestionSeverity::Warning,
                    message: format!(
                        "Rule has high scan cost ({:.1}); consider splitting or adding better atoms",
                        cost.estimated_scan_cost
                    ),
                    suggested_fix: None,
                });
            }

            // Too many patterns
            if rule.patterns.len() > 100 {
                suggestions.push(OptimizationSuggestion {
                    rule_name: rule.name.clone(),
                    severity: SuggestionSeverity::Warning,
                    message: format!(
                        "Rule has {} patterns — consider splitting into a rule set",
                        rule.patterns.len()
                    ),
                    suggested_fix: Some(format!(
                        "Split '{}' into multiple rules with fewer patterns each",
                        rule.name
                    )),
                });
            }

            // Wide + nocase on very long patterns (expensive)
            for pat in &rule.patterns {
                if pat.modifiers.encoding.wide && pat.modifiers.encoding.nocase
                    && let CompiledPatternKind::ByteString(b) = &pat.kind
                        && b.len() > 50 {
                            suggestions.push(OptimizationSuggestion {
                                rule_name: rule.name.clone(),
                                severity: SuggestionSeverity::Info,
                                message: format!(
                                    "Pattern '{}' is long ({} bytes) with wide+nocase modifiers — high memory usage",
                                    pat.id, b.len()
                                ),
                                suggested_fix: None,
                            });
                        }
            }
        }

        suggestions
    }

    pub fn deduplicate_patterns(
        &self,
        rule_set: &mut CompiledRuleSet,
    ) -> usize {
        let mut removed = 0;
        for rule in rule_set.rules.iter_mut()
            .chain(rule_set.globals.iter_mut())
            .chain(rule_set.private_rules.iter_mut())
        {
            let before = rule.patterns.len();
            let mut seen: HashSet<String> = HashSet::new();
            rule.patterns.retain(|p| {
                let key = match &p.kind {
                    CompiledPatternKind::ByteString(b) => format!("bytes:{}", hex::encode(b)),
                    CompiledPatternKind::HexString(t) => format!("hex:{t:?}"),
                    CompiledPatternKind::Regex(r) => format!("re:{r}"),
                };
                seen.insert(key)
            });
            removed += before - rule.patterns.len();
        }
        removed
    }

    #[must_use] 
    pub fn estimate_ruleset_cost(&self, rule_set: &CompiledRuleSet) -> f64 {
        let rules: Vec<&CompiledRule> = rule_set.all_rules().collect();
        let costs = self.estimate_costs(&rules);
        costs.iter().map(|c| c.estimated_scan_cost).sum()
    }

    /// Group cost estimates by namespace, returning a map of
    /// `namespace -> (rule_count, summed_scan_cost)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule set contains any rule whose estimated scan cost is
    /// non-finite (NaN/Inf), which would corrupt downstream aggregation.
    pub fn cost_by_namespace(
        &self,
        rule_set: &CompiledRuleSet,
    ) -> Result<HashMap<String, (usize, f64)>> {
        let rules: Vec<&CompiledRule> = rule_set.all_rules().collect();
        let costs = self.estimate_costs(&rules);
        let mut by_ns: HashMap<String, (usize, f64)> = HashMap::new();
        for c in costs {
            if !c.estimated_scan_cost.is_finite() {
                anyhow::bail!(
                    "non-finite scan cost for rule {}::{}",
                    c.namespace,
                    c.rule_name
                );
            }
            let e = by_ns.entry(c.namespace.clone()).or_insert((0, 0.0));
            e.0 += 1;
            e.1 += c.estimated_scan_cost;
        }
        Ok(by_ns)
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Rule merger ────────────────────────────────────────────────────────────────

pub struct RuleMerger;

impl RuleMerger {
    #[must_use] 
    pub fn merge_overlapping_string_patterns(
        patterns: &[CompiledPattern],
    ) -> Vec<CompiledPattern> {
        let mut result = Vec::new();
        let mut merged: HashSet<usize> = HashSet::new();

        for (i, pa) in patterns.iter().enumerate() {
            if merged.contains(&i) {
                continue;
            }

            let mut best = pa.clone();
            for (j, pb) in patterns.iter().enumerate() {
                if i == j || merged.contains(&j) {
                    continue;
                }

                if let (CompiledPatternKind::ByteString(a), CompiledPatternKind::ByteString(b)) = (&best.kind, &pb.kind) {
                    // Merge if one contains the other — keep the longer one
                    if contains_subslice(b, a) {
                        best = pb.clone();
                        merged.insert(i);
                    } else if contains_subslice(a, b) {
                        merged.insert(j);
                    }
                }
            }

            result.push(best);
        }

        result
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_subslice() {
        assert!(contains_subslice(b"hello world", b"world"));
        assert!(contains_subslice(b"hello", b""));
        assert!(!contains_subslice(b"hello", b"xyz"));
        assert!(contains_subslice(b"MZ\x90\x00", b"MZ"));
    }

    #[test]
    fn test_optimizer_empty_ruleset() {
        let optimizer = RuleOptimizer::new();
        let rs = CompiledRuleSet::new();
        let report = optimizer.analyze(&rs);
        assert_eq!(report.original_rule_count, 0);
        assert_eq!(report.total_savings_pct, 0.0);
    }

    #[test]
    fn test_estimate_ruleset_cost() {
        let optimizer = RuleOptimizer::new();
        let rs = CompiledRuleSet::new();
        assert_eq!(optimizer.estimate_ruleset_cost(&rs), 0.0);
    }
}
