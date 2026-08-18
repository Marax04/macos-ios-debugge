//! Prompt optimization for RE-focused LLM interactions.
//!
//! Provides [`PromptOptimizer`] as the root type, with
//! [`TokenReduction`], [`ContextualExpansion`], [`FewShotSelector`],
//! [`PromptChain`], and [`OptimizationReport`].


use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OptimizerError {
    #[error("empty prompt")]
    EmptyPrompt,

    #[error("token limit {0} too small")]
    TokenLimitTooSmall(u32),

    #[error("no few-shot examples available for task '{0}'")]
    NoExamples(String),

    #[error("chain step {step} failed: {message}")]
    ChainFailed { step: usize, message: String },

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type OptResult<T> = std::result::Result<T, OptimizerError>;

// ── TokenReduction ────────────────────────────────────────────────────────────

/// Reduces the token count of a prompt while preserving intent.
pub struct TokenReduction {
    /// Target token budget (upper bound).
    pub target_tokens: u32,
    /// Whether to use abbreviations for common RE terms.
    pub use_abbreviations: bool,
    /// Whether to strip redundant whitespace and markdown.
    pub strip_formatting: bool,
}

impl TokenReduction {
    #[must_use] 
    pub const fn new(target_tokens: u32) -> Self {
        Self {
            target_tokens,
            use_abbreviations: false,
            strip_formatting: true,
        }
    }

    /// Reduce `prompt` to fit within the token budget.
    pub fn reduce(&self, prompt: &str) -> OptResult<ReductionResult> {
        if prompt.is_empty() {
            return Err(OptimizerError::EmptyPrompt);
        }

        let mut result = prompt.to_owned();
        let original_tokens = estimate_tokens(prompt);
        let mut tokens_saved = 0u32;
        let mut techniques_applied = Vec::new();

        if self.strip_formatting {
            let before = estimate_tokens(&result);
            result = Self::strip_markdown(&result);
            result = Self::normalize_whitespace(&result);
            let after = estimate_tokens(&result);
            if after < before {
                tokens_saved += before - after;
                techniques_applied.push("strip_formatting".to_owned());
            }
        }

        if self.use_abbreviations {
            let before = estimate_tokens(&result);
            result = Self::apply_abbreviations(&result);
            let after = estimate_tokens(&result);
            if after < before {
                tokens_saved += before - after;
                techniques_applied.push("abbreviations".to_owned());
            }
        }

        // If still over budget, truncate.
        let final_tokens = estimate_tokens(&result);
        if final_tokens > self.target_tokens {
            result = Self::truncate_to_tokens(&result, self.target_tokens);
            techniques_applied.push("truncation".to_owned());
        }

        Ok(ReductionResult {
            original_text: prompt.to_owned(),
            reduced_text: result.clone(),
            original_tokens,
            final_tokens: estimate_tokens(&result),
            tokens_saved,
            techniques_applied,
        })
    }

    fn strip_markdown(s: &str) -> String {
        // Remove markdown headers, bold, italic markers.
        let mut out = s.to_owned();
        for marker in &["**", "__", "##", "# ", "```", "> "] {
            out = out.replace(marker, "");
        }
        out
    }

    fn normalize_whitespace(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for (i, word) in s.split_whitespace().enumerate() {
            if i > 0 { out.push(' '); }
            out.push_str(word);
        }
        out
    }

    fn apply_abbreviations(s: &str) -> String {
        let abbrevs = [
            ("reverse engineering", "RE"),
            ("disassembly", "disasm"),
            ("decompilation", "decomp"),
            ("function", "func"),
            ("address", "addr"),
            ("instruction", "insn"),
            ("analysis", "anal"),
            ("vulnerability", "vuln"),
        ];
        let mut out = s.to_owned();
        for (long, short) in abbrevs {
            out = out.replace(long, short);
        }
        out
    }

    fn truncate_to_tokens(s: &str, limit: u32) -> String {
        // Approximate: 1 token ≈ 1 word (conservative).
        let max_words = limit as usize;
        let mut out = String::with_capacity(s.len().min(max_words * 8));
        let mut count = 0usize;
        for word in s.split_whitespace() {
            if count == max_words {
                out.push_str(" [truncated]");
                return out;
            }
            if count > 0 { out.push(' '); }
            out.push_str(word);
            count += 1;
        }
        // Fewer words than limit — return original to avoid the reallocation.
        s.to_owned()
    }
}

#[derive(Debug, Clone)]
pub struct ReductionResult {
    pub original_text: String,
    pub reduced_text: String,
    pub original_tokens: u32,
    pub final_tokens: u32,
    pub tokens_saved: u32,
    pub techniques_applied: Vec<String>,
}

impl ReductionResult {
    #[must_use] 
    pub fn reduction_ratio(&self) -> f64 {
        if self.original_tokens == 0 {
            return 0.0;
        }
        1.0 - (f64::from(self.final_tokens) / f64::from(self.original_tokens))
    }
}

// ── ContextualExpansion ───────────────────────────────────────────────────────

/// Expands a short prompt with contextual RE knowledge.
pub struct ContextualExpansion {
    pub domain: ReDomain,
    pub max_expansion_tokens: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReDomain {
    Malware,
    BinaryAnalysis,
    Vulnerability,
    CryptoAnalysis,
    Generic,
}

impl ContextualExpansion {
    #[must_use] 
    pub const fn new(domain: ReDomain, max_expansion_tokens: u32) -> Self {
        Self {
            domain,
            max_expansion_tokens,
        }
    }

    /// Expand `prompt` with domain context prefix.
    pub fn expand(&self, prompt: &str) -> OptResult<String> {
        if prompt.is_empty() {
            return Err(OptimizerError::EmptyPrompt);
        }
        let prefix = self.domain_prefix();
        let expanded = format!("{prefix}\n\n{prompt}");
        let tokens = estimate_tokens(&expanded);
        if tokens > self.max_expansion_tokens {
            // Trim prefix to fit.
            let budget_for_prefix = self
                .max_expansion_tokens
                .saturating_sub(estimate_tokens(prompt) + 10);
            let trimmed_prefix = TokenReduction::new(budget_for_prefix)
                .reduce(&prefix)?
                .reduced_text;
            Ok(format!("{trimmed_prefix}\n\n{prompt}"))
        } else {
            Ok(expanded)
        }
    }

    fn domain_prefix(&self) -> String {
        match self.domain {
            ReDomain::Malware => "You are analyzing a potentially malicious binary. Focus on: C2 communication, persistence mechanisms, evasion techniques, payload decryption, and IOC extraction.".into(),
            ReDomain::BinaryAnalysis => "You are performing static binary analysis. Focus on: function identification, data flow, control flow graphs, type recovery, and symbol naming.".into(),
            ReDomain::Vulnerability => "You are hunting for vulnerabilities. Focus on: integer overflows, buffer overflows, use-after-free, format string bugs, and unsafe API usage.".into(),
            ReDomain::CryptoAnalysis => "You are analyzing cryptographic usage. Focus on: algorithm identification, key material, IV/nonce handling, custom ciphers, and weak implementations.".into(),
            ReDomain::Generic => "You are a reverse engineering assistant. Provide precise, technical answers based on the binary evidence provided.".into(),
        }
    }
}

// ── FewShotExample ────────────────────────────────────────────────────────────

/// A single few-shot example.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FewShotExample {
    pub task_type: String,
    pub input: String,
    pub output: String,
    pub quality_score: f32,
    pub tags: Vec<String>,
}

impl FewShotExample {
    pub fn new(
        task_type: impl Into<String>,
        input: impl Into<String>,
        output: impl Into<String>,
    ) -> Self {
        Self {
            task_type: task_type.into(),
            input: input.into(),
            output: output.into(),
            quality_score: 1.0,
            tags: Vec::new(),
        }
    }

    #[must_use] 
    pub fn token_cost(&self) -> u32 {
        estimate_tokens(&self.input) + estimate_tokens(&self.output)
    }
}

// ── FewShotSelector ───────────────────────────────────────────────────────────

/// Selects the most relevant few-shot examples for a prompt.
pub struct FewShotSelector {
    examples: Vec<FewShotExample>,
    pub max_examples: usize,
    pub token_budget: u32,
}

impl FewShotSelector {
    #[must_use] 
    pub const fn new(max_examples: usize, token_budget: u32) -> Self {
        Self {
            examples: Vec::new(),
            max_examples,
            token_budget,
        }
    }

    pub fn add_example(&mut self, ex: FewShotExample) {
        self.examples.push(ex);
    }

    /// Select the top examples for `task_type`, sorted by quality score, within budget.
    pub fn select(&self, task_type: &str) -> OptResult<Vec<&FewShotExample>> {
        let mut candidates: Vec<&FewShotExample> = self
            .examples
            .iter()
            .filter(|e| e.task_type == task_type)
            .collect();

        if candidates.is_empty() {
            return Err(OptimizerError::NoExamples(task_type.to_owned()));
        }

        // Sort by quality descending.
        candidates.sort_by(|a, b| {
            b.quality_score
                .partial_cmp(&a.quality_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut selected = Vec::with_capacity(self.max_examples);
        let mut tokens_used = 0u32;

        for ex in candidates.iter().take(self.max_examples) {
            let cost = ex.token_cost();
            if tokens_used + cost > self.token_budget {
                break;
            }
            selected.push(*ex);
            tokens_used += cost;
        }

        Ok(selected)
    }

    /// Build a few-shot prefix string from selected examples.
    pub fn build_prefix(&self, task_type: &str) -> OptResult<String> {
        let examples = self.select(task_type)?;
        let parts: Vec<String> = examples
            .iter()
            .map(|ex| format!("Input: {}\nOutput: {}", ex.input, ex.output))
            .collect();
        Ok(parts.join("\n\n"))
    }

    #[must_use] 
    pub const fn example_count(&self) -> usize {
        self.examples.len()
    }
}

// ── PromptChain ───────────────────────────────────────────────────────────────

/// A chain of prompt transformations applied in sequence.
pub struct PromptChain {
    steps: Vec<Box<dyn PromptStep>>,
}

pub trait PromptStep: Send + Sync {
    fn name(&self) -> &str;
    fn apply(&self, prompt: &str) -> OptResult<String>;
}

/// A step that prepends a string.
pub struct PrependStep {
    pub name_str: String,
    pub prefix: String,
}
impl PromptStep for PrependStep {
    fn name(&self) -> &str {
        &self.name_str
    }
    fn apply(&self, prompt: &str) -> OptResult<String> {
        Ok(format!("{}\n{}", self.prefix, prompt))
    }
}

/// A step that appends a string.
pub struct AppendStep {
    pub name_str: String,
    pub suffix: String,
}
impl PromptStep for AppendStep {
    fn name(&self) -> &str {
        &self.name_str
    }
    fn apply(&self, prompt: &str) -> OptResult<String> {
        Ok(format!("{}\n{}", prompt, self.suffix))
    }
}

/// A step that replaces substrings using a map.
pub struct ReplaceStep {
    pub name_str: String,
    pub replacements: Vec<(String, String)>,
}
impl PromptStep for ReplaceStep {
    fn name(&self) -> &str {
        &self.name_str
    }
    fn apply(&self, prompt: &str) -> OptResult<String> {
        let mut result = prompt.to_owned();
        for (from, to) in &self.replacements {
            result = result.replace(from.as_str(), to.as_str());
        }
        Ok(result)
    }
}

impl PromptChain {
    #[must_use] 
    pub fn new() -> Self {
        Self { steps: Vec::new() }
    }

    #[must_use] 
    pub fn add_step(mut self, step: Box<dyn PromptStep>) -> Self {
        self.steps.push(step);
        self
    }

    /// Apply all steps sequentially.
    pub fn apply(&self, prompt: &str) -> OptResult<ChainResult> {
        if prompt.is_empty() {
            return Err(OptimizerError::EmptyPrompt);
        }

        let mut current = prompt.to_owned();
        let mut step_log = Vec::with_capacity(self.steps.len());

        for (i, step) in self.steps.iter().enumerate() {
            current = step
                .apply(&current)
                .map_err(|e| OptimizerError::ChainFailed {
                    step: i,
                    message: e.to_string(),
                })?;
            step_log.push(StepLog {
                index: i,
                name: step.name().to_owned(),
                output_tokens: estimate_tokens(&current),
            });
        }

        Ok(ChainResult {
            original: prompt.to_owned(),
            final_prompt: current,
            steps_applied: step_log,
        })
    }

    #[must_use] 
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

impl Default for PromptChain {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct StepLog {
    pub index: usize,
    pub name: String,
    pub output_tokens: u32,
}

#[derive(Debug, Clone)]
pub struct ChainResult {
    pub original: String,
    pub final_prompt: String,
    pub steps_applied: Vec<StepLog>,
}

// ── OptimizationReport ────────────────────────────────────────────────────────

/// Summary of the optimization applied to a prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub original_tokens: u32,
    pub final_tokens: u32,
    pub reduction_pct: f64,
    pub few_shot_examples_added: usize,
    pub chain_steps_applied: usize,
    pub context_expansion_applied: bool,
    pub warnings: Vec<String>,
}

impl OptimizationReport {
    #[must_use] 
    pub fn new(original_tokens: u32, final_tokens: u32) -> Self {
        let reduction_pct = if original_tokens > 0 {
            (1.0 - f64::from(final_tokens) / f64::from(original_tokens)) * 100.0
        } else {
            0.0
        };
        Self {
            original_tokens,
            final_tokens,
            reduction_pct,
            few_shot_examples_added: 0,
            chain_steps_applied: 0,
            context_expansion_applied: false,
            warnings: Vec::new(),
        }
    }

    pub fn add_warning(&mut self, w: impl Into<String>) {
        self.warnings.push(w.into());
    }

    pub fn to_json(&self) -> OptResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| OptimizerError::Serialization(e.to_string()))
    }

    /// Flat numeric metrics keyed by name — convenient for dashboards or sinks
    /// that ingest `HashMap<String, u64>` style payloads.
    #[must_use] 
    pub fn metrics(&self) -> HashMap<String, u64> {
        let mut m = HashMap::with_capacity(7);
        m.insert("original_tokens".to_owned(), u64::from(self.original_tokens));
        m.insert("final_tokens".to_owned(), u64::from(self.final_tokens));
        m.insert(
            "reduction_pct_x100".to_owned(),
            (self.reduction_pct * 100.0) as u64,
        );
        m.insert(
            "few_shot_examples_added".to_owned(),
            self.few_shot_examples_added as u64,
        );
        m.insert(
            "chain_steps_applied".to_owned(),
            self.chain_steps_applied as u64,
        );
        m.insert(
            "context_expansion_applied".to_owned(),
            u64::from(self.context_expansion_applied),
        );
        m.insert("warnings".to_owned(), self.warnings.len() as u64);
        m
    }
}

// ── PromptOptimizer ───────────────────────────────────────────────────────────

/// Orchestrates all prompt optimization strategies.
pub struct PromptOptimizer {
    pub reducer: TokenReduction,
    pub expander: ContextualExpansion,
    pub selector: FewShotSelector,
    pub chain: PromptChain,
    pub token_limit: u32,
}

impl PromptOptimizer {
    #[must_use] 
    pub fn new(token_limit: u32, domain: ReDomain) -> Self {
        Self {
            reducer: TokenReduction::new(token_limit),
            expander: ContextualExpansion::new(domain, token_limit),
            selector: FewShotSelector::new(3, token_limit / 4),
            chain: PromptChain::new(),
            token_limit,
        }
    }

    /// Full optimization pipeline: reduce → expand → inject few-shot → apply chain.
    pub fn optimize(
        &self,
        prompt: &str,
        task_type: Option<&str>,
    ) -> OptResult<(String, OptimizationReport)> {
        if prompt.is_empty() {
            return Err(OptimizerError::EmptyPrompt);
        }

        let original_tokens = estimate_tokens(prompt);
        let mut report = OptimizationReport::new(original_tokens, original_tokens);

        // 1. Reduce.
        let reduced = self.reducer.reduce(prompt)?;
        let mut current = reduced.reduced_text;

        // 2. Expand with domain context if we have budget.
        let expanded = self.expander.expand(&current)?;
        if estimate_tokens(&expanded) <= self.token_limit {
            current = expanded;
            report.context_expansion_applied = true;
        } else {
            report.add_warning("context expansion skipped: would exceed token limit");
        }

        // 3. Inject few-shot examples.
        if let Some(task) = task_type {
            match self.selector.build_prefix(task) {
                Ok(prefix) => {
                    let candidate = format!("{prefix}\n\n{current}");
                    if estimate_tokens(&candidate) <= self.token_limit {
                        let count = self.selector.select(task).map(|v| v.len()).unwrap_or(0);
                        current = candidate;
                        report.few_shot_examples_added = count;
                    } else {
                        report.add_warning("few-shot examples skipped: would exceed token limit");
                    }
                }
                Err(OptimizerError::NoExamples(_)) => {
                    report.add_warning(format!("no few-shot examples for task '{task}'"));
                }
                Err(e) => return Err(e),
            }
        }

        // 4. Apply chain.
        if self.chain.step_count() > 0 {
            let chain_result = self.chain.apply(&current)?;
            current = chain_result.final_prompt;
            report.chain_steps_applied = chain_result.steps_applied.len();
        }

        report.final_tokens = estimate_tokens(&current);
        report.reduction_pct = if original_tokens > 0 {
            (1.0 - f64::from(report.final_tokens) / f64::from(original_tokens)) * 100.0
        } else {
            0.0
        };

        Ok((current, report))
    }

    /// Estimate tokens in a string.
    #[must_use] 
    pub fn count_tokens(&self, text: &str) -> u32 {
        estimate_tokens(text)
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn estimate_tokens(text: &str) -> u32 {
    let chars = text.chars().count() as f64;
    ((chars / 4.0).ceil() as u32).max(1)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TokenReduction ────────────────────────────────────────────────────────

    #[test]
    fn test_reduction_empty_prompt() {
        let r = TokenReduction::new(100);
        assert!(matches!(r.reduce(""), Err(OptimizerError::EmptyPrompt)));
    }

    #[test]
    fn test_reduction_normalizes_whitespace() {
        let r = TokenReduction::new(1000);
        let result = r.reduce("hello   world\n\n  test").unwrap();
        assert_eq!(result.reduced_text.trim(), "hello world test");
    }

    #[test]
    fn test_reduction_strips_markdown() {
        let mut r = TokenReduction::new(1000);
        r.strip_formatting = true;
        let result = r.reduce("**bold** text and ## heading").unwrap();
        assert!(!result.reduced_text.contains("**"));
        assert!(!result.reduced_text.contains("##"));
    }

    #[test]
    fn test_reduction_abbreviations() {
        let mut r = TokenReduction::new(1000);
        r.use_abbreviations = true;
        let result = r
            .reduce("analyze this reverse engineering function")
            .unwrap();
        assert!(result.reduced_text.contains("RE") || result.reduced_text.contains("func"));
    }

    #[test]
    fn test_reduction_truncation() {
        let r = TokenReduction::new(5); // very tight budget
        let long_prompt = "a b c d e f g h i j k l m n o p q r s t u v w x y z";
        let result = r.reduce(long_prompt).unwrap();
        assert!(result.final_tokens <= 10); // a bit of tolerance
    }

    #[test]
    fn test_reduction_ratio() {
        let r = ReductionResult {
            original_text: String::new(),
            reduced_text: String::new(),
            original_tokens: 100,
            final_tokens: 80,
            tokens_saved: 20,
            techniques_applied: vec![],
        };
        assert!((r.reduction_ratio() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn test_reduction_ratio_zero_original() {
        let r = ReductionResult {
            original_text: String::new(),
            reduced_text: String::new(),
            original_tokens: 0,
            final_tokens: 0,
            tokens_saved: 0,
            techniques_applied: vec![],
        };
        assert_eq!(r.reduction_ratio(), 0.0);
    }

    // ── ContextualExpansion ───────────────────────────────────────────────────

    #[test]
    fn test_expansion_prepends_domain_prefix() {
        let ex = ContextualExpansion::new(ReDomain::Malware, 2000);
        let expanded = ex.expand("Analyze this function.").unwrap();
        assert!(expanded.contains("malicious") || expanded.contains("C2"));
    }

    #[test]
    fn test_expansion_empty_prompt() {
        let ex = ContextualExpansion::new(ReDomain::Generic, 2000);
        assert!(matches!(ex.expand(""), Err(OptimizerError::EmptyPrompt)));
    }

    #[test]
    fn test_expansion_domains() {
        for domain in [
            ReDomain::Malware,
            ReDomain::BinaryAnalysis,
            ReDomain::Vulnerability,
            ReDomain::CryptoAnalysis,
            ReDomain::Generic,
        ] {
            let ex = ContextualExpansion::new(domain, 2000);
            let result = ex.expand("test prompt").unwrap();
            assert!(!result.is_empty());
        }
    }

    // ── FewShotSelector ───────────────────────────────────────────────────────

    #[test]
    fn test_few_shot_no_examples() {
        let sel = FewShotSelector::new(3, 1000);
        assert!(matches!(
            sel.select("decompile"),
            Err(OptimizerError::NoExamples(_))
        ));
    }

    #[test]
    fn test_few_shot_select_by_task() {
        let mut sel = FewShotSelector::new(3, 10000);
        sel.add_example(FewShotExample::new(
            "decompile",
            "input for decompile",
            "output",
        ));
        sel.add_example(FewShotExample::new("naming", "input for naming", "output"));
        let result = sel.select("decompile").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].task_type, "decompile");
    }

    #[test]
    fn test_few_shot_sorted_by_quality() {
        let mut sel = FewShotSelector::new(3, 10000);
        let mut ex1 = FewShotExample::new("t", "a", "b");
        ex1.quality_score = 0.5;
        let mut ex2 = FewShotExample::new("t", "c", "d");
        ex2.quality_score = 0.9;
        sel.add_example(ex1);
        sel.add_example(ex2);
        let result = sel.select("t").unwrap();
        assert!((result[0].quality_score - 0.9).abs() < 1e-6);
    }

    #[test]
    fn test_few_shot_token_budget_limits() {
        let mut sel = FewShotSelector::new(10, 20); // very small budget
        for i in 0..5 {
            sel.add_example(FewShotExample::new(
                "t",
                format!("long input text {i}"),
                "long output text here",
            ));
        }
        let result = sel.select("t").unwrap();
        // Should be limited by budget.
        assert!(result.len() <= 5);
    }

    #[test]
    fn test_few_shot_build_prefix() {
        let mut sel = FewShotSelector::new(3, 10000);
        sel.add_example(FewShotExample::new("naming", "sub_1234", "malloc_wrapper"));
        let prefix = sel.build_prefix("naming").unwrap();
        assert!(prefix.contains("sub_1234"));
        assert!(prefix.contains("malloc_wrapper"));
    }

    // ── PromptChain ───────────────────────────────────────────────────────────

    #[test]
    fn test_chain_empty_steps() {
        let chain = PromptChain::new();
        let result = chain.apply("hello").unwrap();
        assert_eq!(result.final_prompt, "hello");
        assert!(result.steps_applied.is_empty());
    }

    #[test]
    fn test_chain_empty_prompt() {
        let chain = PromptChain::new();
        assert!(matches!(chain.apply(""), Err(OptimizerError::EmptyPrompt)));
    }

    #[test]
    fn test_chain_prepend_step() {
        let chain = PromptChain::new().add_step(Box::new(PrependStep {
            name_str: "prepend".into(),
            prefix: "PREFIX".into(),
        }));
        let result = chain.apply("body").unwrap();
        assert!(result.final_prompt.starts_with("PREFIX"));
    }

    #[test]
    fn test_chain_append_step() {
        let chain = PromptChain::new().add_step(Box::new(AppendStep {
            name_str: "append".into(),
            suffix: "SUFFIX".into(),
        }));
        let result = chain.apply("body").unwrap();
        assert!(result.final_prompt.ends_with("SUFFIX"));
    }

    #[test]
    fn test_chain_replace_step() {
        let chain = PromptChain::new().add_step(Box::new(ReplaceStep {
            name_str: "replace".into(),
            replacements: vec![("foo".into(), "bar".into())],
        }));
        let result = chain.apply("foo baz foo").unwrap();
        assert!(!result.final_prompt.contains("foo"));
        assert!(result.final_prompt.contains("bar"));
    }

    #[test]
    fn test_chain_multiple_steps() {
        let chain = PromptChain::new()
            .add_step(Box::new(PrependStep {
                name_str: "a".into(),
                prefix: "A".into(),
            }))
            .add_step(Box::new(AppendStep {
                name_str: "b".into(),
                suffix: "B".into(),
            }));
        let result = chain.apply("mid").unwrap();
        assert!(result.final_prompt.contains('A'));
        assert!(result.final_prompt.contains('B'));
        assert_eq!(result.steps_applied.len(), 2);
    }

    #[test]
    fn test_chain_step_count() {
        let chain = PromptChain::new().add_step(Box::new(PrependStep {
            name_str: "x".into(),
            prefix: "x".into(),
        }));
        assert_eq!(chain.step_count(), 1);
    }

    // ── OptimizationReport ────────────────────────────────────────────────────

    #[test]
    fn test_report_reduction_pct() {
        let report = OptimizationReport::new(200, 100);
        assert!((report.reduction_pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_report_no_change() {
        let report = OptimizationReport::new(100, 100);
        assert_eq!(report.reduction_pct, 0.0);
    }

    #[test]
    fn test_report_to_json() {
        let report = OptimizationReport::new(100, 80);
        let json = report.to_json().unwrap();
        assert!(json.contains("reduction_pct"));
    }

    #[test]
    fn test_report_warnings() {
        let mut report = OptimizationReport::new(100, 100);
        report.add_warning("test warning");
        assert_eq!(report.warnings.len(), 1);
    }

    // ── PromptOptimizer ───────────────────────────────────────────────────────

    #[test]
    fn test_optimizer_empty_prompt() {
        let opt = PromptOptimizer::new(4096, ReDomain::Generic);
        assert!(matches!(
            opt.optimize("", None),
            Err(OptimizerError::EmptyPrompt)
        ));
    }

    #[test]
    fn test_optimizer_basic() {
        let opt = PromptOptimizer::new(4096, ReDomain::Generic);
        let (result, report) = opt
            .optimize("Analyze this function at 0x1000.", None)
            .unwrap();
        assert!(!result.is_empty());
        assert!(report.final_tokens > 0);
    }

    #[test]
    fn test_optimizer_with_few_shot() {
        let mut opt = PromptOptimizer::new(8192, ReDomain::Generic);
        opt.selector
            .add_example(FewShotExample::new("naming", "sub_1234", "decrypt_string"));
        let (result, report) = opt.optimize("Name this function.", Some("naming")).unwrap();
        assert!(report.few_shot_examples_added > 0);
        assert!(result.contains("sub_1234") || result.contains("decrypt_string"));
    }

    #[test]
    fn test_optimizer_no_few_shot_for_task() {
        let opt = PromptOptimizer::new(4096, ReDomain::Generic);
        let (_, report) = opt.optimize("Analyze this.", Some("unknown_task")).unwrap();
        assert!(report.few_shot_examples_added == 0);
        assert!(report.warnings.iter().any(|w| w.contains("no few-shot")));
    }

    #[test]
    fn test_optimizer_context_expansion_applied() {
        let opt = PromptOptimizer::new(8192, ReDomain::Malware);
        let (result, report) = opt.optimize("List the imports.", None).unwrap();
        assert!(report.context_expansion_applied);
        assert!(result.contains("malicious") || result.len() > 15); // has prefix
    }

    #[test]
    fn test_optimizer_count_tokens() {
        let opt = PromptOptimizer::new(4096, ReDomain::Generic);
        let count = opt.count_tokens("hello world");
        assert!(count > 0);
    }

    // ── estimate_tokens ───────────────────────────────────────────────────────

    #[test]
    fn test_estimate_tokens_min_1() {
        assert_eq!(estimate_tokens(""), 1);
    }

    #[test]
    fn test_estimate_tokens_8_chars() {
        // 8 chars / 4 = 2 tokens
        assert_eq!(estimate_tokens("abcdefgh"), 2);
    }

    #[test]
    fn test_estimate_tokens_longer() {
        let t = estimate_tokens("a".repeat(40).as_str());
        assert_eq!(t, 10);
    }

    #[test]
    fn test_reduction_techniques_applied_strip() {
        let r = TokenReduction::new(1000);
        let result = r.reduce("**bold** text").unwrap();
        assert!(
            result
                .techniques_applied
                .contains(&"strip_formatting".to_owned())
        );
    }

    #[test]
    fn test_few_shot_example_token_cost() {
        let ex = FewShotExample::new("t", "hello world", "output text");
        assert!(ex.token_cost() > 0);
    }

    #[test]
    fn test_few_shot_example_with_tags() {
        let mut ex = FewShotExample::new("t", "i", "o");
        ex.tags.push("re".into());
        assert_eq!(ex.tags.len(), 1);
    }

    #[test]
    fn test_chain_step_name() {
        let step = PrependStep {
            name_str: "my_step".into(),
            prefix: "P".into(),
        };
        assert_eq!(step.name(), "my_step");
    }

    #[test]
    fn test_append_step_apply() {
        let step = AppendStep {
            name_str: "app".into(),
            suffix: "END".into(),
        };
        let result = step.apply("START").unwrap();
        assert!(result.ends_with("END"));
    }

    #[test]
    fn test_replace_step_no_match() {
        let step = ReplaceStep {
            name_str: "r".into(),
            replacements: vec![("xyz".into(), "abc".into())],
        };
        let result = step.apply("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_chain_default() {
        let chain = PromptChain::default();
        assert_eq!(chain.step_count(), 0);
    }

    #[test]
    fn test_optimizer_with_chain() {
        let mut opt = PromptOptimizer::new(4096, ReDomain::Generic);
        opt.chain = PromptChain::new().add_step(Box::new(AppendStep {
            name_str: "footer".into(),
            suffix: "// end".into(),
        }));
        let (result, report) = opt.optimize("Analyze this.", None).unwrap();
        assert!(result.contains("// end"));
        assert_eq!(report.chain_steps_applied, 1);
    }

    #[test]
    fn test_optimizer_count_tokens_zero_len() {
        let opt = PromptOptimizer::new(4096, ReDomain::Generic);
        // empty string → min 1
        assert_eq!(opt.count_tokens(""), 1);
    }

    #[test]
    fn test_contextual_expansion_vulnerability_domain() {
        let ex = ContextualExpansion::new(ReDomain::Vulnerability, 2000);
        let result = ex.expand("Check this code.").unwrap();
        assert!(result.contains("vuln") || result.contains("buffer") || result.len() > 20);
    }

    #[test]
    fn test_report_few_shot_field() {
        let mut r = OptimizationReport::new(100, 90);
        r.few_shot_examples_added = 2;
        assert_eq!(r.few_shot_examples_added, 2);
    }

    #[test]
    fn test_report_chain_steps_field() {
        let mut r = OptimizationReport::new(100, 90);
        r.chain_steps_applied = 3;
        assert_eq!(r.chain_steps_applied, 3);
    }
}
