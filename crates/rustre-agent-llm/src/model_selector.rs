//! `model_selector` — Select the best LLM model for a task given capability,
//! latency, and budget constraints.
//!
//! Defines [`ModelCapability`], [`ModelProfile`], and [`ModelSelector`] with a
//! built-in catalogue of 11 models.  The selector ranks candidates by
//! capability coverage and estimated cost, returning a sorted list.

use std::fmt;

// ── ModelCapability ───────────────────────────────────────────────────────────

/// Capabilities that a model may support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelCapability {
    /// Complex multi-step reasoning tasks.
    Reasoning,
    /// Source-code generation and completion.
    CodeGeneration,
    /// Condensing long documents into summaries.
    Summarization,
    /// Binary (yes/no) classification.
    ClassificationBinary,
    /// Extracting structured information from text.
    InformationExtraction,
    /// Calling external tools / structured JSON output.
    FunctionCalling,
    /// Handling very long prompts (> 100 k tokens).
    LongContext,
}

impl ModelCapability {
    /// Return a short kebab-case identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reasoning => "reasoning",
            Self::CodeGeneration => "code-generation",
            Self::Summarization => "summarization",
            Self::ClassificationBinary => "classification-binary",
            Self::InformationExtraction => "information-extraction",
            Self::FunctionCalling => "function-calling",
            Self::LongContext => "long-context",
        }
    }
}

impl fmt::Display for ModelCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── ModelProvider ─────────────────────────────────────────────────────────────

/// The organisation or infrastructure that serves the model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ModelProvider {
    /// Anthropic (Claude family).
    Anthropic,
    /// `OpenAI` (GPT family).
    OpenAI,
    /// Google (Gemini / `PaLM` family).
    Google,
    /// A locally-hosted model (e.g. via Ollama, llama.cpp).
    Local,
    /// Any other provider.
    Custom(String),
}

impl fmt::Display for ModelProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anthropic => write!(f, "Anthropic"),
            Self::OpenAI => write!(f, "OpenAI"),
            Self::Google => write!(f, "Google"),
            Self::Local => write!(f, "Local"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ── ModelProfile ──────────────────────────────────────────────────────────────

/// A complete description of a single LLM model.
#[derive(Debug, Clone)]
pub struct ModelProfile {
    /// API model identifier, e.g. `"claude-sonnet-4-6"`.
    pub id: String,
    /// Human-friendly name.
    pub display_name: String,
    /// Serving provider.
    pub provider: ModelProvider,
    /// Maximum context window in tokens (input + output combined).
    pub context_window: u32,
    /// Maximum number of output tokens per request.
    pub output_limit: u32,
    /// Supported capability set.
    pub capabilities: Vec<ModelCapability>,
    /// Price per 1 000 input tokens in USD.
    pub cost_per_1k_input_tokens: f64,
    /// Price per 1 000 output tokens in USD.
    pub cost_per_1k_output_tokens: f64,
    /// Approximate median round-trip latency in milliseconds.
    pub avg_latency_ms: u32,
}

impl ModelProfile {
    /// Return `true` if this model has all of the requested capabilities.
    #[must_use]
    pub fn has_all_capabilities(&self, required: &[ModelCapability]) -> bool {
        required.iter().all(|cap| self.capabilities.contains(cap))
    }

    /// Return the number of the requested capabilities that this model has.
    #[must_use]
    pub fn capability_coverage(&self, required: &[ModelCapability]) -> usize {
        required.iter().filter(|cap| self.capabilities.contains(cap)).count()
    }

    /// Estimate the cost in USD for a request with the given token counts.
    #[must_use]
    pub fn estimate_cost(&self, input_tokens: u32, output_tokens: u32) -> f64 {
        estimate_cost(self, input_tokens, output_tokens)
    }
}

impl fmt::Display for ModelProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) — {}k ctx, ${:.4}/1k in, ${:.4}/1k out, ~{}ms",
            self.display_name,
            self.provider,
            self.context_window / 1000,
            self.cost_per_1k_input_tokens,
            self.cost_per_1k_output_tokens,
            self.avg_latency_ms,
        )
    }
}

// ── Cost estimator ────────────────────────────────────────────────────────────

/// Estimate the USD cost of a request.
#[must_use]
pub fn estimate_cost(model: &ModelProfile, input_tokens: u32, output_tokens: u32) -> f64 {
    let input_cost = (f64::from(input_tokens) / 1000.0) * model.cost_per_1k_input_tokens;
    let output_cost = (f64::from(output_tokens) / 1000.0) * model.cost_per_1k_output_tokens;
    input_cost + output_cost
}

// ── Built-in model catalogue ──────────────────────────────────────────────────

fn builtin_anthropic_models() -> Vec<ModelProfile> {
    use ModelCapability::{Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling, LongContext};
    vec![
        ModelProfile {
            id: "claude-sonnet-4-6".into(),
            display_name: "Claude Sonnet 4.6".into(),
            provider: ModelProvider::Anthropic,
            context_window: 200_000,
            output_limit: 8_192,
            capabilities: vec![Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling, LongContext],
            cost_per_1k_input_tokens: 0.003,
            cost_per_1k_output_tokens: 0.015,
            avg_latency_ms: 2_000,
        },
        ModelProfile {
            id: "claude-opus-4-8".into(),
            display_name: "Claude Opus 4.8".into(),
            provider: ModelProvider::Anthropic,
            context_window: 200_000,
            output_limit: 8_192,
            capabilities: vec![Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling, LongContext],
            cost_per_1k_input_tokens: 0.015,
            cost_per_1k_output_tokens: 0.075,
            avg_latency_ms: 5_000,
        },
        ModelProfile {
            id: "claude-haiku-3-5".into(),
            display_name: "Claude Haiku 3.5".into(),
            provider: ModelProvider::Anthropic,
            context_window: 200_000,
            output_limit: 8_192,
            capabilities: vec![Summarization, ClassificationBinary, InformationExtraction, FunctionCalling, LongContext],
            cost_per_1k_input_tokens: 0.0008,
            cost_per_1k_output_tokens: 0.004,
            avg_latency_ms: 500,
        },
    ]
}

fn builtin_openai_models() -> Vec<ModelProfile> {
    use ModelCapability::{Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling};
    vec![
        ModelProfile {
            id: "gpt-4o".into(),
            display_name: "GPT-4o".into(),
            provider: ModelProvider::OpenAI,
            context_window: 128_000,
            output_limit: 4_096,
            capabilities: vec![Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling],
            cost_per_1k_input_tokens: 0.005,
            cost_per_1k_output_tokens: 0.015,
            avg_latency_ms: 3_000,
        },
        ModelProfile {
            id: "gpt-4o-mini".into(),
            display_name: "GPT-4o mini".into(),
            provider: ModelProvider::OpenAI,
            context_window: 128_000,
            output_limit: 16_384,
            capabilities: vec![CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling],
            cost_per_1k_input_tokens: 0.000_15,
            cost_per_1k_output_tokens: 0.0006,
            avg_latency_ms: 700,
        },
        ModelProfile {
            id: "o1-preview".into(),
            display_name: "o1 Preview".into(),
            provider: ModelProvider::OpenAI,
            context_window: 128_000,
            output_limit: 32_768,
            capabilities: vec![Reasoning, CodeGeneration, InformationExtraction],
            cost_per_1k_input_tokens: 0.015,
            cost_per_1k_output_tokens: 0.06,
            avg_latency_ms: 15_000,
        },
    ]
}

fn builtin_google_models() -> Vec<ModelProfile> {
    use ModelCapability::{Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling, LongContext};
    vec![
        ModelProfile {
            id: "gemini-1.5-pro".into(),
            display_name: "Gemini 1.5 Pro".into(),
            provider: ModelProvider::Google,
            context_window: 1_000_000,
            output_limit: 8_192,
            capabilities: vec![Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction, FunctionCalling, LongContext],
            cost_per_1k_input_tokens: 0.003_5,
            cost_per_1k_output_tokens: 0.010_5,
            avg_latency_ms: 4_000,
        },
        ModelProfile {
            id: "gemini-1.5-flash".into(),
            display_name: "Gemini 1.5 Flash".into(),
            provider: ModelProvider::Google,
            context_window: 1_000_000,
            output_limit: 8_192,
            capabilities: vec![Summarization, ClassificationBinary, InformationExtraction, FunctionCalling, LongContext],
            cost_per_1k_input_tokens: 0.000_35,
            cost_per_1k_output_tokens: 0.001_05,
            avg_latency_ms: 800,
        },
    ]
}

fn builtin_local_models() -> Vec<ModelProfile> {
    use ModelCapability::{Reasoning, CodeGeneration, Summarization, ClassificationBinary, InformationExtraction};
    vec![
        ModelProfile {
            id: "llama-3-70b".into(),
            display_name: "Llama 3 70B".into(),
            provider: ModelProvider::Local,
            context_window: 8_192,
            output_limit: 4_096,
            capabilities: vec![Reasoning, CodeGeneration, Summarization, InformationExtraction],
            cost_per_1k_input_tokens: 0.0,
            cost_per_1k_output_tokens: 0.0,
            avg_latency_ms: 8_000,
        },
        ModelProfile {
            id: "llama-3-8b".into(),
            display_name: "Llama 3 8B".into(),
            provider: ModelProvider::Local,
            context_window: 8_192,
            output_limit: 4_096,
            capabilities: vec![Summarization, ClassificationBinary, InformationExtraction],
            cost_per_1k_input_tokens: 0.0,
            cost_per_1k_output_tokens: 0.0,
            avg_latency_ms: 1_500,
        },
        ModelProfile {
            id: "mistral-7b-instruct".into(),
            display_name: "Mistral 7B Instruct".into(),
            provider: ModelProvider::Local,
            context_window: 32_768,
            output_limit: 4_096,
            capabilities: vec![CodeGeneration, Summarization, ClassificationBinary, InformationExtraction],
            cost_per_1k_input_tokens: 0.0,
            cost_per_1k_output_tokens: 0.0,
            avg_latency_ms: 2_000,
        },
    ]
}

/// Return the built-in catalogue of 11 well-known models.
#[must_use]
pub fn builtin_models() -> Vec<ModelProfile> {
    let mut models = builtin_anthropic_models();
    models.extend(builtin_openai_models());
    models.extend(builtin_google_models());
    models.extend(builtin_local_models());
    models
}

// ── ModelSelector ─────────────────────────────────────────────────────────────

/// Selects the most appropriate LLM model(s) for a task.
#[derive(Debug, Clone)]
pub struct ModelSelector {
    /// Available models to consider.
    models: Vec<ModelProfile>,
}

impl ModelSelector {
    /// Create a new `ModelSelector` using the built-in model catalogue.
    #[must_use]
    pub fn new() -> Self {
        Self { models: builtin_models() }
    }

    /// Create a `ModelSelector` with a custom model list.
    #[must_use]
    pub const fn with_models(models: Vec<ModelProfile>) -> Self {
        Self { models }
    }

    /// Add a model to the selector's catalogue.
    pub fn add_model(&mut self, model: ModelProfile) {
        self.models.push(model);
    }

    /// Return all models in the catalogue.
    #[must_use]
    pub fn all_models(&self) -> &[ModelProfile] {
        &self.models
    }

    /// Return a model by its ID, or `None` if not found.
    #[must_use]
    pub fn find_by_id(&self, id: &str) -> Option<&ModelProfile> {
        self.models.iter().find(|m| m.id == id)
    }

    /// Select the best models for a task.
    ///
    /// Filters by:
    /// 1. All `caps_needed` must be present.
    /// 2. `max_latency` — if specified, models above this threshold are excluded.
    /// 3. `budget` — if specified, a typical 1 000-token request must cost less
    ///    than this amount (input=800 tokens, output=200 tokens).
    ///
    /// Remaining candidates are ranked by:
    /// 1. Full capability coverage (higher = better).
    /// 2. Estimated cost (lower = better).
    /// 3. Latency (lower = better) as a tie-breaker.
    #[must_use]
    pub fn select_best_for_task(
        &self,
        caps_needed: &[ModelCapability],
        budget: Option<f64>,
        max_latency: Option<u32>,
    ) -> Vec<&ModelProfile> {
        let typical_input = 800u32;
        let typical_output = 200u32;

        let mut candidates: Vec<&ModelProfile> = self
            .models
            .iter()
            .filter(|m| m.has_all_capabilities(caps_needed))
            .filter(|m| {
                max_latency.is_none_or(|limit| m.avg_latency_ms <= limit)
            })
            .filter(|m| {
                budget.is_none_or(|budget_usd| {
                    m.estimate_cost(typical_input, typical_output) <= budget_usd
                })
            })
            .collect();

        // Sort: primary cost ascending, secondary latency ascending
        candidates.sort_by(|a, b| {
            let cost_a = a.estimate_cost(typical_input, typical_output);
            let cost_b = b.estimate_cost(typical_input, typical_output);
            cost_a
                .partial_cmp(&cost_b)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.avg_latency_ms.cmp(&b.avg_latency_ms))
        });
        candidates
    }

    /// Return models from the given provider.
    #[must_use]
    pub fn models_by_provider(&self, provider: &ModelProvider) -> Vec<&ModelProfile> {
        self.models.iter().filter(|m| &m.provider == provider).collect()
    }

    /// Return models that fit within the given monthly token budget.
    ///
    /// `monthly_tokens` is split evenly between input and output.
    #[must_use]
    pub fn models_within_monthly_budget(
        &self,
        monthly_usd: f64,
        monthly_tokens: u32,
    ) -> Vec<&ModelProfile> {
        let input_tokens = monthly_tokens / 2;
        let output_tokens = monthly_tokens - input_tokens;
        self.models
            .iter()
            .filter(|m| m.estimate_cost(input_tokens, output_tokens) <= monthly_usd)
            .collect()
    }
}

impl Default for ModelSelector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_models_count() {
        let models = builtin_models();
        assert!(models.len() >= 10, "expected at least 10 built-in models");
    }

    #[test]
    fn test_capability_as_str() {
        assert_eq!(ModelCapability::Reasoning.as_str(), "reasoning");
        assert_eq!(ModelCapability::CodeGeneration.as_str(), "code-generation");
    }

    #[test]
    fn test_model_has_all_capabilities_true() {
        let selector = ModelSelector::new();
        let model = selector.find_by_id("claude-sonnet-4-6").unwrap();
        assert!(model.has_all_capabilities(&[ModelCapability::Reasoning, ModelCapability::CodeGeneration]));
    }

    #[test]
    fn test_model_has_all_capabilities_false() {
        let selector = ModelSelector::new();
        // Haiku doesn't have Reasoning
        let model = selector.find_by_id("claude-haiku-3-5").unwrap();
        assert!(!model.has_all_capabilities(&[ModelCapability::Reasoning]));
    }

    #[test]
    fn test_estimate_cost_zero_for_local() {
        let selector = ModelSelector::new();
        let model = selector.find_by_id("llama-3-70b").unwrap();
        let cost = model.estimate_cost(10_000, 5_000);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn test_estimate_cost_non_zero_for_paid() {
        let model = builtin_models()
            .into_iter()
            .find(|m| m.id == "gpt-4o")
            .unwrap();
        let cost = estimate_cost(&model, 1_000, 1_000);
        assert!(cost > 0.0);
    }

    #[test]
    fn test_select_best_returns_models_with_all_caps() {
        let selector = ModelSelector::new();
        let caps = vec![ModelCapability::Reasoning, ModelCapability::FunctionCalling];
        let results = selector.select_best_for_task(&caps, None, None);
        assert!(!results.is_empty());
        for m in &results {
            assert!(m.has_all_capabilities(&caps));
        }
    }

    #[test]
    fn test_select_best_excludes_over_budget() {
        let selector = ModelSelector::new();
        // Budget so tight only free (local) models qualify
        let caps = vec![ModelCapability::Summarization];
        let results = selector.select_best_for_task(&caps, Some(0.0), None);
        for m in &results {
            let cost = m.estimate_cost(800, 200);
            assert!(cost <= 0.0 + 1e-9, "cost {cost} should be 0 for local models");
        }
    }

    #[test]
    fn test_select_best_respects_max_latency() {
        let selector = ModelSelector::new();
        let caps = vec![ModelCapability::Summarization];
        let results = selector.select_best_for_task(&caps, None, Some(1000));
        for m in &results {
            assert!(m.avg_latency_ms <= 1000);
        }
    }

    #[test]
    fn test_select_best_sorted_by_cost() {
        let selector = ModelSelector::new();
        let caps = vec![ModelCapability::Summarization];
        let results = selector.select_best_for_task(&caps, None, None);
        let costs: Vec<f64> = results
            .iter()
            .map(|m| m.estimate_cost(800, 200))
            .collect();
        for window in costs.windows(2) {
            assert!(window[0] <= window[1], "results should be sorted by cost ascending");
        }
    }

    #[test]
    fn test_models_by_provider_anthropic() {
        let selector = ModelSelector::new();
        let anthropic = selector.models_by_provider(&ModelProvider::Anthropic);
        assert!(!anthropic.is_empty());
        for m in &anthropic {
            assert_eq!(m.provider, ModelProvider::Anthropic);
        }
    }

    #[test]
    fn test_find_by_id_found() {
        let selector = ModelSelector::new();
        assert!(selector.find_by_id("gpt-4o").is_some());
    }

    #[test]
    fn test_find_by_id_not_found() {
        let selector = ModelSelector::new();
        assert!(selector.find_by_id("nonexistent-model-xyz").is_none());
    }

    #[test]
    fn test_models_within_monthly_budget_includes_local() {
        let selector = ModelSelector::new();
        let affordable = selector.models_within_monthly_budget(0.0, 100_000);
        for m in &affordable {
            assert!(
                m.estimate_cost(50_000, 50_000) <= 0.0 + 1e-9,
                "only zero-cost models should be within $0 budget"
            );
        }
    }

    #[test]
    fn test_capability_coverage_partial() {
        let selector = ModelSelector::new();
        // Haiku supports a subset of caps
        let model = selector.find_by_id("claude-haiku-3-5").unwrap();
        let required = vec![ModelCapability::Reasoning, ModelCapability::Summarization];
        let coverage = model.capability_coverage(&required);
        // Summarization is present, Reasoning is not
        assert_eq!(coverage, 1);
    }

    #[test]
    fn test_long_context_model_exists() {
        let selector = ModelSelector::new();
        let caps = vec![ModelCapability::LongContext];
        let results = selector.select_best_for_task(&caps, None, None);
        assert!(!results.is_empty(), "at least one model should support LongContext");
    }

    #[test]
    fn test_add_custom_model() {
        let mut selector = ModelSelector::new();
        let initial_count = selector.all_models().len();
        selector.add_model(ModelProfile {
            id: "custom-v1".into(),
            display_name: "Custom V1".into(),
            provider: ModelProvider::Custom("MyOrg".into()),
            context_window: 4_096,
            output_limit: 1_024,
            capabilities: vec![ModelCapability::Summarization],
            cost_per_1k_input_tokens: 0.001,
            cost_per_1k_output_tokens: 0.002,
            avg_latency_ms: 300,
        });
        assert_eq!(selector.all_models().len(), initial_count + 1);
        assert!(selector.find_by_id("custom-v1").is_some());
    }

    #[test]
    fn test_gemini_long_context_window() {
        let selector = ModelSelector::new();
        let model = selector.find_by_id("gemini-1.5-pro").unwrap();
        assert!(model.context_window >= 1_000_000);
    }
}
