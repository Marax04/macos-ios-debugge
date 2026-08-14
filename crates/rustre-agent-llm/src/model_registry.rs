//! `model_registry` — LLM model registry with capability tracking, cost estimation,
//! rate limiting, and automatic model selection/fallback.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustre_agent::casts::{u64_to_f64, usize_to_f64, usize_to_u32};

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    ModelNotFound(String),
    NoSuitableModel(String),
    RateLimitExceeded { model: String, retry_after_ms: u64 },
    InvalidConfig(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelNotFound(id) => write!(f, "model not found: {id}"),
            Self::NoSuitableModel(req) => write!(f, "no suitable model for: {req}"),
            Self::RateLimitExceeded {
                model,
                retry_after_ms,
            } => {
                write!(
                    f,
                    "rate limit exceeded for '{model}', retry after {retry_after_ms}ms"
                )
            }
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
        }
    }
}

impl std::error::Error for RegistryError {}

// ─── ModelCapability ─────────────────────────────────────────────────────────

/// A discrete capability that a model may or may not possess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelCapability {
    /// Structured function/tool calling.
    FunctionCalling,
    /// Vision / image understanding.
    Vision,
    /// Strong code generation and understanding.
    Code,
    /// Long context window (typically ≥ 32K tokens).
    LongContext,
    /// Streaming response support.
    Streaming,
    /// JSON mode / structured output.
    JsonMode,
    /// Reasoning / chain-of-thought (native).
    Reasoning,
    /// Fine-tuning support.
    FineTuning,
    /// Embeddings generation.
    Embeddings,
    /// Batch/async inference.
    BatchInference,
}

impl fmt::Display for ModelCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FunctionCalling => "function_calling",
            Self::Vision => "vision",
            Self::Code => "code",
            Self::LongContext => "long_context",
            Self::Streaming => "streaming",
            Self::JsonMode => "json_mode",
            Self::Reasoning => "reasoning",
            Self::FineTuning => "fine_tuning",
            Self::Embeddings => "embeddings",
            Self::BatchInference => "batch_inference",
        };
        write!(f, "{s}")
    }
}

// ─── ModelProvider ───────────────────────────────────────────────────────────

/// The API provider for a model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelProvider {
    OpenAi,
    Anthropic,
    Google,
    Mistral,
    Meta,
    Ollama,
    Custom(String),
}

impl fmt::Display for ModelProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenAi => write!(f, "openai"),
            Self::Anthropic => write!(f, "anthropic"),
            Self::Google => write!(f, "google"),
            Self::Mistral => write!(f, "mistral"),
            Self::Meta => write!(f, "meta"),
            Self::Ollama => write!(f, "ollama"),
            Self::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

// ─── ModelDef ────────────────────────────────────────────────────────────────

/// Complete definition of an LLM model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDef {
    /// Unique model identifier (e.g. "gpt-4o", "claude-3-5-sonnet-20241022").
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Provider that hosts this model.
    pub provider: ModelProvider,
    /// Context window in tokens.
    pub context_window: usize,
    /// Maximum output tokens.
    pub max_output_tokens: usize,
    /// Whether this model supports tool/function calling.
    pub supports_tools: bool,
    /// Cost per 1000 input tokens in USD.
    pub cost_per_1k_input: f64,
    /// Cost per 1000 output tokens in USD.
    pub cost_per_1k_output: f64,
    /// Set of supported capabilities.
    pub capabilities: Vec<ModelCapability>,
    /// Whether this model is deprecated / no longer available.
    pub deprecated: bool,
    /// Optional replacement model ID (for deprecated models).
    pub replacement: Option<String>,
    /// Arbitrary metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

impl ModelDef {
    /// Build a minimal model definition.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        provider: ModelProvider,
        context_window: usize,
        cost_per_1k_input: f64,
        cost_per_1k_output: f64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            provider,
            context_window,
            max_output_tokens: 4096,
            supports_tools: false,
            cost_per_1k_input,
            cost_per_1k_output,
            capabilities: Vec::new(),
            deprecated: false,
            replacement: None,
            metadata: HashMap::new(),
        }
    }

    /// Add a capability.
    #[must_use] 
    pub fn with_capability(mut self, cap: ModelCapability) -> Self {
        if !self.capabilities.contains(&cap) {
            self.capabilities.push(cap);
        }
        self
    }

    /// Set `supports_tools` and add `FunctionCalling` capability.
    #[must_use] 
    pub fn with_tools(mut self) -> Self {
        self.supports_tools = true;
        self.with_capability(ModelCapability::FunctionCalling)
    }

    /// Mark as deprecated with a replacement.
    #[must_use]
    pub fn deprecated_by(mut self, replacement: impl Into<String>) -> Self {
        self.deprecated = true;
        self.replacement = Some(replacement.into());
        self
    }

    /// Set max output tokens.
    #[must_use] 
    pub const fn with_max_output(mut self, tokens: usize) -> Self {
        self.max_output_tokens = tokens;
        self
    }

    /// Check whether this model has the given capability.
    #[must_use] 
    pub fn has_capability(&self, cap: ModelCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Estimate the cost for a request.
    #[must_use]
    pub fn estimate_cost(&self, input_tokens: usize, output_tokens: usize) -> f64 {
        (usize_to_f64(input_tokens) / 1000.0).mul_add(self.cost_per_1k_input, (usize_to_f64(output_tokens) / 1000.0) * self.cost_per_1k_output)
    }
}

// ─── CostEstimator ───────────────────────────────────────────────────────────

/// Tracks and estimates LLM call costs.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CostEstimator {
    /// Running total cost in USD.
    pub total_cost_usd: f64,
    /// Total input tokens consumed.
    pub total_input_tokens: u64,
    /// Total output tokens consumed.
    pub total_output_tokens: u64,
    /// Number of API calls tracked.
    pub call_count: u64,
    /// Per-model cost breakdown.
    pub per_model: HashMap<String, f64>,
}

impl CostEstimator {
    /// Record a completed API call.
    pub fn record(&mut self, model: &ModelDef, input_tokens: usize, output_tokens: usize) {
        let cost = model.estimate_cost(input_tokens, output_tokens);
        self.total_cost_usd += cost;
        self.total_input_tokens += input_tokens as u64;
        self.total_output_tokens += output_tokens as u64;
        self.call_count += 1;
        *self.per_model.entry(model.id.clone()).or_default() += cost;
    }

    /// Estimate the cost for a planned request without recording it.
    #[must_use] 
    pub fn preview_cost(model: &ModelDef, input_tokens: usize, output_tokens: usize) -> f64 {
        model.estimate_cost(input_tokens, output_tokens)
    }

    /// Average cost per call.
    #[must_use]
    pub fn avg_cost_per_call(&self) -> f64 {
        if self.call_count == 0 {
            0.0
        } else {
            self.total_cost_usd / u64_to_f64(self.call_count)
        }
    }

    /// Most expensive model used.
    ///
    /// # Panics
    ///
    /// Does not panic; `partial_cmp` falls back to `Equal` for NaN costs.
    #[must_use]
    pub fn most_expensive_model(&self) -> Option<(&str, f64)> {
        // `per_model` is a HashMap: equal costs must be broken on the model name,
        // or the reported "most expensive" model varies between runs.
        self.per_model
            .iter()
            .max_by(|a, b| {
                a.1.partial_cmp(b.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.0.cmp(a.0))
            })
            .map(|(k, v)| (k.as_str(), *v))
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ─── RateLimiter ─────────────────────────────────────────────────────────────

/// Sliding-window rate limiter tracking requests per minute and tokens per minute.
#[derive(Debug)]
pub struct RateLimiter {
    /// Model ID this limiter is for.
    pub model_id: String,
    /// Max requests per minute.
    pub rpm_limit: u32,
    /// Max tokens per minute.
    pub tpm_limit: u64,
    /// Request timestamps in the last minute.
    request_times: VecDeque<Instant>,
    /// Token counts paired with timestamps.
    token_window: VecDeque<(Instant, u64)>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(model_id: impl Into<String>, rpm_limit: u32, tpm_limit: u64) -> Self {
        Self {
            model_id: model_id.into(),
            rpm_limit,
            tpm_limit,
            request_times: VecDeque::new(),
            token_window: VecDeque::new(),
        }
    }

    /// Prune entries older than one minute.
    fn prune(&mut self) {
        let cutoff = Instant::now().checked_sub(Duration::from_mins(1)).unwrap();
        while self.request_times.front().is_some_and(|&t| t < cutoff) {
            self.request_times.pop_front();
        }
        while self
            .token_window
            .front()
            .is_some_and(|&(t, _)| t < cutoff)
        {
            self.token_window.pop_front();
        }
    }

    /// Check whether a request with the given token count can proceed.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::RateLimitExceeded`] when RPM or TPM limits are exceeded.
    pub fn check(&mut self, tokens: u64) -> Result<(), RegistryError> {
        self.prune();
        let current_rpm = usize_to_u32(self.request_times.len());
        let tpm_total: u64 = self.token_window.iter().map(|(_, t)| t).sum();

        if current_rpm >= self.rpm_limit {
            // Estimate when oldest request falls out of window.
            let oldest = self
                .request_times
                .front()
                .copied()
                .unwrap_or_else(Instant::now);
            let retry_after = Duration::from_mins(1)
                .checked_sub(oldest.elapsed())
                .unwrap_or(Duration::ZERO);
            return Err(RegistryError::RateLimitExceeded {
                model: self.model_id.clone(),
                retry_after_ms: u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX),
            });
        }
        if tpm_total + tokens > self.tpm_limit {
            return Err(RegistryError::RateLimitExceeded {
                model: self.model_id.clone(),
                retry_after_ms: 5_000,
            });
        }
        Ok(())
    }

    /// Record a completed request.
    pub fn record(&mut self, tokens: u64) {
        let now = Instant::now();
        self.request_times.push_back(now);
        self.token_window.push_back((now, tokens));
        self.prune();
    }

    /// Current requests in the last minute.
    pub fn current_rpm(&mut self) -> u32 {
        self.prune();
        usize_to_u32(self.request_times.len())
    }

    /// Current tokens in the last minute.
    pub fn current_tpm(&mut self) -> u64 {
        self.prune();
        self.token_window.iter().map(|(_, t)| t).sum()
    }
}

// ─── ModelFallback ───────────────────────────────────────────────────────────

/// Defines a fallback chain for a primary model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFallback {
    /// Primary model ID.
    pub primary: String,
    /// Ordered list of fallback model IDs to try in sequence.
    pub fallbacks: Vec<String>,
    /// Conditions that trigger falling back.
    pub trigger_on_rate_limit: bool,
    pub trigger_on_error: bool,
    pub trigger_on_cost_threshold: Option<f64>,
}

impl ModelFallback {
    /// Create a simple fallback chain.
    pub fn new(primary: impl Into<String>, fallbacks: Vec<String>) -> Self {
        Self {
            primary: primary.into(),
            fallbacks,
            trigger_on_rate_limit: true,
            trigger_on_error: true,
            trigger_on_cost_threshold: None,
        }
    }

    /// Iterator over all models in order (primary first).
    pub fn ordered(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.primary.as_str()).chain(self.fallbacks.iter().map(std::string::String::as_str))
    }
}

// ─── SelectionCriteria ───────────────────────────────────────────────────────

/// Criteria used by `ModelSelector` to pick the best model.
#[derive(Debug, Clone, Default)]
pub struct SelectionCriteria {
    /// Required capabilities.
    pub required_capabilities: Vec<ModelCapability>,
    /// Minimum context window needed.
    pub min_context_window: usize,
    /// Maximum acceptable cost per 1k tokens (combined).
    pub max_cost_per_1k: Option<f64>,
    /// Preferred provider (optional).
    pub preferred_provider: Option<ModelProvider>,
    /// Whether the task requires tool calling.
    pub needs_tools: bool,
    /// Rough task type hint.
    pub task_type: Option<TaskType>,
}

/// High-level RE task type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskType {
    CodeAnalysis,
    BinaryDescription,
    VulnerabilityHunting,
    CryptoIdentification,
    ProtocolReversal,
    MalwareAnalysis,
    ScriptGeneration,
    Documentation,
}

// ─── ModelSelector ───────────────────────────────────────────────────────────

/// Picks the best available model for a given task.
#[derive(Debug, Default)]
pub struct ModelSelector;

impl ModelSelector {
    /// Select the best model from a registry given selection criteria.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NoSuitableModel`] when no model meets the criteria.
    ///
    /// # Panics
    ///
    /// Does not panic; score comparison uses `unwrap_or(Equal)` for NaN safety.
    pub fn select<'a>(
        registry: &'a ModelRegistry,
        criteria: &SelectionCriteria,
    ) -> Result<&'a ModelDef, RegistryError> {
        let mut candidates: Vec<&ModelDef> =
            registry.models.values().filter(|m| !m.deprecated).collect();

        // Filter by required capabilities.
        for cap in &criteria.required_capabilities {
            candidates.retain(|m| m.has_capability(*cap));
        }

        // Filter by context window.
        if criteria.min_context_window > 0 {
            candidates.retain(|m| m.context_window >= criteria.min_context_window);
        }

        // Filter by tools requirement.
        if criteria.needs_tools {
            candidates.retain(|m| m.supports_tools);
        }

        // Filter by cost.
        if let Some(max_cost) = criteria.max_cost_per_1k {
            candidates.retain(|m| m.cost_per_1k_input + m.cost_per_1k_output <= max_cost);
        }

        // Filter by provider preference.
        if let Some(ref pref) = criteria.preferred_provider {
            let preferred: Vec<_> = candidates
                .iter()
                .copied()
                .filter(|m| &m.provider == pref)
                .collect();
            if !preferred.is_empty() {
                candidates = preferred;
            }
        }

        if candidates.is_empty() {
            return Err(RegistryError::NoSuitableModel(format!(
                "{:?}",
                criteria.required_capabilities
            )));
        }

        // Score candidates: context window weight + tools weight + code weight.
        let scored: &ModelDef = candidates
            .into_iter()
            .max_by(|a, b| {
                let score_a = Self::score(a, criteria);
                let score_b = Self::score(b, criteria);
                // `candidates` comes from `registry.models.values()`, a HashMap:
                // without a tie-break on the id, two runs with identical inputs
                // could select different models — and bill differently for it.
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.id.cmp(&a.id))
            })
            .unwrap_or_else(|| unreachable!("candidates non-empty checked above"));

        Ok(scored)
    }

    fn score(model: &ModelDef, criteria: &SelectionCriteria) -> f64 {
        let mut score = 0.0f64;
        // Favour larger context windows.
        score = usize_to_f64(model.context_window).log2().mul_add(0.1, score);
        // Favour lower cost.
        score = (model.cost_per_1k_input + model.cost_per_1k_output).mul_add(-10.0, score);
        // Task-type bonuses.
        if let Some(tt) = criteria.task_type {
            match tt {
                TaskType::CodeAnalysis | TaskType::ScriptGeneration => {
                    if model.has_capability(ModelCapability::Code) {
                        score += 5.0;
                    }
                }
                TaskType::MalwareAnalysis | TaskType::VulnerabilityHunting => {
                    if model.has_capability(ModelCapability::Reasoning) {
                        score += 5.0;
                    }
                    if model.has_capability(ModelCapability::Code) {
                        score += 3.0;
                    }
                }
                TaskType::Documentation
                | TaskType::BinaryDescription
                | TaskType::CryptoIdentification
                | TaskType::ProtocolReversal => {
                    // No special bonus for these task types.
                }
            }
        }
        score
    }
}

// ─── ModelRegistry ───────────────────────────────────────────────────────────

/// Thread-safe registry of all known LLM models.
#[derive(Debug, Default)]
pub struct ModelRegistry {
    /// All registered models keyed by ID.
    pub models: HashMap<String, ModelDef>,
    /// Rate limiters per model ID.
    pub rate_limiters: HashMap<String, Arc<Mutex<RateLimiter>>>,
    /// Cost estimator shared across all calls.
    pub cost_estimator: Arc<Mutex<CostEstimator>>,
    /// Fallback chains.
    pub fallback_chains: Vec<ModelFallback>,
}

impl ModelRegistry {
    /// Create an empty registry.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with well-known models.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        Self::register_openai_defaults(&mut r);
        Self::register_anthropic_defaults(&mut r);
        Self::register_google_defaults(&mut r);
        Self::register_local_defaults(&mut r);
        Self::add_default_rate_limiters(&mut r);
        Self::add_default_fallbacks(&mut r);
        r
    }

    fn register_openai_defaults(r: &mut Self) {
        r.register(
            ModelDef::new("gpt-4o", "GPT-4o", ModelProvider::OpenAi, 128_000, 0.005, 0.015)
                .with_tools()
                .with_capability(ModelCapability::Vision)
                .with_capability(ModelCapability::Code)
                .with_capability(ModelCapability::Streaming)
                .with_capability(ModelCapability::JsonMode)
                .with_max_output(4096),
        );
        r.register(
            ModelDef::new("gpt-4o-mini", "GPT-4o Mini", ModelProvider::OpenAi, 128_000, 0.000_15, 0.0006)
                .with_tools()
                .with_capability(ModelCapability::Vision)
                .with_capability(ModelCapability::Code)
                .with_capability(ModelCapability::Streaming)
                .with_capability(ModelCapability::JsonMode)
                .with_max_output(16384),
        );
        r.register(
            ModelDef::new("o1-preview", "o1 Preview", ModelProvider::OpenAi, 128_000, 0.015, 0.060)
                .with_tools()
                .with_capability(ModelCapability::Reasoning)
                .with_capability(ModelCapability::Code),
        );
        r.register(
            ModelDef::new(
                "mistral-large-latest",
                "Mistral Large",
                ModelProvider::Mistral,
                128_000,
                0.003,
                0.009,
            )
            .with_tools()
            .with_capability(ModelCapability::Code)
            .with_capability(ModelCapability::Streaming)
            .with_max_output(4096),
        );
    }

    fn register_anthropic_defaults(r: &mut Self) {
        r.register(
            ModelDef::new(
                "claude-3-5-sonnet-20241022",
                "Claude 3.5 Sonnet",
                ModelProvider::Anthropic,
                200_000,
                0.003,
                0.015,
            )
            .with_tools()
            .with_capability(ModelCapability::Vision)
            .with_capability(ModelCapability::Code)
            .with_capability(ModelCapability::Streaming)
            .with_capability(ModelCapability::LongContext)
            .with_max_output(8192),
        );
        r.register(
            ModelDef::new(
                "claude-3-haiku-20240307",
                "Claude 3 Haiku",
                ModelProvider::Anthropic,
                200_000,
                0.000_25,
                0.001_25,
            )
            .with_tools()
            .with_capability(ModelCapability::Vision)
            .with_capability(ModelCapability::Streaming)
            .with_capability(ModelCapability::LongContext)
            .with_max_output(4096),
        );
    }

    fn register_google_defaults(r: &mut Self) {
        r.register(
            ModelDef::new("gemini-1.5-pro", "Gemini 1.5 Pro", ModelProvider::Google, 1_000_000, 0.003_5, 0.007)
                .with_tools()
                .with_capability(ModelCapability::Vision)
                .with_capability(ModelCapability::Code)
                .with_capability(ModelCapability::LongContext)
                .with_capability(ModelCapability::Streaming)
                .with_max_output(8192),
        );
        r.register(
            ModelDef::new("gemini-1.5-flash", "Gemini 1.5 Flash", ModelProvider::Google, 1_000_000, 0.000_075, 0.0003)
                .with_tools()
                .with_capability(ModelCapability::Vision)
                .with_capability(ModelCapability::Code)
                .with_capability(ModelCapability::LongContext)
                .with_capability(ModelCapability::Streaming)
                .with_max_output(8192),
        );
    }

    fn register_local_defaults(r: &mut Self) {
        r.register(
            ModelDef::new("llama3:70b", "Llama 3 70B (local)", ModelProvider::Ollama, 8_192, 0.0, 0.0)
                .with_capability(ModelCapability::Code)
                .with_capability(ModelCapability::Streaming),
        );
        r.register(
            ModelDef::new("codellama:34b", "CodeLlama 34B (local)", ModelProvider::Ollama, 16_384, 0.0, 0.0)
                .with_capability(ModelCapability::Code)
                .with_capability(ModelCapability::Streaming),
        );
    }

    fn add_default_rate_limiters(r: &mut Self) {
        r.add_rate_limiter("gpt-4o", 500, 300_000);
        r.add_rate_limiter("gpt-4o-mini", 500, 2_000_000);
        r.add_rate_limiter("claude-3-5-sonnet-20241022", 50, 40_000);
        r.add_rate_limiter("claude-3-haiku-20240307", 50, 100_000);
        r.add_rate_limiter("gemini-1.5-pro", 360, 4_000_000);
    }

    fn add_default_fallbacks(r: &mut Self) {
        r.add_fallback(ModelFallback::new(
            "claude-3-5-sonnet-20241022",
            vec!["claude-3-haiku-20240307".into(), "gpt-4o-mini".into()],
        ));
        r.add_fallback(ModelFallback::new(
            "gpt-4o",
            vec!["gpt-4o-mini".into(), "claude-3-haiku-20240307".into()],
        ));
    }

    /// Register a model definition.
    pub fn register(&mut self, model: ModelDef) {
        self.models.insert(model.id.clone(), model);
    }

    /// Add a rate limiter for a model.
    pub fn add_rate_limiter(&mut self, model_id: &str, rpm: u32, tpm: u64) {
        self.rate_limiters.insert(
            model_id.to_string(),
            Arc::new(Mutex::new(RateLimiter::new(model_id, rpm, tpm))),
        );
    }

    /// Add a fallback chain.
    pub fn add_fallback(&mut self, fallback: ModelFallback) {
        self.fallback_chains.push(fallback);
    }

    /// Look up a model by ID.
    #[must_use] 
    pub fn get(&self, id: &str) -> Option<&ModelDef> {
        self.models.get(id)
    }

    /// Look up a model, following deprecation chains.
    #[must_use] 
    pub fn get_active(&self, id: &str) -> Option<&ModelDef> {
        let mut current = self.models.get(id)?;
        let mut depth = 0;
        while current.deprecated {
            if depth > 8 {
                break; // Prevent infinite loop.
            }
            current = current
                .replacement
                .as_deref()
                .and_then(|r| self.models.get(r))?;
            depth += 1;
        }
        Some(current)
    }

    /// List all non-deprecated models.
    #[must_use] 
    pub fn active_models(&self) -> Vec<&ModelDef> {
        self.models.values().filter(|m| !m.deprecated).collect()
    }

    /// List all models with a specific capability.
    #[must_use] 
    pub fn models_with_capability(&self, cap: ModelCapability) -> Vec<&ModelDef> {
        self.models
            .values()
            .filter(|m| !m.deprecated && m.has_capability(cap))
            .collect()
    }

    /// Select the best model for the given criteria.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NoSuitableModel`] when no model meets the criteria.
    pub fn select(&self, criteria: &SelectionCriteria) -> Result<&ModelDef, RegistryError> {
        ModelSelector::select(self, criteria)
    }

    /// Get the fallback chain for a primary model.
    #[must_use] 
    pub fn fallback_for(&self, primary_id: &str) -> Option<&ModelFallback> {
        self.fallback_chains
            .iter()
            .find(|f| f.primary == primary_id)
    }

    /// Check and record a rate-limited request. Returns the first available model
    /// from the fallback chain.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::RateLimitExceeded`] when all models in the chain are rate-limited.
    pub fn acquire_with_fallback(
        &self,
        primary_id: &str,
        tokens: u64,
    ) -> Result<String, RegistryError> {
        let chain: Vec<String> = self.fallback_for(primary_id).map_or_else(
            || vec![primary_id.to_string()],
            |fb| fb.ordered().map(std::string::ToString::to_string).collect(),
        );

        for model_id in &chain {
            if let Some(limiter_arc) = self.rate_limiters.get(model_id) {
                if let Ok(mut limiter) = limiter_arc.lock()
                    && limiter.check(tokens).is_ok() {
                        limiter.record(tokens);
                        return Ok(model_id.clone());
                    }
            } else {
                // No rate limiter configured → always allowed.
                return Ok(model_id.clone());
            }
        }
        Err(RegistryError::RateLimitExceeded {
            model: primary_id.to_string(),
            retry_after_ms: 5_000,
        })
    }

    /// Record a completed API call for cost tracking.
    pub fn record_call(&self, model_id: &str, input_tokens: usize, output_tokens: usize) {
        if let Some(model) = self.models.get(model_id)
            && let Ok(mut estimator) = self.cost_estimator.lock() {
                estimator.record(model, input_tokens, output_tokens);
            }
    }

    /// Total accumulated cost across all calls.
    #[must_use] 
    pub fn total_cost(&self) -> f64 {
        self.cost_estimator
            .lock()
            .map_or(0.0, |e| e.total_cost_usd)
    }

    /// Number of registered models.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.models.len()
    }

    /// True if the registry is empty.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_model(id: &str) -> ModelDef {
        ModelDef::new(id, id, ModelProvider::OpenAi, 8_192, 0.01, 0.02)
    }

    #[test]
    fn model_def_capabilities() {
        let m = basic_model("m1")
            .with_capability(ModelCapability::Code)
            .with_capability(ModelCapability::Streaming);
        assert!(m.has_capability(ModelCapability::Code));
        assert!(m.has_capability(ModelCapability::Streaming));
        assert!(!m.has_capability(ModelCapability::Vision));
    }

    #[test]
    fn model_def_with_tools() {
        let m = basic_model("m2").with_tools();
        assert!(m.supports_tools);
        assert!(m.has_capability(ModelCapability::FunctionCalling));
    }

    #[test]
    fn model_def_estimate_cost() {
        let m = ModelDef::new("m", "m", ModelProvider::OpenAi, 1000, 1.0, 2.0);
        // 1000 input tokens → 1.0 / 1000 * 1000 = 1.0
        // 500 output tokens → 2.0 / 1000 * 500 = 1.0
        assert!((m.estimate_cost(1000, 500) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn model_def_deprecated() {
        let m = basic_model("old").deprecated_by("new");
        assert!(m.deprecated);
        assert_eq!(m.replacement.as_deref(), Some("new"));
    }

    #[test]
    fn registry_register_get() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("gpt-test"));
        assert!(r.get("gpt-test").is_some());
        assert!(r.get("nonexistent").is_none());
    }

    #[test]
    fn registry_get_active_deprecated() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("new-model"));
        let old = basic_model("old-model").deprecated_by("new-model");
        r.register(old);
        let active = r.get_active("old-model");
        assert!(active.is_some());
        assert_eq!(active.unwrap().id, "new-model");
    }

    #[test]
    fn registry_active_models_filters_deprecated() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("live"));
        r.register(basic_model("dead").deprecated_by("live"));
        let active = r.active_models();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "live");
    }

    #[test]
    fn registry_models_with_capability() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("a").with_capability(ModelCapability::Vision));
        r.register(basic_model("b").with_capability(ModelCapability::Code));
        r.register(
            basic_model("c")
                .with_capability(ModelCapability::Vision)
                .with_capability(ModelCapability::Code),
        );
        let vision = r.models_with_capability(ModelCapability::Vision);
        assert_eq!(vision.len(), 2);
    }

    #[test]
    fn registry_defaults_populated() {
        let r = ModelRegistry::with_defaults();
        assert!(r.len() > 5);
        assert!(r.get("gpt-4o").is_some());
        assert!(r.get("claude-3-5-sonnet-20241022").is_some());
    }

    #[test]
    fn model_selector_picks_capable() {
        let r = ModelRegistry::with_defaults();
        let criteria = SelectionCriteria {
            required_capabilities: vec![ModelCapability::Vision],
            ..Default::default()
        };
        let result = r.select(&criteria);
        assert!(result.is_ok());
        assert!(result.unwrap().has_capability(ModelCapability::Vision));
    }

    #[test]
    fn model_selector_no_suitable() {
        let r = ModelRegistry::new(); // empty
        let criteria = SelectionCriteria::default();
        assert!(matches!(
            r.select(&criteria),
            Err(RegistryError::NoSuitableModel(_))
        ));
    }

    #[test]
    fn model_selector_filters_deprecated() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("deprecated").deprecated_by("live"));
        r.register(basic_model("live"));
        let criteria = SelectionCriteria::default();
        let result = r.select(&criteria).unwrap();
        assert_eq!(result.id, "live");
    }

    #[test]
    fn model_selector_min_context_window() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("small")); // 8192 context
        let big = ModelDef::new("big", "big", ModelProvider::OpenAi, 100_000, 0.01, 0.02);
        r.register(big);
        let criteria = SelectionCriteria {
            min_context_window: 50_000,
            ..Default::default()
        };
        let result = r.select(&criteria).unwrap();
        assert_eq!(result.id, "big");
    }

    #[test]
    fn model_selector_needs_tools() {
        let mut r = ModelRegistry::new();
        r.register(basic_model("no-tools"));
        r.register(basic_model("with-tools").with_tools());
        let criteria = SelectionCriteria {
            needs_tools: true,
            ..Default::default()
        };
        let result = r.select(&criteria).unwrap();
        assert!(result.supports_tools);
    }

    #[test]
    fn cost_estimator_record() {
        let m = ModelDef::new("m", "m", ModelProvider::OpenAi, 1000, 1.0, 2.0);
        let mut est = CostEstimator::default();
        est.record(&m, 1000, 500);
        assert!((est.total_cost_usd - 2.0).abs() < 1e-9);
        assert_eq!(est.call_count, 1);
    }

    #[test]
    fn cost_estimator_multiple_calls() {
        let m = ModelDef::new("m", "m", ModelProvider::OpenAi, 1000, 1.0, 2.0);
        let mut est = CostEstimator::default();
        for _ in 0..5 {
            est.record(&m, 1000, 500);
        }
        assert!((est.total_cost_usd - 10.0).abs() < 1e-9);
        assert!((est.avg_cost_per_call() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn cost_estimator_per_model() {
        let m1 = ModelDef::new("m1", "m1", ModelProvider::OpenAi, 1000, 1.0, 2.0);
        let m2 = ModelDef::new("m2", "m2", ModelProvider::Anthropic, 1000, 0.5, 1.0);
        let mut est = CostEstimator::default();
        est.record(&m1, 1000, 500);
        est.record(&m2, 1000, 500);
        assert!(est.per_model.contains_key("m1"));
        assert!(est.per_model.contains_key("m2"));
    }

    #[test]
    fn cost_estimator_most_expensive() {
        let m1 = ModelDef::new("cheap", "cheap", ModelProvider::OpenAi, 1000, 0.001, 0.002);
        let m2 = ModelDef::new(
            "expensive",
            "expensive",
            ModelProvider::OpenAi,
            1000,
            10.0,
            20.0,
        );
        let mut est = CostEstimator::default();
        est.record(&m1, 1000, 500);
        est.record(&m2, 1000, 500);
        let (name, _) = est.most_expensive_model().unwrap();
        assert_eq!(name, "expensive");
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut rl = RateLimiter::new("m", 10, 100_000);
        assert!(rl.check(1000).is_ok());
        rl.record(1000);
        assert_eq!(rl.current_rpm(), 1);
    }

    #[test]
    fn rate_limiter_blocks_over_rpm() {
        let mut rl = RateLimiter::new("m", 2, 100_000);
        rl.record(100);
        rl.record(100);
        let result = rl.check(100);
        assert!(matches!(
            result,
            Err(RegistryError::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn rate_limiter_blocks_over_tpm() {
        let mut rl = RateLimiter::new("m", 1000, 500);
        rl.record(400);
        let result = rl.check(200); // 400+200 > 500
        assert!(matches!(
            result,
            Err(RegistryError::RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn model_fallback_ordered() {
        let fb = ModelFallback::new("primary", vec!["fb1".into(), "fb2".into()]);
        let order: Vec<&str> = fb.ordered().collect();
        assert_eq!(order, vec!["primary", "fb1", "fb2"]);
    }

    #[test]
    fn registry_acquire_with_fallback_no_limiter() {
        let r = ModelRegistry::with_defaults();
        // llama3 has no rate limiter → always succeeds.
        let result = r.acquire_with_fallback("llama3:70b", 1000);
        assert!(result.is_ok());
    }

    #[test]
    fn registry_total_cost() {
        let r = ModelRegistry::with_defaults();
        r.record_call("gpt-4o", 1000, 500);
        assert!(r.total_cost() > 0.0);
    }

    #[test]
    fn registry_len_non_empty() {
        let r = ModelRegistry::with_defaults();
        assert!(!r.is_empty());
    }

    #[test]
    fn model_capability_display() {
        assert_eq!(
            ModelCapability::FunctionCalling.to_string(),
            "function_calling"
        );
        assert_eq!(ModelCapability::Vision.to_string(), "vision");
    }

    #[test]
    fn model_provider_display() {
        assert_eq!(ModelProvider::OpenAi.to_string(), "openai");
        assert_eq!(ModelProvider::Custom("x".into()).to_string(), "custom:x");
    }

    #[test]
    fn cost_estimator_reset() {
        let m = ModelDef::new("m", "m", ModelProvider::OpenAi, 1000, 1.0, 2.0);
        let mut est = CostEstimator::default();
        est.record(&m, 1000, 500);
        est.reset();
        assert_eq!(est.total_cost_usd, 0.0);
    }

    #[test]
    fn registry_error_display() {
        let e = RegistryError::ModelNotFound("gpt-99".into());
        assert!(e.to_string().contains("gpt-99"));
    }

    #[test]
    fn model_selector_provider_preference() {
        let r = ModelRegistry::with_defaults();
        let criteria = SelectionCriteria {
            preferred_provider: Some(ModelProvider::Anthropic),
            ..Default::default()
        };
        let result = r.select(&criteria).unwrap();
        assert_eq!(result.provider, ModelProvider::Anthropic);
    }
}
