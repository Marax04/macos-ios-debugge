// rustre-agent-llm/src/local_llm_client.rs
//
// Local LLM client supporting:
//   - Ollama  (POST /api/chat  or  /api/generate)
//   - vLLM    (OpenAI-compatible /v1/chat/completions)
//   - llama.cpp server  (OpenAI-compatible)
//   - LM Studio         (OpenAI-compatible)
//   - Fallback mode: use local backend if Anthropic is unavailable
//   - Model selection by task type

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────── Error ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum LocalLlmError {
    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },
    #[error("network error: {0}")]
    Network(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("no available backend for task type '{0}'")]
    NoBackend(String),
    #[error("all backends failed: {0}")]
    AllFailed(String),
    #[error("model not found: {0}")]
    ModelNotFound(String),
    #[error("streaming error: {0}")]
    Stream(String),
}

pub type LocalResult<T> = Result<T, LocalLlmError>;

// ─────────────────────────────── Backend kind ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Ollama,
    Vllm,
    LlamaCpp,
    LmStudio,
    OpenAiCompatible,
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ollama => write!(f, "ollama"),
            Self::Vllm => write!(f, "vllm"),
            Self::LlamaCpp => write!(f, "llama.cpp"),
            Self::LmStudio => write!(f, "lmstudio"),
            Self::OpenAiCompatible => write!(f, "openai-compat"),
        }
    }
}

// ─────────────────────────────── Task types ──────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    /// Short, fast responses (classify / rename).
    Quick,
    /// Full decompile / function analysis (needs large context).
    Analysis,
    /// Generate embeddings.
    Embedding,
    /// Code generation / patch suggestion.
    Code,
    /// General / default.
    General,
}

// ─────────────────────────────── Chat message ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn system(c: impl Into<String>) -> Self { Self { role: "system".to_owned(), content: c.into() } }
    pub fn user(c: impl Into<String>) -> Self { Self { role: "user".to_owned(), content: c.into() } }
    pub fn assistant(c: impl Into<String>) -> Self { Self { role: "assistant".to_owned(), content: c.into() } }
}

// ─────────────────────────────── Completion request / response ───────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCompletionRequest {
    pub messages: Vec<ChatMessage>,
    pub model: String,
    pub max_tokens: u32,
    pub temperature: f64,
    pub top_p: f64,
    pub stream: bool,
    pub stop: Vec<String>,
}

impl LocalCompletionRequest {
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            model: model.into(),
            messages,
            max_tokens: 2048,
            temperature: 0.2,
            top_p: 1.0,
            stream: false,
            stop: Vec::new(),
        }
    }
    #[must_use] 
    pub const fn with_max_tokens(mut self, n: u32) -> Self { self.max_tokens = n; self }
    #[must_use] 
    pub const fn with_temperature(mut self, t: f64) -> Self { self.temperature = t; self }
    #[must_use] 
    pub fn with_stop(mut self, tokens: Vec<String>) -> Self { self.stop = tokens; self }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCompletionResponse {
    pub text: String,
    pub model: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub elapsed_ms: f64,
    pub backend: BackendKind,
}

// ─────────────────────────────── Ollama types ────────────────────────────────

#[derive(Debug, Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    temperature: f64,
    top_p: f64,
    num_predict: u32,
}

#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: ChatMessage,
    done: bool,
    prompt_eval_count: Option<u32>,
    eval_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OllamaListResponse {
    models: Vec<OllamaModel>,
}

#[derive(Debug, Deserialize)]
struct OllamaModel {
    name: String,
}

// ─────────────────────────────── OpenAI-compat types ─────────────────────────

#[derive(Debug, Serialize)]
struct OaiChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f64,
    top_p: f64,
    stream: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stop: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OaiChatResponse {
    choices: Vec<OaiChoice>,
    usage: Option<OaiUsage>,
    model: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OaiChoice {
    message: ChatMessage,
}

#[derive(Debug, Deserialize)]
struct OaiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
}

// ─────────────────────────────── BackendConfig ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub kind: BackendKind,
    pub base_url: String,
    pub api_key: Option<String>,
    /// Models offered by this backend.
    pub models: Vec<ModelCapability>,
    pub timeout_secs: u64,
    pub priority: u8, // lower = higher priority
}

impl BackendConfig {
    #[must_use] 
    pub fn ollama_default() -> Self {
        Self {
            kind: BackendKind::Ollama,
            base_url: "http://localhost:11434".to_owned(),
            api_key: None,
            models: vec![
                ModelCapability::new("llama3.2:8b").for_tasks([TaskType::Quick, TaskType::General]),
                ModelCapability::new("deepseek-coder-v2:16b").for_tasks([TaskType::Code, TaskType::Analysis]),
            ],
            timeout_secs: 120,
            priority: 10,
        }
    }

    #[must_use] 
    pub fn llama_cpp_default() -> Self {
        Self {
            kind: BackendKind::LlamaCpp,
            base_url: "http://localhost:8080".to_owned(),
            api_key: None,
            models: vec![ModelCapability::new("local").for_all_tasks()],
            timeout_secs: 180,
            priority: 20,
        }
    }

    #[must_use] 
    pub fn lm_studio_default() -> Self {
        Self {
            kind: BackendKind::LmStudio,
            base_url: "http://localhost:1234".to_owned(),
            api_key: None,
            models: vec![ModelCapability::new("local").for_all_tasks()],
            timeout_secs: 120,
            priority: 15,
        }
    }

    pub fn vllm(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            kind: BackendKind::Vllm,
            base_url: base_url.into(),
            api_key: None,
            models: vec![ModelCapability::new(model).for_all_tasks()],
            timeout_secs: 120,
            priority: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCapability {
    pub model_id: String,
    pub supported_tasks: Vec<TaskType>,
    pub context_length: usize,
}

impl ModelCapability {
    pub fn new(id: impl Into<String>) -> Self {
        Self { model_id: id.into(), supported_tasks: Vec::new(), context_length: 8192 }
    }

    /// Add supported task types.
    #[must_use]
    pub fn for_tasks(mut self, tasks: impl IntoIterator<Item = TaskType>) -> Self {
        self.supported_tasks.extend(tasks);
        self
    }

    #[must_use] 
    pub fn for_all_tasks(mut self) -> Self {
        self.supported_tasks = vec![
            TaskType::Quick, TaskType::Analysis, TaskType::Code, TaskType::General,
        ];
        self
    }

    #[must_use] 
    pub const fn with_context(mut self, n: usize) -> Self { self.context_length = n; self }

    #[must_use] 
    pub fn supports(&self, task: &TaskType) -> bool {
        self.supported_tasks.contains(task) || self.supported_tasks.contains(&TaskType::General)
    }
}

// ─────────────────────────────── Backend executor ────────────────────────────

struct BackendExecutor {
    config: BackendConfig,
    http: Client,
    healthy: AtomicBool,
}

impl BackendExecutor {
    fn new(config: BackendConfig) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("reqwest client");
        Self { config, http, healthy: AtomicBool::new(true) }
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
    }

    fn mark_healthy(&self) {
        self.healthy.store(true, Ordering::Relaxed);
    }

    async fn complete(&self, req: &LocalCompletionRequest) -> LocalResult<LocalCompletionResponse> {
        match self.config.kind {
            BackendKind::Ollama => self.ollama_complete(req).await,
            BackendKind::Vllm | BackendKind::LlamaCpp | BackendKind::LmStudio | BackendKind::OpenAiCompatible => {
                self.openai_compat_complete(req).await
            }
        }
    }

    async fn list_models(&self) -> LocalResult<Vec<String>> {
        match self.config.kind {
            BackendKind::Ollama => self.ollama_list_models().await,
            _ => Ok(self.config.models.iter().map(|m| m.model_id.clone()).collect()),
        }
    }

    // ── Ollama ────────────────────────────────────────────────────────────────

    async fn ollama_complete(&self, req: &LocalCompletionRequest) -> LocalResult<LocalCompletionResponse> {
        let body = OllamaChatRequest {
            model: req.model.clone(),
            messages: req.messages.clone(),
            stream: false,
            options: OllamaOptions {
                temperature: req.temperature,
                top_p: req.top_p,
                num_predict: req.max_tokens,
            },
        };
        let json = serde_json::to_string(&body)
            .map_err(|e| LocalLlmError::Serialize(e.to_string()))?;
        let url = format!("{}/api/chat", self.config.base_url);
        let t0 = Instant::now();
        let resp = self.post_json(&url, &json, None).await?;
        let parsed: OllamaChatResponse = serde_json::from_str(&resp)
            .map_err(|e| LocalLlmError::Serialize(format!("{e}: {resp}")))?;
        if !parsed.done {
            return Err(LocalLlmError::Stream(
                "ollama returned a non-final chunk for a non-streaming request".to_owned(),
            ));
        }
        Ok(LocalCompletionResponse {
            text: parsed.message.content,
            model: body.model,
            input_tokens: parsed.prompt_eval_count.unwrap_or(0),
            output_tokens: parsed.eval_count.unwrap_or(0),
            elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
            backend: BackendKind::Ollama,
        })
    }

    async fn ollama_list_models(&self) -> LocalResult<Vec<String>> {
        let url = format!("{}/api/tags", self.config.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| LocalLlmError::Network(e.to_string()))?
            .text()
            .await
            .map_err(|e| LocalLlmError::Network(e.to_string()))?;
        let list: OllamaListResponse = serde_json::from_str(&resp)
            .map_err(|e| LocalLlmError::Serialize(e.to_string()))?;
        Ok(list.models.into_iter().map(|m| m.name).collect())
    }

    // ── OpenAI-compatible ─────────────────────────────────────────────────────

    async fn openai_compat_complete(&self, req: &LocalCompletionRequest) -> LocalResult<LocalCompletionResponse> {
        let body = OaiChatRequest {
            model: req.model.clone(),
            messages: req.messages.clone(),
            max_tokens: req.max_tokens,
            temperature: req.temperature,
            top_p: req.top_p,
            stream: false,
            stop: req.stop.clone(),
        };
        let json = serde_json::to_string(&body)
            .map_err(|e| LocalLlmError::Serialize(e.to_string()))?;
        let url = format!("{}/v1/chat/completions", self.config.base_url);
        let t0 = Instant::now();
        let resp = self.post_json(&url, &json, self.config.api_key.as_deref()).await?;
        let parsed: OaiChatResponse = serde_json::from_str(&resp)
            .map_err(|e| LocalLlmError::Serialize(format!("{e}: {resp}")))?;
        let text = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default();
        let (inp, out) = parsed
            .usage
            .map_or((0, 0), |u| (u.prompt_tokens, u.completion_tokens));
        Ok(LocalCompletionResponse {
            text,
            model: parsed.model.unwrap_or_else(|| req.model.clone()),
            input_tokens: inp,
            output_tokens: out,
            elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
            backend: self.config.kind.clone(),
        })
    }

    // ── HTTP helper ───────────────────────────────────────────────────────────

    async fn post_json(&self, url: &str, body: &str, api_key: Option<&str>) -> LocalResult<String> {
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_owned());
        if let Some(key) = api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| LocalLlmError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| LocalLlmError::Network(e.to_string()))?;
        if status >= 400 {
            return Err(LocalLlmError::Http { status, body: text });
        }
        Ok(text)
    }
}

// ─────────────────────────────── LocalLlmClient ──────────────────────────────

/// Multi-backend local LLM client with automatic model selection and failover.
pub struct LocalLlmClient {
    backends: Vec<Arc<BackendExecutor>>,
    task_model_map: HashMap<TaskType, String>,
    fallback_enabled: bool,
}

impl LocalLlmClient {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            task_model_map: HashMap::new(),
            fallback_enabled: false,
        }
    }

    /// Add a backend.
    #[must_use] 
    pub fn add_backend(mut self, config: BackendConfig) -> Self {
        let mut backends = self.backends;
        backends.push(Arc::new(BackendExecutor::new(config)));
        // Keep sorted by priority.
        backends.sort_by_key(|b| b.config.priority);
        self.backends = backends;
        self
    }

    /// Map a task type to a specific model ID.
    #[must_use]
    pub fn map_task(mut self, task: TaskType, model: impl Into<String>) -> Self {
        self.task_model_map.insert(task, model.into());
        self
    }

    /// Enable fallback mode (try next backend on error).
    #[must_use] 
    pub const fn with_fallback(mut self) -> Self {
        self.fallback_enabled = true;
        self
    }

    /// Default setup: try Ollama, then llama.cpp, then LM Studio.
    #[must_use] 
    pub fn default_local() -> Self {
        Self::new()
            .add_backend(BackendConfig::ollama_default())
            .add_backend(BackendConfig::llama_cpp_default())
            .add_backend(BackendConfig::lm_studio_default())
            .with_fallback()
    }

    // ── API ───────────────────────────────────────────────────────────────────

    /// Complete a chat request for the given task type.
    ///
    /// # Errors
    ///
    /// Returns a [`LocalLlmError`] if no backend can handle the task or if the request fails.
    pub async fn complete(
        &self,
        messages: Vec<ChatMessage>,
        task: TaskType,
        max_tokens: u32,
    ) -> LocalResult<LocalCompletionResponse> {
        let model = self.select_model(&task);
        let req = LocalCompletionRequest::new(model, messages)
            .with_max_tokens(max_tokens);
        self.dispatch(req, &task).await
    }

    /// Simple single-prompt completion.
    ///
    /// # Errors
    ///
    /// Returns a [`LocalLlmError`] if the backend call fails.
    pub async fn complete_prompt(
        &self,
        system: Option<&str>,
        user: &str,
        task: TaskType,
        max_tokens: u32,
    ) -> LocalResult<String> {
        let mut msgs = Vec::new();
        if let Some(s) = system {
            msgs.push(ChatMessage::system(s));
        }
        msgs.push(ChatMessage::user(user));
        let resp = self.complete(msgs, task, max_tokens).await?;
        Ok(resp.text)
    }

    /// List all available models across backends.
    pub async fn list_all_models(&self) -> HashMap<String, Vec<String>> {
        let mut result = HashMap::new();
        for be in &self.backends {
            let name = be.config.kind.to_string();
            match be.list_models().await {
                Ok(models) => { result.insert(name, models); }
                Err(_) => { result.insert(name, vec![]); }
            }
        }
        result
    }

    /// Health check: ping each backend.
    pub async fn health_check(&self) -> HashMap<String, bool> {
        let mut result = HashMap::new();
        for be in &self.backends {
            let name = be.config.kind.to_string();
            let ok = be.list_models().await.is_ok();
            be.healthy.store(ok, Ordering::Relaxed);
            result.insert(name, ok);
        }
        result
    }

    // ── internal ──────────────────────────────────────────────────────────────

    fn select_model(&self, task: &TaskType) -> String {
        if let Some(m) = self.task_model_map.get(task) {
            return m.clone();
        }
        // Find first backend that has a model for this task.
        for be in &self.backends {
            if !be.is_healthy() { continue; }
            for cap in &be.config.models {
                if cap.supports(task) {
                    return cap.model_id.clone();
                }
            }
        }
        // Last resort: first model of first backend.
        self.backends
            .first()
            .and_then(|be| be.config.models.first()).map_or_else(|| "default".to_owned(), |m| m.model_id.clone())
    }

    async fn dispatch(&self, req: LocalCompletionRequest, task: &TaskType) -> LocalResult<LocalCompletionResponse> {
        let mut last_err = LocalLlmError::NoBackend(format!("{task:?}"));

        for be in &self.backends {
            if !be.is_healthy() { continue; }

            // Check that this backend supports the task.
            let supports = be
                .config
                .models
                .iter()
                .any(|m| m.model_id == req.model && m.supports(task));
            if !supports && !self.fallback_enabled {
                continue;
            }

            match be.complete(&req).await {
                Ok(r) => {
                    be.mark_healthy();
                    return Ok(r);
                }
                Err(e) => {
                    be.mark_unhealthy();
                    last_err = e;
                    if !self.fallback_enabled {
                        break;
                    }
                }
            }
        }

        Err(last_err)
    }
}

impl Default for LocalLlmClient {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────── FallbackClient ──────────────────────────────

/// Wrapper that tries Anthropic first and falls back to local backends.
/// Useful in air-gapped environments or when rate limits are hit.
pub struct FallbackClient<P> {
    primary: Arc<P>,
    local: Arc<LocalLlmClient>,
    local_task: TaskType,
}

impl<P: Send + Sync> FallbackClient<P> {
    pub const fn new(primary: Arc<P>, local: Arc<LocalLlmClient>, local_task: TaskType) -> Self {
        Self { primary, local, local_task }
    }

    #[must_use] 
    pub fn local(&self) -> &LocalLlmClient {
        &self.local
    }

    /// Borrow the primary backend (typically an Anthropic client).
    #[must_use] 
    pub fn primary(&self) -> &P {
        &self.primary
    }

    /// The `TaskType` used when dispatching a fallback call to the
    /// local backend.
    #[must_use] 
    pub const fn local_task(&self) -> &TaskType {
        &self.local_task
    }

    /// Try `op` against the primary backend; on error, fall back to
    /// the local backend using `local_task` for model selection.
    ///
    /// # Errors
    ///
    /// Returns a [`LocalLlmError`] if both the primary operation and the local fallback fail.
    pub async fn try_or_fallback<T, F, Fut, E>(
        &self,
        messages: Vec<ChatMessage>,
        max_tokens: u32,
        op: F,
    ) -> LocalResult<LocalCompletionResponse>
    where
        T: Into<LocalCompletionResponse> + Send,
        E: std::fmt::Display + Send,
        F: FnOnce(Arc<P>) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T, E>> + Send,
    {
        match op(Arc::clone(&self.primary)).await {
            Ok(v) => Ok(v.into()),
            Err(_) => self.local.complete(messages, self.local_task.clone(), max_tokens).await,
        }
    }
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_capability_supports() {
        let cap = ModelCapability::new("llama3")
            .for_tasks([TaskType::Quick, TaskType::Code]);
        assert!(cap.supports(&TaskType::Quick));
        assert!(cap.supports(&TaskType::Code));
        assert!(!cap.supports(&TaskType::Analysis));
    }

    #[test]
    fn model_capability_general_supports_all() {
        let cap = ModelCapability::new("x").for_all_tasks();
        assert!(cap.supports(&TaskType::Analysis));
        assert!(cap.supports(&TaskType::Embedding));
    }

    #[test]
    fn backend_config_ollama_default() {
        let cfg = BackendConfig::ollama_default();
        assert_eq!(cfg.kind, BackendKind::Ollama);
        assert_eq!(cfg.base_url, "http://localhost:11434");
        assert!(!cfg.models.is_empty());
    }

    #[test]
    fn backend_config_vllm() {
        let cfg = BackendConfig::vllm("http://localhost:8000", "mistral-7b");
        assert_eq!(cfg.kind, BackendKind::Vllm);
        assert_eq!(cfg.models[0].model_id, "mistral-7b");
    }

    #[test]
    fn select_model_task_map() {
        let client = LocalLlmClient::new()
            .add_backend(BackendConfig::ollama_default())
            .map_task(TaskType::Analysis, "deepseek-r1:32b");
        let model = client.select_model(&TaskType::Analysis);
        assert_eq!(model, "deepseek-r1:32b");
    }

    #[test]
    fn select_model_fallback_to_backend() {
        let client = LocalLlmClient::new().add_backend(BackendConfig::ollama_default());
        let model = client.select_model(&TaskType::Quick);
        assert!(!model.is_empty());
    }

    #[test]
    fn chat_message_roles() {
        let s = ChatMessage::system("You are an RE expert");
        assert_eq!(s.role, "system");
        let u = ChatMessage::user("Analyze this");
        assert_eq!(u.role, "user");
    }

    #[test]
    fn completion_request_defaults() {
        let r = LocalCompletionRequest::new("llama3", vec![ChatMessage::user("hello")]);
        assert_eq!(r.temperature, 0.2);
        assert_eq!(r.max_tokens, 2048);
        assert!(!r.stream);
    }

    #[test]
    fn backend_health_flag() {
        let be = BackendExecutor::new(BackendConfig::ollama_default());
        assert!(be.is_healthy());
        be.mark_unhealthy();
        assert!(!be.is_healthy());
        be.mark_healthy();
        assert!(be.is_healthy());
    }

    #[test]
    fn client_default_local_has_backends() {
        let c = LocalLlmClient::default_local();
        assert!(!c.backends.is_empty());
        assert!(c.fallback_enabled);
    }

    #[test]
    fn oai_serialization() {
        let r = OaiChatRequest {
            model: "m".to_owned(),
            messages: vec![ChatMessage::user("hi")],
            max_tokens: 100,
            temperature: 0.5,
            top_p: 1.0,
            stream: false,
            stop: vec![],
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"m\""));
        assert!(!j.contains("stop")); // empty vec skipped
    }
}
