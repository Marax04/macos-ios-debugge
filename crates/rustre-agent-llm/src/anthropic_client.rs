// rustre-agent-llm/src/anthropic_client.rs
//
// Anthropic API client:
//   - POST /v1/messages (non-streaming and SSE streaming)
//   - Tool use (tool_choice, tools array)
//   - Vision (base64 image blocks)
//   - Exponential backoff retry + rate-limit handling
//   - Cost tracking (input/output tokens × prices per model)
//   - Cache-control headers (prompt caching beta)

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client, StatusCode,
};
use rustre_agent::casts::u64_to_f64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────── Error ───────────────────────────────────────

#[derive(Debug, Error)]
pub enum AnthropicError {
    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },
    #[error("rate limited – retry after {retry_after_secs}s")]
    RateLimit { retry_after_secs: u64 },
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("streaming error: {0}")]
    Stream(String),
    #[error("max retries exceeded ({0})")]
    MaxRetries(u32),
}

pub type AnthropicResult<T> = Result<T, AnthropicError>;

// ─────────────────────────────── Pricing ─────────────────────────────────────

/// Per-million-token prices in USD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub cache_write_per_mtok: f64,
    pub cache_read_per_mtok: f64,
}

impl ModelPricing {
    #[must_use] 
    pub const fn claude_opus_4() -> Self {
        Self { input_per_mtok: 15.0, output_per_mtok: 75.0, cache_write_per_mtok: 18.75, cache_read_per_mtok: 1.5 }
    }
    #[must_use] 
    pub const fn claude_sonnet_4() -> Self {
        Self { input_per_mtok: 3.0, output_per_mtok: 15.0, cache_write_per_mtok: 3.75, cache_read_per_mtok: 0.3 }
    }
    #[must_use] 
    pub const fn claude_haiku_35() -> Self {
        Self { input_per_mtok: 0.8, output_per_mtok: 4.0, cache_write_per_mtok: 1.0, cache_read_per_mtok: 0.08 }
    }
}

fn pricing_for_model(model: &str) -> ModelPricing {
    if model.contains("opus") { ModelPricing::claude_opus_4() }
    else if model.contains("haiku") { ModelPricing::claude_haiku_35() }
    else { ModelPricing::claude_sonnet_4() }
}

// ─────────────────────────────── Cost tracker ────────────────────────────────

#[derive(Debug, Default)]
pub struct CostTracker {
    input_tokens: AtomicU64,
    output_tokens: AtomicU64,
    cache_write_tokens: AtomicU64,
    cache_read_tokens: AtomicU64,
    total_requests: AtomicU64,
}

impl CostTracker {
    pub fn record(&self, usage: &Usage) {
        self.input_tokens.fetch_add(u64::from(usage.input_tokens), Ordering::Relaxed);
        self.output_tokens.fetch_add(u64::from(usage.output_tokens), Ordering::Relaxed);
        if let Some(cw) = usage.cache_creation_input_tokens {
            self.cache_write_tokens.fetch_add(u64::from(cw), Ordering::Relaxed);
        }
        if let Some(cr) = usage.cache_read_input_tokens {
            self.cache_read_tokens.fetch_add(u64::from(cr), Ordering::Relaxed);
        }
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_cost_usd(&self, pricing: &ModelPricing) -> f64 {
        let inp = u64_to_f64(self.input_tokens.load(Ordering::Relaxed));
        let out = u64_to_f64(self.output_tokens.load(Ordering::Relaxed));
        let cw  = u64_to_f64(self.cache_write_tokens.load(Ordering::Relaxed));
        let cr  = u64_to_f64(self.cache_read_tokens.load(Ordering::Relaxed));
        (inp * pricing.input_per_mtok / 1_000_000.0)
            + (out * pricing.output_per_mtok / 1_000_000.0)
            + (cw  * pricing.cache_write_per_mtok / 1_000_000.0)
            + (cr  * pricing.cache_read_per_mtok / 1_000_000.0)
    }

    pub fn snapshot(&self) -> CostSnapshot {
        CostSnapshot {
            input_tokens: self.input_tokens.load(Ordering::Relaxed),
            output_tokens: self.output_tokens.load(Ordering::Relaxed),
            cache_write_tokens: self.cache_write_tokens.load(Ordering::Relaxed),
            cache_read_tokens: self.cache_read_tokens.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSnapshot {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_write_tokens: u64,
    pub cache_read_tokens: u64,
    pub total_requests: u64,
}

// ─────────────────────────────── API types ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_input_tokens: Option<u32>,
    pub cache_read_input_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text { text: String },
    ToolUse { id: String, name: String, input: serde_json::Value },
    Image { source: ImageSource },
}

impl ContentBlock {
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text { text: s.into() }
    }

    pub fn tool_use(id: impl Into<String>, name: impl Into<String>, input: serde_json::Value) -> Self {
        Self::ToolUse { id: id.into(), name: name.into(), input }
    }

    #[must_use] 
    pub const fn as_text(&self) -> Option<&str> {
        match self { Self::Text { text } => Some(text.as_str()), _ => None }
    }

    #[must_use] 
    pub fn as_tool_use(&self) -> Option<(&str, &str, &serde_json::Value)> {
        match self { Self::ToolUse { id, name, input } => Some((id, name, input)), _ => None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImageSource {
    Base64 { media_type: String, data: String },
    Url { url: String },
}

impl ImageSource {
    #[must_use] 
    pub fn from_bytes(bytes: &[u8], media_type: &str) -> Self {
        use base64::Engine as _;
        Self::Base64 {
            media_type: media_type.to_owned(),
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    #[must_use] 
    pub fn from_png(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes, "image/png")
    }

    #[must_use] 
    pub fn from_jpeg(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes, "image/jpeg")
    }
}

/// A message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: MessageContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl Message {
    pub fn user(text: impl Into<String>) -> Self {
        Self { role: "user".to_owned(), content: MessageContent::Text(text.into()) }
    }

    pub fn assistant(text: impl Into<String>) -> Self {
        Self { role: "assistant".to_owned(), content: MessageContent::Text(text.into()) }
    }

    pub fn user_with_image(text: impl Into<String>, image: ImageSource) -> Self {
        Self {
            role: "user".to_owned(),
            content: MessageContent::Blocks(vec![
                ContentBlock::Image { source: image },
                ContentBlock::Text { text: text.into() },
            ]),
        }
    }

    /// Create a `tool_result` user message.
    ///
    /// # Panics
    ///
    /// Panics if the internal `serde_json::from_value` call fails (this cannot happen for the
    /// hard-coded JSON shape used here).
    pub fn tool_result(tool_use_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: "user".to_owned(),
            content: MessageContent::Blocks(vec![
                serde_json::from_value(serde_json::json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id.into(),
                    "content": content.into()
                })).unwrap()
            ]),
        }
    }
}

/// Tool definition for the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

impl ToolDef {
    pub fn new(name: impl Into<String>, description: impl Into<String>, schema: serde_json::Value) -> Self {
        Self { name: name.into(), description: description.into(), input_schema: schema }
    }
}

/// Tool choice mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ToolChoice {
    Auto,
    Any,
    Tool { name: String },
}

/// Full request body for /v1/messages.
#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl MessagesRequest {
    pub fn new(model: impl Into<String>, messages: Vec<Message>, max_tokens: u32) -> Self {
        Self {
            model: model.into(),
            messages,
            max_tokens,
            system: None,
            temperature: None,
            top_p: None,
            top_k: None,
            tools: Vec::new(),
            tool_choice: None,
            stream: None,
            metadata: HashMap::new(),
        }
    }

    /// Set the system prompt.
    #[must_use]
    pub fn with_system(mut self, s: impl Into<String>) -> Self { self.system = Some(s.into()); self }
    #[must_use] 
    pub const fn with_temperature(mut self, t: f64) -> Self { self.temperature = Some(t); self }
    #[must_use] 
    pub fn with_tools(mut self, tools: Vec<ToolDef>) -> Self { self.tools = tools; self }
    #[must_use] 
    pub fn with_tool_choice(mut self, tc: ToolChoice) -> Self { self.tool_choice = Some(tc); self }
    #[must_use] 
    pub const fn with_stream(mut self) -> Self { self.stream = Some(true); self }
}

/// Response from /v1/messages.
#[derive(Debug, Clone, Deserialize)]
pub struct MessagesResponse {
    pub id: String,
    pub r#type: String,
    pub role: String,
    pub content: Vec<ContentBlock>,
    pub model: String,
    pub stop_reason: Option<String>,
    pub stop_sequence: Option<String>,
    pub usage: Usage,
}

impl MessagesResponse {
    #[must_use] 
    pub fn text_content(&self) -> String {
        self.content
            .iter()
            .filter_map(|b| b.as_text())
            .collect::<Vec<_>>()
            .join("")
    }

    #[must_use] 
    pub fn tool_calls(&self) -> Vec<(&str, &str, &serde_json::Value)> {
        self.content.iter().filter_map(|b| b.as_tool_use()).collect()
    }

    #[must_use] 
    pub fn is_tool_use(&self) -> bool {
        self.stop_reason.as_deref() == Some("tool_use")
    }
}

// ─────────────────────────────── SSE event ───────────────────────────────────

/// Parsed SSE event from the streaming endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    MessageStart { message: MessagesResponsePartial },
    ContentBlockStart { index: u32, content_block: ContentBlockPartial },
    ContentBlockDelta { index: u32, delta: Delta },
    ContentBlockStop { index: u32 },
    MessageDelta { delta: MessageDeltaPartial, usage: UsageDelta },
    MessageStop,
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesResponsePartial {
    pub id: String,
    pub model: String,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlockPartial {
    Text { text: String },
    ToolUse { id: String, name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Delta {
    TextDelta { text: String },
    InputJsonDelta { partial_json: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDeltaPartial {
    pub stop_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageDelta {
    pub output_tokens: u32,
}

// ─────────────────────────────── Client config ───────────────────────────────

#[derive(Debug, Clone)]
pub struct AnthropicConfig {
    pub api_key: String,
    pub base_url: String,
    pub default_model: String,
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub request_timeout_secs: u64,
    /// Enable prompt caching beta header.
    pub enable_cache: bool,
}

impl AnthropicConfig {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: "https://api.anthropic.com".to_owned(),
            default_model: "claude-sonnet-4-6".to_owned(),
            max_retries: 5,
            initial_backoff_ms: 500,
            max_backoff_ms: 60_000,
            request_timeout_secs: 120,
            enable_cache: true,
        }
    }

    pub fn from_env() -> Option<Self> {
        std::env::var("ANTHROPIC_API_KEY").ok().map(Self::new)
    }
}

// ─────────────────────────────── Client ──────────────────────────────────────

pub struct AnthropicClient {
    config: AnthropicConfig,
    http: Client,
    cost: Arc<CostTracker>,
    pricing: ModelPricing,
}

impl AnthropicClient {
    /// Create a new [`AnthropicClient`] from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AnthropicError::Network`] if the underlying `reqwest` client cannot be built.
    pub fn new(config: AnthropicConfig) -> AnthropicResult<Self> {
        let pricing = pricing_for_model(&config.default_model);
        let http = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .use_rustls_tls()
            .build()
            .map_err(|e| AnthropicError::Network(e.to_string()))?;
        Ok(Self { config, http, cost: Arc::new(CostTracker::default()), pricing })
    }

    #[must_use] 
    pub fn cost_tracker(&self) -> Arc<CostTracker> {
        Arc::clone(&self.cost)
    }

    #[must_use] 
    pub fn total_cost_usd(&self) -> f64 {
        self.cost.total_cost_usd(&self.pricing)
    }

    #[must_use] 
    pub fn cost_snapshot(&self) -> CostSnapshot {
        self.cost.snapshot()
    }

    // ── Non-streaming ─────────────────────────────────────────────────────────

    /// Send a non-streaming messages request.
    ///
    /// # Errors
    ///
    /// Returns an [`AnthropicError`] on network failure, rate limiting, auth failure, or JSON errors.
    pub async fn messages(&self, mut req: MessagesRequest) -> AnthropicResult<MessagesResponse> {
        req.stream = None; // ensure non-streaming
        let body = serde_json::to_string(&req)
            .map_err(|e| AnthropicError::Serialize(e.to_string()))?;

        let resp = self.post_with_retry("/v1/messages", &body).await?;
        let parsed: MessagesResponse = serde_json::from_str(&resp)
            .map_err(|e| AnthropicError::Serialize(format!("{e}: {resp}")))?;
        self.cost.record(&parsed.usage);
        Ok(parsed)
    }

    /// Simple helper: send a user message and return the text response.
    ///
    /// # Errors
    ///
    /// Returns an [`AnthropicError`] on network failure, rate limiting, auth failure, or JSON errors.
    pub async fn complete(
        &self,
        model: &str,
        system: Option<&str>,
        user: &str,
        max_tokens: u32,
    ) -> AnthropicResult<String> {
        let mut req = MessagesRequest::new(
            model,
            vec![Message::user(user)],
            max_tokens,
        );
        if let Some(s) = system {
            req = req.with_system(s);
        }
        let resp = self.messages(req).await?;
        Ok(resp.text_content())
    }

    // ── Streaming ─────────────────────────────────────────────────────────────

    /// Stream tokens from the `/v1/messages` SSE endpoint.
    ///
    /// Reads the HTTP response body as a byte stream, accumulates an
    /// internal buffer, and dispatches one [`StreamEvent`] per SSE
    /// `data:` frame as soon as the terminating blank line arrives.
    /// `on_token` is invoked for every `content_block_delta` text delta,
    /// live — no full-body buffering.
    ///
    /// Handled events: `message_start`, `content_block_delta`,
    /// `message_delta`, `message_stop`. Other event types
    /// (`content_block_start`, `content_block_stop`, `ping`) are parsed
    /// but ignored. Unknown event types are silently skipped to remain
    /// forward-compatible.
    ///
    /// # Errors
    ///
    /// Returns an [`AnthropicError`] on network failure, rate limiting, auth failure,
    /// serialization error, or if the SSE stream terminates without a `message_stop`.
    pub async fn stream_tokens(
        &self,
        req: MessagesRequest,
        on_token: impl FnMut(&str),
    ) -> AnthropicResult<MessagesResponse> {
        let req = req.with_stream();
        let model_req = req.model.clone();
        let body = serde_json::to_string(&req)
            .map_err(|e| AnthropicError::Serialize(e.to_string()))?;

        let http_resp = self.send_streaming_request(&body).await?;
        self.process_sse_stream(http_resp, model_req, on_token).await
    }

    async fn send_streaming_request(&self, body: &str) -> AnthropicResult<reqwest::Response> {
        let url = format!("{}/v1/messages", self.config.base_url);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            HeaderValue::from_str(&self.config.api_key)
                .map_err(|e| AnthropicError::Auth(e.to_string()))?,
        );
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(reqwest::header::ACCEPT, HeaderValue::from_static("text/event-stream"));
        if self.config.enable_cache {
            headers.insert(
                "anthropic-beta",
                HeaderValue::from_static("prompt-caching-2024-07-31"),
            );
        }
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .body(body.to_owned())
            .send()
            .await
            .map_err(|e| AnthropicError::Network(e.to_string()))?;

        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let err_text = resp.text().await.unwrap_or_default();
            let retry = serde_json::from_str::<serde_json::Value>(&err_text)
                .ok()
                .and_then(|v| v["error"]["retry_after"].as_u64())
                .unwrap_or(60);
            return Err(AnthropicError::RateLimit { retry_after_secs: retry });
        }
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(AnthropicError::Auth(err_text));
        }
        if !status.is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(AnthropicError::Http { status: status.as_u16(), body: err_text });
        }
        Ok(resp)
    }

    async fn process_sse_stream(
        &self,
        resp: reqwest::Response,
        model_req: String,
        mut on_token: impl FnMut(&str),
    ) -> AnthropicResult<MessagesResponse> {
        use futures::StreamExt;

        let mut final_usage = Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };
        let mut full_text = String::new();
        let mut model = model_req;
        let mut id = String::new();
        let mut stop_reason: Option<String> = None;
        let mut saw_message_stop = false;

        let mut buf = String::new();
        let mut stream = resp.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| AnthropicError::Stream(e.to_string()))?;
            buf.push_str(
                std::str::from_utf8(&chunk).map_err(|e| AnthropicError::Stream(e.to_string()))?,
            );

            while let Some(boundary) = buf.find("\n\n") {
                let frame = buf[..boundary].to_owned();
                buf.drain(..boundary + 2);

                let mut data = String::new();
                for line in frame.lines() {
                    if let Some(rest) = line.strip_prefix("data:") {
                        if !data.is_empty() {
                            data.push('\n');
                        }
                        data.push_str(rest.trim_start());
                    }
                }
                if data.is_empty() {
                    continue;
                }
                if data == "[DONE]" {
                    saw_message_stop = true;
                    break;
                }

                match serde_json::from_str::<StreamEvent>(&data) {
                    Ok(StreamEvent::MessageStart { message }) => {
                        id = message.id;
                        model = message.model;
                        final_usage = message.usage;
                    }
                    Ok(StreamEvent::ContentBlockDelta {
                        delta: Delta::TextDelta { text },
                        ..
                    }) => {
                        on_token(&text);
                        full_text.push_str(&text);
                    }
                    Ok(StreamEvent::MessageDelta { delta, usage }) => {
                        final_usage.output_tokens = usage.output_tokens;
                        if let Some(reason) = delta.stop_reason {
                            stop_reason = Some(reason);
                        }
                    }
                    Ok(StreamEvent::MessageStop) => {
                        saw_message_stop = true;
                    }
                    Ok(_) | Err(_) => {
                        // content_block_start / content_block_stop / ping /
                        // input_json_delta, or unknown/future event — ignored.
                    }
                }
            }

            if saw_message_stop {
                break;
            }
        }

        if !saw_message_stop && !buf.trim().is_empty() {
            return Err(AnthropicError::Stream(
                "stream ended before message_stop event".to_owned(),
            ));
        }

        self.cost.record(&final_usage);

        Ok(MessagesResponse {
            id,
            r#type: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![ContentBlock::Text { text: full_text }],
            model,
            stop_reason: stop_reason.or_else(|| Some("end_turn".to_owned())),
            stop_sequence: None,
            usage: final_usage,
        })
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    async fn post_with_retry(&self, path: &str, body: &str) -> AnthropicResult<String> {
        let mut attempt = 0u32;
        let mut backoff_ms = self.config.initial_backoff_ms;

        loop {
            match self.http_request_raw(path, body).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    match &e {
                        AnthropicError::RateLimit { retry_after_secs } => {
                            if attempt < self.config.max_retries {
                                let wait = Duration::from_secs(*retry_after_secs).max(Duration::from_millis(backoff_ms));
                                tokio::time::sleep(wait).await;
                                attempt += 1;
                                backoff_ms = (backoff_ms * 2).min(self.config.max_backoff_ms);
                                continue;
                            }
                        }
                        AnthropicError::Http { status, .. } if *status >= 500 => {
                            if attempt < self.config.max_retries {
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                attempt += 1;
                                backoff_ms = (backoff_ms * 2).min(self.config.max_backoff_ms);
                                continue;
                            }
                        }
                        AnthropicError::Network(_)
                            if attempt < self.config.max_retries => {
                                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                                attempt += 1;
                                backoff_ms = (backoff_ms * 2).min(self.config.max_backoff_ms);
                                continue;
                            }
                        _ => {}
                    }
                    if attempt >= self.config.max_retries {
                        return Err(AnthropicError::MaxRetries(self.config.max_retries));
                    }
                    return Err(e);
                }
            }
        }
    }

    async fn http_request_raw(&self, path: &str, body: &str) -> AnthropicResult<String> {
        let url = format!("{}{path}", self.config.base_url);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            HeaderValue::from_str(&self.config.api_key)
                .map_err(|e| AnthropicError::Auth(e.to_string()))?,
        );
        headers.insert(
            "anthropic-version",
            HeaderValue::from_static("2023-06-01"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if self.config.enable_cache {
            headers.insert(
                "anthropic-beta",
                HeaderValue::from_static("prompt-caching-2024-07-31"),
            );
        }

        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .body(body.to_owned())
            .send()
            .await
            .map_err(|e| AnthropicError::Network(e.to_string()))?;

        let status = resp.status();
        let text = resp.text().await.map_err(|e| AnthropicError::Network(e.to_string()))?;

        if status == StatusCode::TOO_MANY_REQUESTS {
            // Try to parse retry-after from body
            let retry = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["error"]["retry_after"].as_u64())
                .unwrap_or(60);
            return Err(AnthropicError::RateLimit { retry_after_secs: retry });
        }

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err(AnthropicError::Auth(text));
        }

        if !status.is_success() {
            return Err(AnthropicError::Http { status: status.as_u16(), body: text });
        }

        Ok(text)
    }
}

// ─────────────────────────────── unit tests ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_pricing_sonnet() {
        let p = ModelPricing::claude_sonnet_4();
        assert!(p.input_per_mtok < p.output_per_mtok);
    }

    #[test]
    fn cost_tracker_record_and_snapshot() {
        let tracker = CostTracker::default();
        tracker.record(&Usage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        });
        let snap = tracker.snapshot();
        assert_eq!(snap.input_tokens, 1000);
        assert_eq!(snap.output_tokens, 500);
        assert_eq!(snap.total_requests, 1);
    }

    #[test]
    fn cost_tracker_usd() {
        let tracker = CostTracker::default();
        tracker.record(&Usage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        });
        let cost = tracker.total_cost_usd(&ModelPricing::claude_sonnet_4());
        // 3.0 + 15.0 = 18.0
        assert!((cost - 18.0).abs() < 0.01);
    }

    #[test]
    fn messages_request_serialization() {
        let req = MessagesRequest::new(
            "claude-sonnet-4-6",
            vec![Message::user("hello")],
            1024,
        )
        .with_system("You are an RE expert")
        .with_temperature(0.2);

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("claude-sonnet-4-6"));
        assert!(json.contains("hello"));
        assert!(json.contains("RE expert"));
        assert!(!json.contains("\"stream\"")); // None fields skipped
    }

    #[test]
    fn content_block_text() {
        let b = ContentBlock::text("hi");
        assert_eq!(b.as_text(), Some("hi"));
        assert!(b.as_tool_use().is_none());
    }

    #[test]
    fn image_source_base64_png() {
        let src = ImageSource::from_png(b"\x89PNG\r\n");
        match src {
            ImageSource::Base64 { media_type, data } => {
                assert_eq!(media_type, "image/png");
                assert!(!data.is_empty());
            }
            _ => panic!("expected Base64"),
        }
    }

    #[test]
    fn tool_def_serialized() {
        let t = ToolDef::new("disasm", "Disassemble", serde_json::json!({"type":"object"}));
        let j = serde_json::to_value(&t).unwrap();
        assert_eq!(j["name"], "disasm");
        assert_eq!(j["description"], "Disassemble");
    }

    #[test]
    fn pricing_for_model_dispatch() {
        let p = pricing_for_model("claude-haiku-3-5");
        assert!(p.input_per_mtok < 2.0);
        let p2 = pricing_for_model("claude-opus-4");
        assert!(p2.input_per_mtok > 10.0);
    }

    #[test]
    fn messages_response_text_content() {
        let r = MessagesResponse {
            id: "msg_1".to_owned(),
            r#type: "message".to_owned(),
            role: "assistant".to_owned(),
            content: vec![
                ContentBlock::Text { text: "Hello ".to_owned() },
                ContentBlock::Text { text: "world".to_owned() },
            ],
            model: "claude-sonnet-4-6".to_owned(),
            stop_reason: Some("end_turn".to_owned()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        assert_eq!(r.text_content(), "Hello world");
        assert!(!r.is_tool_use());
    }
}
