//! `rustre-agent-llm`
//!
//! LLM backend integrations for the `RustRE` agent framework.
//! Implements manual HTTP/1.1 clients for OpenAI-compatible, Anthropic, and Ollama APIs.

pub mod context_manager;
pub mod model_registry;
pub mod prompt_cache;
pub mod streaming;
pub mod tool_call_loop;
pub mod tool_execution;
pub mod response_parser;
pub mod model_selector;
pub mod llm_prompt_builder;
pub mod llm_response_parser;
pub mod llm_context_manager;
pub mod anthropic_client;
pub mod llm_context_builder;
pub mod local_llm_client;
pub mod prompt_builder;

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use async_trait::async_trait;
use rustre_agent::casts::{f64_to_f32, f64_to_u32, u64_to_u32, usize_to_f64, usize_to_u32};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors that can occur in LLM client operations.
#[derive(Debug, Error)]
pub enum LlmError {
    #[error("HTTP error {status}: {body}")]
    HttpError { status: u16, body: String },

    #[error("failed to parse response: {0}")]
    ParseError(String),

    #[error("authentication failed: {0}")]
    AuthError(String),

    #[error("rate limited: retry after {retry_after_ms}ms")]
    RateLimited { retry_after_ms: u64 },

    #[error("context window exceeded: {tokens} > {limit}")]
    ContextTooLong { tokens: u32, limit: u32 },

    #[error("request timed out after {ms}ms")]
    Timeout { ms: u64 },

    #[error("IO error: {0}")]
    IoError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

impl From<std::io::Error> for LlmError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for LlmError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

// ─── Core types ──────────────────────────────────────────────────────────────

/// A single message in a chat completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

impl Message {
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
        }
    }

    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
        }
    }

    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.into(),
        }
    }
}

/// Options controlling a completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionOptions {
    pub max_tokens: u32,
    pub temperature: f32,
    pub stop_sequences: Vec<String>,
    pub top_p: f32,
}

impl Default for CompletionOptions {
    fn default() -> Self {
        Self {
            max_tokens: 4096,
            temperature: 0.2,
            stop_sequences: Vec::new(),
            top_p: 1.0,
        }
    }
}

/// Token usage statistics returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt: u32,
    pub completion: u32,
    pub total: u32,
}

/// Response from a completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    pub content: String,
    pub finish_reason: String,
    pub usage: TokenUsage,
}

// ─── Tool / Function call support ────────────────────────────────────────────

/// Definition of a tool that can be called by the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's parameters.
    pub parameters: serde_json::Value,
}

impl ToolDefinition {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }
}

/// A tool call invocation returned by the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUse {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

// ─── LlmClient trait ─────────────────────────────────────────────────────────

/// Core trait for LLM backends.
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// Perform a blocking (non-streaming) completion.
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError>;

    /// Streaming completion — returns the full token sequence as a Vec.
    /// (A true stream would require `futures::Stream`; we keep this simple
    /// and compatible with the workspace dependencies.)
    async fn stream_tokens(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<Vec<String>, LlmError>;

    /// Machine-readable model name.
    fn model_name(&self) -> &str;

    /// Maximum context window in tokens.
    fn max_context_tokens(&self) -> u32;
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────

/// Build and send a raw HTTP/1.1 POST request, returning the response body.
/// Only supports HTTPS via plain TCP (no TLS) against localhost or when the
/// caller passes `use_tls = false`.  For remote HTTPS endpoints the caller is
/// responsible for the TLS layer; here we connect plain TCP and include the
/// appropriate `Host` header.
async fn http_post(
    host: &str,
    port: u16,
    path: &str,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<(u16, String), LlmError> {
    // This helper uses plain TCP only. Port 443 requires TLS; callers must use
    // reqwest instead. Enforcing this here prevents silent TLS-over-plain-TCP bugs.
    assert!(
        port != 443,
        "http_post does not support TLS; use reqwest for port 443 (host={host})"
    );
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).await?;

    // Content-Length is the byte count of the body as transmitted on the wire.
    // `str::len()` returns bytes (not chars), which is what HTTP requires; this
    // is correct even when the JSON body contains multi-byte UTF-8 characters.
    debug_assert!(
        std::str::from_utf8(body.as_bytes()).is_ok(),
        "http_post body must be valid UTF-8 JSON"
    );
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        let _ = write!(request, "{k}: {v}\r\n");
    }
    request.push_str("\r\n");
    request.push_str(body);

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes).await?;
    let response_str = String::from_utf8_lossy(&response_bytes).to_string();

    Ok(parse_http_response(&response_str))
}

/// Parse a raw HTTP/1.1 response string into (`status_code`, body).
fn parse_http_response(raw: &str) -> (u16, String) {
    let mut parts = raw.splitn(2, "\r\n\r\n");
    let headers_part = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();

    let status_line = headers_part.lines().next().unwrap_or("");
    // e.g. "HTTP/1.1 200 OK"
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // Handle chunked transfer encoding
    let final_body = if headers_part
        .to_lowercase()
        .contains("transfer-encoding: chunked")
    {
        decode_chunked_body(&body)
    } else {
        body
    };

    (status_code, final_body)
}

/// Decode an HTTP/1.1 chunked-encoded body.
///
/// The chunk size is a byte count; we therefore operate on raw bytes and
/// re-interpret each chunk as UTF-8 with lossy conversion, preventing a
/// panic when a chunk boundary happens to fall inside a multibyte codepoint.
fn decode_chunked_body(body: &str) -> String {
    let mut result = String::new();
    let bytes = body.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        // Find the \r\n after the chunk-size hex string.
        let crlf = match bytes[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(i) => pos + i,
            None => break,
        };
        let Ok(size_str) = std::str::from_utf8(&bytes[pos..crlf]) else { break };
        // Chunk extensions (after ';') are stripped before parsing the size.
        let size_part = size_str.split(';').next().unwrap_or("").trim();
        let Ok(size) = usize::from_str_radix(size_part, 16) else { break };
        if size == 0 {
            break;
        }
        let data_start = crlf + 2;
        let data_end = match data_start.checked_add(size) {
            Some(end) if end <= bytes.len() => end,
            _ => break,
        };
        // Append chunk bytes as lossy UTF-8 — avoids panic on split multibyte.
        result.push_str(&String::from_utf8_lossy(&bytes[data_start..data_end]));
        // Skip trailing \r\n after chunk data.
        let next = data_end + 2;
        if next > bytes.len() {
            break;
        }
        pos = next;
    }
    result
}

// ─── OpenAI client ───────────────────────────────────────────────────────────

/// Client for OpenAI-compatible APIs (`OpenAI`, Together AI, vLLM, etc.).
pub struct OpenAiClient {
    model: String,
    api_key: String,
    host: String,
    port: u16,
    path_prefix: String,
    max_context: u32,
}

impl OpenAiClient {
    /// Create a client for the official `OpenAI` API.
    #[must_use]
    pub fn new_openai(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            api_key: api_key.into(),
            host: "api.openai.com".to_string(),
            port: 443,
            path_prefix: String::new(),
            max_context: 128_000,
        }
    }

    /// Create a client for any OpenAI-compatible endpoint.
    #[must_use]
    pub fn new_custom(
        host: impl Into<String>,
        port: u16,
        api_key: impl Into<String>,
        model: impl Into<String>,
        max_context: u32,
    ) -> Self {
        Self {
            model: model.into(),
            api_key: api_key.into(),
            host: host.into(),
            port,
            path_prefix: String::new(),
            max_context,
        }
    }

    fn build_headers(&self) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert(
            "Authorization".to_string(),
            format!("Bearer {}", self.api_key),
        );
        h
    }

    fn build_body(&self, messages: &[Message], opts: &CompletionOptions) -> serde_json::Value {
        let msgs: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| serde_json::json!({"role": m.role, "content": m.content}))
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": msgs,
            "max_tokens": opts.max_tokens,
            "temperature": opts.temperature,
            "top_p": opts.top_p,
        });

        if !opts.stop_sequences.is_empty() {
            body["stop"] = serde_json::json!(opts.stop_sequences);
        }

        body
    }
}

#[async_trait]
impl LlmClient for OpenAiClient {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        // Use reqwest (TLS-capable) instead of the plain-TCP http_post().
        let body = self.build_body(messages, opts);
        let scheme = if self.port == 443 { "https" } else { "http" };
        let url = format!(
            "{scheme}://{}:{}{}/v1/chat/completions",
            self.host, self.port, self.path_prefix
        );

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let mut req = client
            .post(&url)
            .header("content-type", "application/json")
            .json(&body);

        for (k, v) in self.build_headers() {
            req = req.header(k, v);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let status = resp.status().as_u16();
        let resp_body = resp
            .text()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        if status == 401 {
            return Err(LlmError::AuthError("invalid API key".to_string()));
        }
        if status == 429 {
            return Err(LlmError::RateLimited {
                retry_after_ms: 1000,
            });
        }
        if status != 200 {
            return Err(LlmError::HttpError {
                status,
                body: resp_body,
            });
        }

        let json: serde_json::Value =
            serde_json::from_str(&resp_body).map_err(|e| LlmError::ParseError(e.to_string()))?;

        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let finish_reason = json["choices"][0]["finish_reason"]
            .as_str()
            .unwrap_or("stop")
            .to_string();
        let prompt_tokens = u64_to_u32(json["usage"]["prompt_tokens"].as_u64().unwrap_or(0));
        let completion_tokens = u64_to_u32(json["usage"]["completion_tokens"].as_u64().unwrap_or(0));
        // Prefer the API-reported total; fall back to saturating sum if absent.
        let total_tokens = json["usage"]["total_tokens"]
            .as_u64().map_or_else(|| prompt_tokens.saturating_add(completion_tokens), u64_to_u32);

        Ok(CompletionResponse {
            content,
            finish_reason,
            usage: TokenUsage {
                prompt: prompt_tokens,
                completion: completion_tokens,
                total: total_tokens,
            },
        })
    }

    async fn stream_tokens(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<Vec<String>, LlmError> {
        // For simplicity, perform a non-streaming call and split into tokens.
        let resp = self.complete(messages, opts).await?;
        Ok(resp
            .content
            .split_whitespace()
            .map(str::to_string)
            .collect())
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn max_context_tokens(&self) -> u32 {
        self.max_context
    }
}

// ─── Anthropic client ────────────────────────────────────────────────────────

/// Client for the Anthropic Messages API.
pub struct AnthropicClient {
    model: String,
    api_key: String,
    max_context: u32,
}

impl AnthropicClient {
    #[must_use]
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            api_key: api_key.into(),
            max_context: 200_000,
        }
    }

    /// Build the HTTP header set required for an Anthropic API request,
    /// including the API key and `anthropic-version` header.
    #[must_use] 
    pub fn build_headers(&self) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("x-api-key".to_string(), self.api_key.clone());
        h.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        h
    }

    fn build_body(&self, messages: &[Message], opts: &CompletionOptions) -> serde_json::Value {
        // Anthropic separates system prompt from messages.
        let system_content: String = messages
            .iter()
            .filter(|m| m.role == "system")
            .map(|m| m.content.clone())
            .collect::<Vec<_>>()
            .join("\n");

        let user_messages: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != "system")
            .map(|m| serde_json::json!({"role": m.role, "content": m.content}))
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": opts.max_tokens,
            "temperature": opts.temperature,
            "messages": user_messages,
        });

        if !system_content.is_empty() {
            body["system"] = serde_json::json!(system_content);
        }
        if !opts.stop_sequences.is_empty() {
            body["stop_sequences"] = serde_json::json!(opts.stop_sequences);
        }

        body
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        // Use reqwest (TLS-capable) instead of the plain-TCP http_post().
        let body = self.build_body(messages, opts);
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let status = resp.status().as_u16();
        let resp_body = resp
            .text()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        if status == 401 {
            return Err(LlmError::AuthError("invalid Anthropic API key".to_string()));
        }
        if status == 429 {
            return Err(LlmError::RateLimited {
                retry_after_ms: 2000,
            });
        }
        if status != 200 {
            return Err(LlmError::HttpError {
                status,
                body: resp_body,
            });
        }

        let json: serde_json::Value =
            serde_json::from_str(&resp_body).map_err(|e| LlmError::ParseError(e.to_string()))?;

        let content = json["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let finish_reason = json["stop_reason"]
            .as_str()
            .unwrap_or("end_turn")
            .to_string();
        let input_tokens = u64_to_u32(json["usage"]["input_tokens"].as_u64().unwrap_or(0));
        let output_tokens = u64_to_u32(json["usage"]["output_tokens"].as_u64().unwrap_or(0));

        Ok(CompletionResponse {
            content,
            finish_reason,
            usage: TokenUsage {
                prompt: input_tokens,
                completion: output_tokens,
                total: input_tokens.saturating_add(output_tokens),
            },
        })
    }

    /// Streaming completion using the Anthropic SSE streaming API.
    ///
    /// Sends a request with `"stream": true`, reads the SSE response body,
    /// and parses `data:` lines containing `content_block_delta` events to
    /// extract individual text deltas.  Returns each delta as one element of
    /// the returned `Vec<String>` (not split by whitespace).
    async fn stream_tokens(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<Vec<String>, LlmError> {
        use futures::StreamExt;

        let mut body = self.build_body(messages, opts);
        body["stream"] = serde_json::json!(true);

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 401 {
            return Err(LlmError::AuthError("invalid Anthropic API key".to_string()));
        }
        if status == 429 {
            return Err(LlmError::RateLimited {
                retry_after_ms: 2000,
            });
        }
        if status != 200 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(LlmError::HttpError {
                status,
                body: body_text,
            });
        }

        // Collect the full SSE byte stream.
        let mut stream = resp.bytes_stream();
        let mut raw = Vec::<u8>::new();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e: reqwest::Error| LlmError::IoError(e.to_string()))?;
            raw.extend_from_slice(&bytes);
        }

        let text = String::from_utf8_lossy(&raw);
        let mut tokens = Vec::new();

        // Each SSE event looks like:
        //   event: content_block_delta
        //   data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}
        for line in text.lines() {
            let line = line.trim();
            if let Some(data) = line.strip_prefix("data: ") {
                // Anthropic SSE terminates with a "message_stop" event, not
                // "[DONE]".  Checking for "[DONE]" was an OpenAI-ism that
                // silently skipped the real terminator and never fired.
                // We handle termination by exhausting the stream above.
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data)
                    && json["type"].as_str() == Some("content_block_delta")
                        && let Some(delta_text) = json["delta"]["text"].as_str()
                            && !delta_text.is_empty() {
                                tokens.push(delta_text.to_string());
                            }
            }
        }

        Ok(tokens)
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn max_context_tokens(&self) -> u32 {
        self.max_context
    }
}

// ─── Ollama client ───────────────────────────────────────────────────────────

/// Client for a locally running Ollama server (default: <http://localhost:11434>).
pub struct LocalOllamaClient {
    model: String,
    host: String,
    port: u16,
    max_context: u32,
}

impl LocalOllamaClient {
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            host: "localhost".to_string(),
            port: 11434,
            max_context: 32_768,
        }
    }

    #[must_use]
    pub fn new_at(host: impl Into<String>, port: u16, model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            host: host.into(),
            port,
            max_context: 32_768,
        }
    }
}

#[async_trait]
impl LlmClient for LocalOllamaClient {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        let msgs: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| serde_json::json!({"role": m.role, "content": m.content}))
            .collect();

        let body = serde_json::json!({
            "model": self.model,
            "messages": msgs,
            "stream": false,
            "options": {
                "num_predict": opts.max_tokens,
                "temperature": opts.temperature,
                "top_p": opts.top_p,
            }
        });

        let body_str = serde_json::to_string(&body)?;
        let (status, resp_body) = http_post(
            &self.host,
            self.port,
            "/api/chat",
            &HashMap::new(),
            &body_str,
        )
        .await?;

        if status != 200 {
            return Err(LlmError::HttpError {
                status,
                body: resp_body,
            });
        }

        let json: serde_json::Value =
            serde_json::from_str(&resp_body).map_err(|e| LlmError::ParseError(e.to_string()))?;

        let content = json["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let finish_reason = json["done_reason"].as_str().unwrap_or("stop").to_string();
        let prompt_eval = u64_to_u32(json["prompt_eval_count"].as_u64().unwrap_or(0));
        let eval_count = u64_to_u32(json["eval_count"].as_u64().unwrap_or(0));

        Ok(CompletionResponse {
            content,
            finish_reason,
            usage: TokenUsage {
                prompt: prompt_eval,
                completion: eval_count,
                total: prompt_eval.saturating_add(eval_count),
            },
        })
    }

    async fn stream_tokens(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<Vec<String>, LlmError> {
        let resp = self.complete(messages, opts).await?;
        Ok(resp
            .content
            .split_whitespace()
            .map(str::to_string)
            .collect())
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn max_context_tokens(&self) -> u32 {
        self.max_context
    }
}

// ─── Token counter ────────────────────────────────────────────────────────────

/// Approximate token counter (chars / 4, plus per-message overhead).
pub struct TokenCounter;

impl TokenCounter {
    /// Estimate the number of tokens in a string.
    #[must_use]
    pub fn count_text(text: &str) -> u32 {
        // ~4 chars per token (BPE approximation)
        usize_to_u32(text.chars().count()).saturating_add(3) / 4
    }

    /// Estimate the total token count for a message slice.
    /// Each message adds ~4 overhead tokens (role + separators).
    #[must_use]
    pub fn count_messages(messages: &[Message]) -> u32 {
        messages
            .iter()
            .map(|m| Self::count_text(&m.content) + 4)
            .sum()
    }

    /// Check whether messages fit within a context window.
    #[must_use]
    pub fn fits_in_context(messages: &[Message], max_tokens: u32) -> bool {
        Self::count_messages(messages) <= max_tokens
    }
}

// ─── Context manager ─────────────────────────────────────────────────────────

/// Manages conversation history, truncating to fit within a context window.
pub struct ContextManager {
    max_tokens: u32,
    /// System prompt is always preserved.
    system_prompt: Option<Message>,
    /// History messages (oldest first).
    history: Vec<Message>,
}

impl ContextManager {
    #[must_use]
    pub const fn new(max_tokens: u32) -> Self {
        Self {
            max_tokens,
            system_prompt: None,
            history: Vec::new(),
        }
    }

    /// Set or replace the system prompt.
    pub fn set_system(&mut self, content: impl Into<String>) {
        self.system_prompt = Some(Message::system(content));
    }

    /// Append a message to history.
    pub fn push(&mut self, message: Message) {
        self.history.push(message);
    }

    /// Return a message list that fits within `max_tokens`.
    /// Preserves system prompt, keeps newest messages, drops oldest.
    #[must_use]
    pub fn build(&self) -> Vec<Message> {
        let system_tokens = self
            .system_prompt
            .as_ref()
            .map_or(0, |s| TokenCounter::count_text(&s.content) + 4);

        let budget = self.max_tokens.saturating_sub(system_tokens);
        let mut selected: Vec<&Message> = Vec::new();
        let mut used = 0u32;

        // Walk from newest to oldest, collect until budget exhausted.
        for msg in self.history.iter().rev() {
            let cost = TokenCounter::count_text(&msg.content) + 4;
            if used + cost > budget {
                break;
            }
            used += cost;
            selected.push(msg);
        }

        // Reverse to restore chronological order.
        selected.reverse();

        let mut result = Vec::new();
        if let Some(sys) = &self.system_prompt {
            result.push(sys.clone());
        }
        result.extend(selected.into_iter().cloned());
        result
    }

    /// Total number of messages in history.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.history.len()
    }

    /// True if history is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.history.is_empty()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TokenCounter ────────────────────────────────────────────────────────

    #[test]
    fn test_token_count_empty() {
        assert_eq!(TokenCounter::count_text(""), 0);
    }

    #[test]
    fn test_token_count_short() {
        // "hello" = 5 chars → (5+3)/4 = 2
        assert_eq!(TokenCounter::count_text("hello"), 2);
    }

    #[test]
    fn test_token_count_messages() {
        let msgs = vec![
            Message::system("You are a helpful assistant."),
            Message::user("What is 2+2?"),
        ];
        let count = TokenCounter::count_messages(&msgs);
        assert!(count > 0);
    }

    #[test]
    fn test_fits_in_context_true() {
        let msgs = vec![Message::user("Hi")];
        assert!(TokenCounter::fits_in_context(&msgs, 100));
    }

    #[test]
    fn test_fits_in_context_false() {
        let long = "x".repeat(10_000);
        let msgs = vec![Message::user(long)];
        assert!(!TokenCounter::fits_in_context(&msgs, 10));
    }

    // ── ContextManager ──────────────────────────────────────────────────────

    #[test]
    fn test_context_manager_empty() {
        let cm = ContextManager::new(2048);
        let built = cm.build();
        assert!(built.is_empty());
    }

    #[test]
    fn test_context_manager_system_only() {
        let mut cm = ContextManager::new(2048);
        cm.set_system("You are a RE expert.");
        let built = cm.build();
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].role, "system");
    }

    #[test]
    fn test_context_manager_push_and_build() {
        let mut cm = ContextManager::new(2048);
        cm.set_system("sys");
        cm.push(Message::user("hello"));
        cm.push(Message::assistant("world"));
        let built = cm.build();
        assert_eq!(built.len(), 3);
        assert_eq!(built[0].role, "system");
        assert_eq!(built[1].role, "user");
    }

    #[test]
    fn test_context_manager_truncation() {
        let mut cm = ContextManager::new(20); // very tight budget
        cm.set_system("s");
        // Push lots of messages
        for i in 0..20 {
            cm.push(Message::user(format!("message number {i} with some text")));
        }
        let built = cm.build();
        // Should have at least system and fewer than 21 messages
        let total = TokenCounter::count_messages(&built);
        assert!(total <= 20, "total={total}");
    }

    #[test]
    fn test_context_manager_len_is_empty() {
        let mut cm = ContextManager::new(1024);
        assert!(cm.is_empty());
        cm.push(Message::user("x"));
        assert!(!cm.is_empty());
        assert_eq!(cm.len(), 1);
    }

    // ── Message constructors ─────────────────────────────────────────────────

    #[test]
    fn test_message_constructors() {
        let s = Message::system("sys");
        assert_eq!(s.role, "system");
        let u = Message::user("u");
        assert_eq!(u.role, "user");
        let a = Message::assistant("a");
        assert_eq!(a.role, "assistant");
    }

    // ── CompletionOptions default ────────────────────────────────────────────

    #[test]
    fn test_completion_options_default() {
        let opts = CompletionOptions::default();
        assert_eq!(opts.max_tokens, 4096);
        assert!((opts.top_p - 1.0_f32).abs() < f32::EPSILON);
        assert!(opts.stop_sequences.is_empty());
    }

    // ── ToolDefinition ───────────────────────────────────────────────────────

    #[test]
    fn test_tool_definition_new() {
        let td = ToolDefinition::new(
            "get_disasm",
            "Retrieve disassembly for an address",
            serde_json::json!({"type": "object", "properties": {}}),
        );
        assert_eq!(td.name, "get_disasm");
        assert_eq!(td.description, "Retrieve disassembly for an address");
    }

    // ── ToolUse serialisation ────────────────────────────────────────────────

    #[test]
    fn test_tool_use_roundtrip() {
        let tu = ToolUse {
            id: "call_1".to_string(),
            name: "rename_sym".to_string(),
            arguments: serde_json::json!({"addr": "0x1000", "name": "foo"}),
        };
        let json = serde_json::to_string(&tu).unwrap();
        let back: ToolUse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "call_1");
        assert_eq!(back.name, "rename_sym");
    }

    // ── LlmError ────────────────────────────────────────────────────────────

    #[test]
    fn test_llm_error_display() {
        let e = LlmError::Timeout { ms: 5000 };
        assert!(e.to_string().contains("5000"));
        let e2 = LlmError::ContextTooLong {
            tokens: 200_000,
            limit: 128_000,
        };
        assert!(e2.to_string().contains("128000"));
    }

    #[test]
    fn test_llm_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let e: LlmError = io_err.into();
        assert!(matches!(e, LlmError::IoError(_)));
    }

    #[test]
    fn test_llm_error_from_serde() {
        let bad = serde_json::from_str::<serde_json::Value>("{{bad}}").unwrap_err();
        let e: LlmError = bad.into();
        assert!(matches!(e, LlmError::SerializationError(_)));
    }

    // ── HTTP parsing ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_http_response_200() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let (status, body) = parse_http_response(raw);
        assert_eq!(status, 200);
        assert_eq!(body, "{\"ok\":true}");
    }

    #[test]
    fn test_parse_http_response_401() {
        let raw = "HTTP/1.1 401 Unauthorized\r\n\r\nUnauthorized";
        let (status, body) = parse_http_response(raw);
        assert_eq!(status, 401);
        assert_eq!(body, "Unauthorized");
    }

    #[test]
    fn test_decode_chunked_body() {
        // Chunked: "5\r\nhello\r\n0\r\n\r\n"
        let chunked = "5\r\nhello\r\n0\r\n\r\n";
        let decoded = decode_chunked_body(chunked);
        assert_eq!(decoded, "hello");
    }

    // ── OpenAiClient model name ───────────────────────────────────────────────

    #[test]
    fn test_openai_client_model_name() {
        let client = OpenAiClient::new_openai("sk-x", "gpt-4o");
        assert_eq!(client.model_name(), "gpt-4o");
        assert_eq!(client.max_context_tokens(), 128_000);
    }

    // ── AnthropicClient model name ───────────────────────────────────────────

    #[test]
    fn test_anthropic_client_model_name() {
        let client = AnthropicClient::new("sk-ant-x", "claude-opus-4-5");
        assert_eq!(client.model_name(), "claude-opus-4-5");
    }

    // ── LocalOllamaClient model name ─────────────────────────────────────────

    #[test]
    fn test_ollama_client_model_name() {
        let client = LocalOllamaClient::new("llama3");
        assert_eq!(client.model_name(), "llama3");
        assert_eq!(client.max_context_tokens(), 32_768);
    }

    #[test]
    fn test_ollama_client_custom_host() {
        let client = LocalOllamaClient::new_at("192.168.1.5", 11434, "mistral");
        assert_eq!(client.model_name(), "mistral");
    }

    // ── TokenUsage arithmetic ────────────────────────────────────────────────

    #[test]
    fn test_token_usage_total() {
        let u = TokenUsage {
            prompt: 100,
            completion: 50,
            total: 150,
        };
        assert_eq!(u.total, u.prompt + u.completion);
    }
}

// ─── Spec-required types ──────────────────────────────────────────────────────

/// Role in an LLM conversation (spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmRole {
    System,
    User,
    Assistant,
}

impl std::fmt::Display for LlmRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Single message for spec LLM API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    pub role: LlmRole,
    pub content: String,
}

impl LlmMessage {
    #[must_use]
    pub fn user(c: impl Into<String>) -> Self {
        Self {
            role: LlmRole::User,
            content: c.into(),
        }
    }

    #[must_use]
    pub fn system(c: impl Into<String>) -> Self {
        Self {
            role: LlmRole::System,
            content: c.into(),
        }
    }

    #[must_use]
    pub fn assistant(c: impl Into<String>) -> Self {
        Self {
            role: LlmRole::Assistant,
            content: c.into(),
        }
    }
}

impl From<Message> for LlmMessage {
    fn from(m: Message) -> Self {
        let role = match m.role.as_str() {
            "system" => LlmRole::System,
            "assistant" => LlmRole::Assistant,
            _ => LlmRole::User,
        };
        Self {
            role,
            content: m.content,
        }
    }
}

impl From<&Message> for LlmMessage {
    fn from(m: &Message) -> Self {
        Self::from(m.clone())
    }
}

/// Model identifier (spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlmModel {
    Gpt4,
    Gpt35Turbo,
    Claude3Opus,
    Claude3Sonnet,
    Claude3Haiku,
    Llama3,
    Custom(String),
}

impl std::fmt::Display for LlmModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// Configuration for an LLM call (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub model: LlmModel,
    pub api_key: String,
    pub base_url: String,
    pub max_tokens: u32,
    pub temperature: f32,
}

impl LlmConfig {
    #[must_use]
    pub fn new(model: LlmModel, api_key: impl Into<String>) -> Self {
        Self {
            model,
            api_key: api_key.into(),
            base_url: "https://api.openai.com".to_string(),
            max_tokens: 4096,
            temperature: 0.2,
        }
    }

    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    #[must_use]
    pub const fn with_max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = n;
        self
    }

    #[must_use]
    pub const fn with_temperature(mut self, t: f32) -> Self {
        self.temperature = t;
        self
    }
}

/// Token usage statistics (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// A single completion choice (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmChoice {
    pub text: String,
    pub finish_reason: String,
    pub index: u32,
}

/// Full LLM response (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub choices: Vec<LlmChoice>,
    pub usage: LlmUsage,
    pub model: String,
}

impl LlmResponse {
    #[must_use]
    pub fn first_text(&self) -> Option<&str> {
        self.choices.first().map(|c| c.text.as_str())
    }
}

/// LLM provider errors (spec).
#[derive(Debug, thiserror::Error)]
pub enum LlmProviderError {
    #[error("API error {code}: {message}")]
    ApiError { code: u32, message: String },
    #[error("request timed out")]
    Timeout,
    #[error("rate limited")]
    RateLimit,
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("parse error: {0}")]
    Parse(String),
}

/// LLM provider trait (spec).
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &str;
    async fn complete(
        &self,
        messages: Vec<LlmMessage>,
        config: &LlmConfig,
    ) -> Result<LlmResponse, LlmProviderError>;
}

/// Mock LLM provider with queued responses (spec).
pub struct MockLlmProvider {
    pub responses: parking_lot::Mutex<Vec<String>>,
}

impl MockLlmProvider {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            responses: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn queue(&self, response: impl Into<String>) {
        self.responses.lock().push(response.into());
    }
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmProvider for MockLlmProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn complete(
        &self,
        _messages: Vec<LlmMessage>,
        config: &LlmConfig,
    ) -> Result<LlmResponse, LlmProviderError> {
        let text = {
            let mut lock = self.responses.lock();
            if lock.is_empty() {
                "mock response".to_string()
            } else if lock.len() == 1 {
                lock[0].clone()
            } else {
                lock.remove(0)
            }
        };
        Ok(LlmResponse {
            choices: vec![LlmChoice {
                text,
                finish_reason: "stop".to_string(),
                index: 0,
            }],
            usage: LlmUsage {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            },
            model: config.model.to_string(),
        })
    }
}

#[cfg(test)]
mod spec_tests {
    use super::*;

    #[test]
    fn test_llm_role_display() {
        assert_eq!(LlmRole::System.to_string(), "System");
        assert_eq!(LlmRole::User.to_string(), "User");
        assert_eq!(LlmRole::Assistant.to_string(), "Assistant");
    }

    #[test]
    fn test_llm_message_constructors() {
        let u = LlmMessage::user("hello");
        assert_eq!(u.role, LlmRole::User);
        assert_eq!(u.content, "hello");
        let s = LlmMessage::system("sys");
        assert_eq!(s.role, LlmRole::System);
        let a = LlmMessage::assistant("ans");
        assert_eq!(a.role, LlmRole::Assistant);
    }

    #[test]
    fn test_llm_model_display() {
        assert_eq!(LlmModel::Gpt4.to_string(), "Gpt4");
        assert_eq!(
            LlmModel::Custom("my-model".to_string()).to_string(),
            "custom:my-model"
        );
    }

    #[test]
    fn test_llm_config_builder() {
        let cfg = LlmConfig::new(LlmModel::Gpt4, "sk-x")
            .with_base_url("https://example.com")
            .with_max_tokens(1024)
            .with_temperature(0.5);
        assert_eq!(cfg.max_tokens, 1024);
        assert!((cfg.temperature - 0.5).abs() < f32::EPSILON);
        assert_eq!(cfg.base_url, "https://example.com");
    }

    #[test]
    fn test_llm_config_defaults() {
        let cfg = LlmConfig::new(LlmModel::Claude3Haiku, "key");
        assert_eq!(cfg.max_tokens, 4096);
        assert_eq!(cfg.model, LlmModel::Claude3Haiku);
    }

    #[test]
    fn test_llm_response_first_text_some() {
        let r = LlmResponse {
            choices: vec![LlmChoice {
                text: "answer".to_string(),
                finish_reason: "stop".to_string(),
                index: 0,
            }],
            usage: LlmUsage {
                prompt_tokens: 5,
                completion_tokens: 2,
                total_tokens: 7,
            },
            model: "gpt-4".to_string(),
        };
        assert_eq!(r.first_text(), Some("answer"));
    }

    #[test]
    fn test_llm_response_first_text_none() {
        let r = LlmResponse {
            choices: vec![],
            usage: LlmUsage {
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0,
            },
            model: "x".to_string(),
        };
        assert_eq!(r.first_text(), None);
    }

    #[tokio::test]
    async fn test_mock_provider_queued() {
        let p = MockLlmProvider::new();
        p.queue("first");
        p.queue("second");
        let cfg = LlmConfig::new(LlmModel::Gpt4, "");
        let r1 = p.complete(vec![], &cfg).await.unwrap();
        assert_eq!(r1.first_text(), Some("first"));
        let r2 = p.complete(vec![], &cfg).await.unwrap();
        assert_eq!(r2.first_text(), Some("second"));
    }

    #[tokio::test]
    async fn test_mock_provider_repeats_last() {
        let p = MockLlmProvider::new();
        p.queue("only");
        let cfg = LlmConfig::new(LlmModel::Llama3, "");
        let r1 = p.complete(vec![], &cfg).await.unwrap();
        let r2 = p.complete(vec![], &cfg).await.unwrap();
        assert_eq!(r1.first_text(), Some("only"));
        assert_eq!(r2.first_text(), Some("only"));
    }

    #[tokio::test]
    async fn test_mock_provider_default_response() {
        let p = MockLlmProvider::new();
        let cfg = LlmConfig::new(LlmModel::Claude3Sonnet, "");
        let r = p.complete(vec![], &cfg).await.unwrap();
        assert_eq!(r.first_text(), Some("mock response"));
    }

    #[test]
    fn test_mock_provider_name() {
        let p = MockLlmProvider::new();
        assert_eq!(p.name(), "mock");
    }

    #[test]
    fn test_llm_provider_error_display() {
        let e = LlmProviderError::ApiError {
            code: 429,
            message: "rate limited".to_string(),
        };
        assert!(e.to_string().contains("429"));
        let e2 = LlmProviderError::Timeout;
        assert!(e2.to_string().contains("timed out"));
        let e3 = LlmProviderError::RateLimit;
        assert!(e3.to_string().contains("rate"));
        let e4 = LlmProviderError::InvalidConfig("bad url".to_string());
        assert!(e4.to_string().contains("bad url"));
        let e5 = LlmProviderError::Parse("json error".to_string());
        assert!(e5.to_string().contains("json error"));
    }

    #[test]
    fn test_llm_usage_fields() {
        let u = LlmUsage {
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
        };
        assert_eq!(u.total_tokens, 15);
    }

    #[test]
    fn test_llm_choice_fields() {
        let c = LlmChoice {
            text: "hi".to_string(),
            finish_reason: "stop".to_string(),
            index: 0,
        };
        assert_eq!(c.text, "hi");
        assert_eq!(c.index, 0);
    }

    #[test]
    fn test_llm_model_all_variants() {
        let models = [LlmModel::Gpt4,
            LlmModel::Gpt35Turbo,
            LlmModel::Claude3Opus,
            LlmModel::Claude3Sonnet,
            LlmModel::Claude3Haiku,
            LlmModel::Llama3,
            LlmModel::Custom("x".to_string())];
        assert_eq!(models.len(), 7);
    }
}

// ─── LlmBackend trait ────────────────────────────────────────────────────────

/// Full-featured LLM backend trait with all capabilities.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError>;
    async fn chat(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError>;
    async fn embed(&self, text: &str) -> Result<Vec<f32>, LlmError>;
    async fn count_tokens(&self, text: &str) -> Result<u32, LlmError>;
    fn backend_name(&self) -> &str;
    fn model_id(&self) -> &str;
    fn context_length(&self) -> u32;
}

// ─── AnthropicBackend ────────────────────────────────────────────────────────

/// Claude API backend for claude-3-opus, claude-3-sonnet, etc.
/// Uses the reqwest-based V2 client for TLS-capable HTTPS connections.
pub struct AnthropicBackend {
    v2: AnthropicBackendV2,
    model: String,
}

impl AnthropicBackend {
    #[must_use]
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        let model_str: String = model.into();
        Self {
            v2: AnthropicBackendV2::new(api_key, model_str.clone(), 4096),
            model: model_str,
        }
    }

    #[must_use]
    pub fn claude_opus(api_key: impl Into<String>) -> Self {
        Self::new(api_key, "claude-opus-4-5")
    }

    #[must_use]
    pub fn claude_sonnet(api_key: impl Into<String>) -> Self {
        Self::new(api_key, "claude-sonnet-4-5")
    }

    #[must_use]
    pub fn claude_haiku(api_key: impl Into<String>) -> Self {
        Self::new(api_key, "claude-haiku-3-5")
    }

    /// Convert a `BackendResponse` from V2 into a `CompletionResponse`.
    fn backend_to_completion(
        resp: BackendResponse,
        opts: &CompletionOptions,
    ) -> CompletionResponse {
        let finish_reason = resp.stop_reason.to_string();
        let _ = opts; // max_tokens not returned by API in this path
        CompletionResponse {
            content: resp.content,
            finish_reason,
            usage: TokenUsage {
                prompt: 0,
                completion: 0,
                total: 0,
            },
        }
    }
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        // Build a temporary V2 backend with the caller-supplied max_tokens.
        let v2 = AnthropicBackendV2::new(&self.v2.api_key, &self.model, opts.max_tokens);
        let chat_msgs: Vec<ChatMessage> = messages.iter().map(ChatMessage::from).collect();
        let resp = v2.chat(&chat_msgs, &[]).await?;
        Ok(Self::backend_to_completion(resp, opts))
    }

    async fn chat(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        self.complete(messages, opts).await
    }

    async fn embed(&self, _text: &str) -> Result<Vec<f32>, LlmError> {
        // Anthropic doesn't currently offer a public embeddings API
        Err(LlmError::ParseError(
            "Anthropic does not support embeddings".to_string(),
        ))
    }

    async fn count_tokens(&self, text: &str) -> Result<u32, LlmError> {
        Ok(TokenCounter::count_text(text))
    }

    fn backend_name(&self) -> &'static str {
        "anthropic"
    }
    fn model_id(&self) -> &str {
        &self.model
    }
    fn context_length(&self) -> u32 {
        200_000
    }
}

// ─── OpenAiBackend ───────────────────────────────────────────────────────────

/// `OpenAI` API backend for gpt-4, gpt-4-turbo, etc.
/// Uses the reqwest-based V2 client for TLS-capable HTTPS connections.
pub struct OpenAiBackend {
    v2: OpenAiBackendV2,
    model: String,
}

impl OpenAiBackend {
    #[must_use]
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        let m: String = model.into();
        Self {
            v2: OpenAiBackendV2::new_openai(api_key, m.clone()),
            model: m,
        }
    }

    #[must_use]
    pub fn gpt4(api_key: impl Into<String>) -> Self {
        Self::new(api_key, "gpt-4")
    }

    #[must_use]
    pub fn gpt4_turbo(api_key: impl Into<String>) -> Self {
        Self::new(api_key, "gpt-4-turbo-preview")
    }

    #[must_use]
    pub fn gpt4o(api_key: impl Into<String>) -> Self {
        Self::new(api_key, "gpt-4o")
    }

    /// Convert a `BackendResponse` from V2 into a `CompletionResponse`.
    fn backend_to_completion(resp: BackendResponse) -> CompletionResponse {
        let finish_reason = resp.stop_reason.to_string();
        CompletionResponse {
            content: resp.content,
            finish_reason,
            usage: TokenUsage {
                prompt: 0,
                completion: 0,
                total: 0,
            },
        }
    }
}

#[async_trait]
impl LlmBackend for OpenAiBackend {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        // Build a temporary V2 backend with the caller-supplied max_tokens.
        let v2 = OpenAiBackendV2::new(
            &self.v2.api_key,
            &self.v2.base_url,
            &self.model,
            opts.max_tokens,
        );
        let chat_msgs: Vec<ChatMessage> = messages.iter().map(ChatMessage::from).collect();
        let resp = v2.chat(&chat_msgs, &[]).await?;
        Ok(Self::backend_to_completion(resp))
    }

    async fn chat(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        self.complete(messages, opts).await
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, LlmError> {
        // Simplified stub - real implementation would call text-embedding-ada-002
        let token_count = TokenCounter::count_text(text);
        let dim = 1536usize;
        let v: Vec<f32> = (0..dim)
            .map(|i| (f64_to_f32(f64::from(token_count)) + f64_to_f32(usize_to_f64(i))) / f64_to_f32(usize_to_f64(dim)))
            .collect();
        Ok(v)
    }

    async fn count_tokens(&self, text: &str) -> Result<u32, LlmError> {
        Ok(TokenCounter::count_text(text))
    }

    fn backend_name(&self) -> &'static str {
        "openai"
    }
    fn model_id(&self) -> &str {
        &self.model
    }
    fn context_length(&self) -> u32 {
        128_000
    }
}

// ─── OllamaBackend ───────────────────────────────────────────────────────────

/// Local Ollama backend.
pub struct OllamaBackend {
    client: LocalOllamaClient,
    model: String,
}

impl OllamaBackend {
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        let m: String = model.into();
        Self {
            client: LocalOllamaClient::new(m.clone()),
            model: m,
        }
    }

    #[must_use]
    pub fn at(host: impl Into<String>, port: u16, model: impl Into<String>) -> Self {
        let m: String = model.into();
        Self {
            client: LocalOllamaClient::new_at(host, port, m.clone()),
            model: m,
        }
    }
}

#[async_trait]
impl LlmBackend for OllamaBackend {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        self.client.complete(messages, opts).await
    }

    async fn chat(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        self.client.complete(messages, opts).await
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, LlmError> {
        let n = f64_to_f32(f64::from(TokenCounter::count_text(text)));
        Ok(vec![n / 1000.0; 384])
    }

    async fn count_tokens(&self, text: &str) -> Result<u32, LlmError> {
        Ok(TokenCounter::count_text(text))
    }

    fn backend_name(&self) -> &'static str {
        "ollama"
    }
    fn model_id(&self) -> &str {
        &self.model
    }
    fn context_length(&self) -> u32 {
        32_768
    }
}

// ─── HuggingFaceBackend ──────────────────────────────────────────────────────

/// `HuggingFace` Inference API backend.
pub struct HuggingFaceBackend {
    model: String,
    api_key: String,
    max_context: u32,
}

impl HuggingFaceBackend {
    #[must_use]
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            api_key: api_key.into(),
            max_context: 4096,
        }
    }

    /// Build the `Authorization` header value sent to the `HuggingFace`
    /// Inference API. The API authenticates requests with a bearer token.
    #[must_use]
    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_key)
    }
}

#[async_trait]
impl LlmBackend for HuggingFaceBackend {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        let prompt: String = messages
            .iter()
            .map(|m| format!("{}: {}", m.role, m.content))
            .collect::<Vec<_>>()
            .join("\n");

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let url = format!(
            "https://api-inference.huggingface.co/models/{}/v1/chat/completions",
            self.model
        );

        let body = serde_json::json!({
            "model": self.model,
            "messages": messages.iter().map(|m| serde_json::json!({"role": m.role, "content": m.content})).collect::<Vec<_>>(),
            "max_tokens": opts.max_tokens,
            "temperature": opts.temperature,
        });

        let resp = client
            .post(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.text().await.unwrap_or_default();
            return Err(LlmError::HttpError { status, body });
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| LlmError::ParseError(e.to_string()))?;

        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let finish_reason = json["choices"][0]["finish_reason"]
            .as_str()
            .unwrap_or("stop")
            .to_string();
        let prompt_tokens = u64_to_u32(json["usage"]["prompt_tokens"].as_u64().unwrap_or(0));
        let completion_tokens = u64_to_u32(json["usage"]["completion_tokens"].as_u64().unwrap_or(0));

        let _ = prompt; // suppress unused warning — prompt is only used for fallback logging
        Ok(CompletionResponse {
            content,
            finish_reason,
            usage: TokenUsage {
                prompt: prompt_tokens,
                completion: completion_tokens,
                total: prompt_tokens.saturating_add(completion_tokens),
            },
        })
    }

    async fn chat(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        self.complete(messages, opts).await
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, LlmError> {
        let n = f64_to_f32(f64::from(TokenCounter::count_text(text)));
        Ok(vec![n / 1000.0; 768])
    }

    async fn count_tokens(&self, text: &str) -> Result<u32, LlmError> {
        Ok(TokenCounter::count_text(text))
    }

    fn backend_name(&self) -> &'static str {
        "huggingface"
    }
    fn model_id(&self) -> &str {
        &self.model
    }
    fn context_length(&self) -> u32 {
        self.max_context
    }
}

// ─── LlamaCppBackend ─────────────────────────────────────────────────────────

/// llama.cpp server API backend.
pub struct LlamaCppBackend {
    model: String,
    host: String,
    port: u16,
}

impl LlamaCppBackend {
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            host: host.into(),
            port,
        }
    }

    #[must_use]
    pub fn localhost(port: u16, model: impl Into<String>) -> Self {
        Self::new("localhost", port, model)
    }
}

#[async_trait]
impl LlmBackend for LlamaCppBackend {
    async fn complete(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        let msgs: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| serde_json::json!({"role": m.role, "content": m.content}))
            .collect();
        let body = serde_json::json!({
            "model": self.model,
            "messages": msgs,
            "n_predict": opts.max_tokens,
            "temperature": opts.temperature,
        });
        let body_str = serde_json::to_string(&body)?;
        let (status, resp) = http_post(
            &self.host,
            self.port,
            "/v1/chat/completions",
            &HashMap::new(),
            &body_str,
        )
        .await?;
        if status != 200 {
            return Err(LlmError::HttpError { status, body: resp });
        }
        let json: serde_json::Value =
            serde_json::from_str(&resp).map_err(|e| LlmError::ParseError(e.to_string()))?;
        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok(CompletionResponse {
            content,
            finish_reason: "stop".to_string(),
            usage: TokenUsage {
                prompt: 0,
                completion: 0,
                total: 0,
            },
        })
    }

    async fn chat(
        &self,
        messages: &[Message],
        opts: &CompletionOptions,
    ) -> Result<CompletionResponse, LlmError> {
        self.complete(messages, opts).await
    }

    async fn embed(&self, text: &str) -> Result<Vec<f32>, LlmError> {
        let n = f64_to_f32(f64::from(TokenCounter::count_text(text)));
        Ok(vec![n / 500.0; 4096])
    }

    async fn count_tokens(&self, text: &str) -> Result<u32, LlmError> {
        Ok(TokenCounter::count_text(text))
    }

    fn backend_name(&self) -> &'static str {
        "llama-cpp"
    }
    fn model_id(&self) -> &str {
        &self.model
    }
    fn context_length(&self) -> u32 {
        131_072
    }
}

// ─── ChatRequest / ChatResponse ──────────────────────────────────────────────

/// A structured chat request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: f32,
    pub max_tokens: u32,
    pub stop_sequences: Vec<String>,
    pub stream: bool,
}

impl ChatRequest {
    #[must_use]
    pub fn new(model: impl Into<String>, messages: Vec<Message>) -> Self {
        Self {
            model: model.into(),
            messages,
            temperature: 0.2,
            max_tokens: 4096,
            stop_sequences: Vec::new(),
            stream: false,
        }
    }

    #[must_use]
    pub const fn with_temperature(mut self, t: f32) -> Self {
        self.temperature = t;
        self
    }
    #[must_use]
    pub const fn with_max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = n;
        self
    }
    #[must_use]
    pub fn with_stop(mut self, seqs: Vec<String>) -> Self {
        self.stop_sequences = seqs;
        self
    }
    #[must_use]
    pub const fn streaming(mut self) -> Self {
        self.stream = true;
        self
    }
}

/// A structured chat response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub content: String,
    pub finish_reason: String,
    pub model: String,
    pub usage: TokenUsage,
}

// ─── EmbeddingRequest / EmbeddingResponse ────────────────────────────────────

/// Request to embed text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    pub model: String,
    pub text: String,
    pub normalize: bool,
}

impl EmbeddingRequest {
    #[must_use]
    pub fn new(model: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            text: text.into(),
            normalize: true,
        }
    }
}

/// Response containing an embedding vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    pub embedding: Vec<f32>,
    pub model: String,
    pub token_count: u32,
}

impl EmbeddingResponse {
    #[must_use]
    pub fn new(embedding: Vec<f32>, model: impl Into<String>, token_count: u32) -> Self {
        Self {
            embedding,
            model: model.into(),
            token_count,
        }
    }

    /// Cosine similarity with another embedding.
    #[must_use]
    pub fn cosine_similarity(&self, other: &Self) -> f32 {
        if self.embedding.len() != other.embedding.len() {
            return 0.0;
        }
        let dot: f32 = self
            .embedding
            .iter()
            .zip(other.embedding.iter())
            .map(|(a, b)| a * b)
            .sum();
        let norm_a: f32 = self.embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = other.embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        // `== 0.0` catches neither NaN nor infinity: an embedding carrying
        // either would slip through and `clamp` propagates NaN rather than
        // sanitising it, so the "similarity" would poison every comparison it
        // takes part in. Require a finite, non-zero norm outright.
        if !norm_a.is_finite() || !norm_b.is_finite() || norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        let cos = dot / (norm_a * norm_b);
        if cos.is_nan() {
            return 0.0;
        }
        cos.clamp(-1.0, 1.0)
    }
}

// ─── LlmCache ────────────────────────────────────────────────────────────────

/// Simple in-memory cache for LLM completions.
pub struct LlmCache {
    entries: parking_lot::Mutex<std::collections::HashMap<u64, (String, std::time::Instant)>>,
    max_age_secs: u64,
    capacity: usize,
}

impl LlmCache {
    #[must_use]
    pub fn new(capacity: usize, max_age_secs: u64) -> Self {
        Self {
            entries: parking_lot::Mutex::new(std::collections::HashMap::new()),
            max_age_secs,
            capacity,
        }
    }

    fn cache_key(messages: &[Message], opts: &CompletionOptions) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for m in messages {
            for b in m.content.bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        h ^= u64::from(f64_to_u32(f64::from(opts.temperature) * 1000.0));
        h ^= u64::from(opts.max_tokens);
        h
    }

    pub fn get(&self, messages: &[Message], opts: &CompletionOptions) -> Option<String> {
        let key = Self::cache_key(messages, opts);
        let guard = self.entries.lock();
        let result = guard.get(&key)
            .filter(|(_, created)| created.elapsed().as_secs() < self.max_age_secs)
            .map(|(val, _)| val.clone());
        drop(guard);
        result
    }

    pub fn insert(&self, messages: &[Message], opts: &CompletionOptions, response: String) {
        let key = Self::cache_key(messages, opts);
        let mut guard = self.entries.lock();
        if guard.len() >= self.capacity {
            // Remove oldest entry
            // HashMap iteration order is not reproducible and `Instant`s tie
            // easily, so break the tie on the key itself.
            if let Some(&oldest_key) = guard
                .iter()
                .min_by(|a, b| a.1 .1.cmp(&b.1 .1).then(a.0.cmp(b.0)))
                .map(|(k, _)| k)
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(key, (response, std::time::Instant::now()));
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

// ─── LlmRetry ────────────────────────────────────────────────────────────────

/// Exponential backoff retry configuration for LLM calls.
#[derive(Debug, Clone)]
pub struct LlmRetry {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub exponential: bool,
}

impl LlmRetry {
    #[must_use]
    pub const fn new(max_attempts: u32, initial_delay_ms: u64) -> Self {
        Self {
            max_attempts,
            initial_delay_ms,
            max_delay_ms: 30_000,
            exponential: true,
        }
    }

    #[must_use]
    pub const fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            initial_delay_ms: 0,
            max_delay_ms: 0,
            exponential: false,
        }
    }

    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        if attempt == 0 {
            return 0;
        }
        let base = self.initial_delay_ms;
        let delay = if self.exponential {
            base.saturating_mul(2u64.saturating_pow(attempt - 1))
        } else {
            base
        };
        delay.min(self.max_delay_ms)
    }
}

impl Default for LlmRetry {
    fn default() -> Self {
        Self::new(3, 1000)
    }
}

// ─── LlmRateLimiter ──────────────────────────────────────────────────────────

/// Internal state for `LlmRateLimiter`, kept under a single lock to eliminate
/// TOCTOU races and nested-lock deadlock risk.
struct RateLimiterState {
    budget: u32,
    last_reset: std::time::Instant,
}

/// Token-bucket rate limiter for API calls (tokens per minute).
pub struct LlmRateLimiter {
    tokens_per_minute: u32,
    state: parking_lot::Mutex<RateLimiterState>,
}

impl LlmRateLimiter {
    #[must_use]
    pub fn new(tokens_per_minute: u32) -> Self {
        Self {
            tokens_per_minute,
            state: parking_lot::Mutex::new(RateLimiterState {
                budget: tokens_per_minute,
                last_reset: std::time::Instant::now(),
            }),
        }
    }

    /// Try to consume `tokens` from the bucket. Returns `true` if granted.
    /// All reads and writes happen under a single lock acquisition, preventing
    /// TOCTOU races and nested-lock deadlocks.
    pub fn try_consume(&self, tokens: u32) -> bool {
        let now = std::time::Instant::now();
        let mut state = self.state.lock();
        if now.duration_since(state.last_reset).as_secs() >= 60 {
            state.budget = self.tokens_per_minute;
            state.last_reset = now;
        }
        if state.budget >= tokens {
            state.budget -= tokens;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.state.lock().budget
    }
}

// ─── LlmCostTracker ──────────────────────────────────────────────────────────

/// Tracks API usage costs per session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmCostTracker {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub requests: u64,
    /// Cost in USD (approximate).
    pub estimated_cost_usd: f64,
}

impl LlmCostTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a usage event with model-specific pricing.
    pub fn record(
        &mut self,
        usage: &TokenUsage,
        prompt_cost_per_1k: f64,
        completion_cost_per_1k: f64,
    ) {
        self.prompt_tokens += u64::from(usage.prompt);
        self.completion_tokens += u64::from(usage.completion);
        self.requests += 1;
        self.estimated_cost_usd += (f64::from(usage.prompt) / 1000.0).mul_add(prompt_cost_per_1k, (f64::from(usage.completion) / 1000.0) * completion_cost_per_1k);
    }

    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ─── LlmStreamingResponse ────────────────────────────────────────────────────

/// Represents a streaming LLM response (collected token-by-token).
#[derive(Debug, Clone, Default)]
pub struct LlmStreamingResponse {
    tokens: Vec<String>,
    is_complete: bool,
    finish_reason: Option<String>,
}

impl LlmStreamingResponse {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_token(&mut self, token: impl Into<String>) {
        self.tokens.push(token.into());
    }

    pub fn complete(&mut self, reason: impl Into<String>) {
        self.is_complete = true;
        self.finish_reason = Some(reason.into());
    }

    #[must_use]
    pub fn text(&self) -> String {
        self.tokens.join("")
    }

    #[must_use]
    pub const fn token_count(&self) -> usize {
        self.tokens.len()
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.is_complete
    }
}

// ─── LlmFunctionCall ─────────────────────────────────────────────────────────

/// A function call requested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmFunctionCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

impl LlmFunctionCall {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments,
        }
    }
}

/// Result of a function call to return to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmFunctionResult {
    pub call_id: String,
    pub name: String,
    pub content: serde_json::Value,
    pub is_error: bool,
}

impl LlmFunctionResult {
    #[must_use]
    pub fn success(
        call_id: impl Into<String>,
        name: impl Into<String>,
        content: serde_json::Value,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            name: name.into(),
            content,
            is_error: false,
        }
    }

    #[must_use]
    pub fn error(
        call_id: impl Into<String>,
        name: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            name: name.into(),
            content: serde_json::json!({"error": error.into()}),
            is_error: true,
        }
    }
}

// ─── LlmSystemPrompt builder ─────────────────────────────────────────────────

/// Builds system prompts specific to RE tasks.
pub struct LlmSystemPrompt {
    role: String,
    context_sections: Vec<(String, String)>,
    output_format: Option<String>,
    constraints: Vec<String>,
}

impl LlmSystemPrompt {
    #[must_use]
    pub fn re_expert() -> Self {
        Self {
            role: "You are an expert reverse engineer with deep knowledge of binary analysis, \
                   assembly languages, decompilers, malware analysis, and vulnerability research."
                .to_string(),
            context_sections: Vec::new(),
            output_format: None,
            constraints: Vec::new(),
        }
    }

    #[must_use]
    pub fn malware_analyst() -> Self {
        Self {
            role: "You are an expert malware analyst specializing in static and dynamic analysis, \
                   threat intelligence, and MITRE ATT&CK framework mapping."
                .to_string(),
            context_sections: Vec::new(),
            output_format: None,
            constraints: Vec::new(),
        }
    }

    #[must_use]
    pub fn vuln_researcher() -> Self {
        Self {
            role: "You are a vulnerability researcher specializing in binary exploitation, \
                   CVE analysis, and security assessment."
                .to_string(),
            context_sections: Vec::new(),
            output_format: None,
            constraints: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, title: impl Into<String>, content: impl Into<String>) -> Self {
        self.context_sections.push((title.into(), content.into()));
        self
    }

    #[must_use]
    pub fn with_output_format(mut self, format: impl Into<String>) -> Self {
        self.output_format = Some(format.into());
        self
    }

    #[must_use]
    pub fn with_constraint(mut self, c: impl Into<String>) -> Self {
        self.constraints.push(c.into());
        self
    }

    /// Build the final system prompt string.
    #[must_use]
    pub fn build(&self) -> String {
        let mut prompt = self.role.clone();
        for (title, content) in &self.context_sections {
            let _ = write!(prompt, "\n\n{title}:\n{content}");
        }
        if let Some(fmt) = &self.output_format {
            let _ = write!(prompt, "\n\nOutput format: {fmt}");
        }
        if !self.constraints.is_empty() {
            prompt.push_str("\n\nConstraints:");
            for c in &self.constraints {
                let _ = write!(prompt, "\n- {c}");
            }
        }
        prompt
    }
}

// ─── LlmPromptTemplate ───────────────────────────────────────────────────────

/// A prompt template with variable substitution.
#[derive(Debug, Clone)]
pub struct LlmPromptTemplate {
    pub name: String,
    pub template: String,
}

impl LlmPromptTemplate {
    #[must_use]
    pub fn new(name: impl Into<String>, template: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            template: template.into(),
        }
    }

    /// Render the template substituting `{{key}}` with values from `vars`.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::ParseError`] if a `{{key}}` placeholder has no corresponding entry in `vars`.
    pub fn render(
        &self,
        vars: &std::collections::HashMap<String, String>,
    ) -> Result<String, LlmError> {
        let mut output = self.template.clone();
        let mut pos = 0usize;
        while let Some(i) = output[pos..].find("{{") {
            let start = pos + i;
            let Some(end_rel) = output[start..].find("}}") else {
                break;
            };
            let end = start + end_rel;
            let key = output[start + 2..end].trim().to_string();
            let value = vars.get(&key).cloned().ok_or_else(|| {
                LlmError::ParseError(format!("missing template variable: {key}"))
            })?;
            output.replace_range(start..end + 2, &value);
            pos = start + value.len();
        }
        Ok(output)
    }
}

// ─── LlmContextWindow ────────────────────────────────────────────────────────

/// Manages the context window, truncating to fit the model's limit.
pub struct LlmContextWindow {
    pub max_tokens: u32,
    pub system: Option<Message>,
    pub history: Vec<Message>,
}

impl LlmContextWindow {
    #[must_use]
    pub const fn new(max_tokens: u32) -> Self {
        Self {
            max_tokens,
            system: None,
            history: Vec::new(),
        }
    }

    pub fn set_system(&mut self, content: impl Into<String>) {
        self.system = Some(Message::system(content));
    }

    pub fn push(&mut self, msg: Message) {
        self.history.push(msg);
    }

    #[must_use]
    pub fn build(&self) -> Vec<Message> {
        let sys_tokens = self
            .system
            .as_ref()
            .map_or(0, |s| TokenCounter::count_text(&s.content) + 4);
        let budget = self.max_tokens.saturating_sub(sys_tokens + 512);
        let mut selected: Vec<&Message> = Vec::new();
        let mut used = 0u32;
        for msg in self.history.iter().rev() {
            let cost = TokenCounter::count_text(&msg.content) + 4;
            if used + cost > budget {
                break;
            }
            used += cost;
            selected.push(msg);
        }
        selected.reverse();
        let mut out = Vec::new();
        if let Some(s) = &self.system {
            out.push(s.clone());
        }
        out.extend(selected.into_iter().cloned());
        out
    }

    #[must_use]
    pub fn used_tokens(&self) -> u32 {
        let msgs = self.build();
        TokenCounter::count_messages(&msgs)
    }

    #[must_use]
    pub fn remaining_tokens(&self) -> u32 {
        self.max_tokens.saturating_sub(self.used_tokens())
    }
}

// ─── LlmJsonMode ─────────────────────────────────────────────────────────────

/// Helper for structured JSON output from LLMs.
pub struct LlmJsonMode;

impl LlmJsonMode {
    /// Wrap a prompt to request JSON output.
    #[must_use]
    pub fn wrap_prompt(prompt: &str) -> String {
        format!("{prompt}\n\nRespond with ONLY valid JSON, no other text or markdown.")
    }

    /// Parse and validate JSON from LLM output.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::ParseError`] if the response (with or without code fences) is not valid JSON.
    pub fn parse(response: &str) -> Result<serde_json::Value, LlmError> {
        let trimmed = response.trim();
        if let Ok(v) = serde_json::from_str(trimmed) {
            return Ok(v);
        }
        // Try stripping code fences
        let stripped = trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();
        serde_json::from_str(stripped).map_err(|e| LlmError::ParseError(e.to_string()))
    }

    /// Validate that a JSON value matches an expected schema shape.
    ///
    /// # Errors
    ///
    /// Returns [`LlmError::ParseError`] if any required key is missing from `value`.
    pub fn validate_keys(
        value: &serde_json::Value,
        required_keys: &[&str],
    ) -> Result<(), LlmError> {
        let obj = value
            .as_object()
            .ok_or_else(|| LlmError::ParseError("expected JSON object".into()))?;
        for key in required_keys {
            if !obj.contains_key(*key) {
                return Err(LlmError::ParseError(format!("missing required key: {key}")));
            }
        }
        Ok(())
    }
}

// ─── Extended tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;
    use std::collections::HashMap;

    // ── AnthropicBackend ─────────────────────────────────────────────────────
    #[test]
    fn test_anthropic_backend_fields() {
        let b = AnthropicBackend::claude_opus("key");
        assert_eq!(b.backend_name(), "anthropic");
        assert_eq!(b.context_length(), 200_000);
        assert!(b.model_id().contains("opus"));
    }

    #[test]
    fn test_anthropic_backend_sonnet() {
        let b = AnthropicBackend::claude_sonnet("key");
        assert!(b.model_id().contains("sonnet"));
    }

    #[test]
    fn test_anthropic_backend_haiku() {
        let b = AnthropicBackend::claude_haiku("key");
        assert!(b.model_id().contains("haiku"));
    }

    // ── OpenAiBackend ────────────────────────────────────────────────────────
    #[test]
    fn test_openai_backend_fields() {
        let b = OpenAiBackend::gpt4("key");
        assert_eq!(b.backend_name(), "openai");
        assert_eq!(b.context_length(), 128_000);
    }

    #[test]
    fn test_openai_backend_gpt4o() {
        let b = OpenAiBackend::gpt4o("key");
        assert_eq!(b.model_id(), "gpt-4o");
    }

    // ── OllamaBackend ────────────────────────────────────────────────────────
    #[test]
    fn test_ollama_backend_fields() {
        let b = OllamaBackend::new("llama3");
        assert_eq!(b.backend_name(), "ollama");
        assert_eq!(b.model_id(), "llama3");
    }

    #[test]
    fn test_ollama_backend_at() {
        let b = OllamaBackend::at("192.168.1.1", 11434, "mistral");
        assert_eq!(b.model_id(), "mistral");
    }

    // ── HuggingFaceBackend ───────────────────────────────────────────────────
    #[test]
    fn test_hf_backend_fields() {
        let b = HuggingFaceBackend::new("hf_key", "mistralai/Mistral-7B-v0.1");
        assert_eq!(b.backend_name(), "huggingface");
    }

    #[test]
    fn test_hf_backend_auth_header() {
        let b = HuggingFaceBackend::new("hf_secret_token", "mistralai/Mistral-7B-v0.1");
        assert_eq!(b.auth_header(), "Bearer hf_secret_token");
    }

    // ── LlamaCppBackend ──────────────────────────────────────────────────────
    #[test]
    fn test_llamacpp_backend_fields() {
        let b = LlamaCppBackend::localhost(8080, "llama3.1");
        assert_eq!(b.backend_name(), "llama-cpp");
        assert_eq!(b.context_length(), 131_072);
    }

    // ── ChatRequest ──────────────────────────────────────────────────────────
    #[test]
    fn test_chat_request_builder() {
        let req = ChatRequest::new("gpt-4", vec![Message::user("hello")])
            .with_temperature(0.5)
            .with_max_tokens(1000)
            .with_stop(vec!["STOP".to_string()])
            .streaming();
        assert_eq!(req.temperature, 0.5);
        assert_eq!(req.max_tokens, 1000);
        assert!(req.stream);
        assert!(!req.stop_sequences.is_empty());
    }

    // ── EmbeddingResponse ────────────────────────────────────────────────────
    #[test]
    fn test_embedding_cosine_similarity_identical() {
        let e1 = EmbeddingResponse::new(vec![1.0, 0.0], "m", 5);
        let e2 = EmbeddingResponse::new(vec![1.0, 0.0], "m", 5);
        let sim = e1.cosine_similarity(&e2);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_embedding_cosine_similarity_orthogonal() {
        let e1 = EmbeddingResponse::new(vec![1.0, 0.0], "m", 5);
        let e2 = EmbeddingResponse::new(vec![0.0, 1.0], "m", 5);
        let sim = e1.cosine_similarity(&e2);
        assert!(sim.abs() < 1e-6);
    }

    #[test]
    fn test_embedding_cosine_similarity_different_len() {
        let e1 = EmbeddingResponse::new(vec![1.0], "m", 1);
        let e2 = EmbeddingResponse::new(vec![1.0, 2.0], "m", 2);
        assert_eq!(e1.cosine_similarity(&e2), 0.0);
    }

    // ── LlmCache ─────────────────────────────────────────────────────────────
    #[test]
    fn test_llm_cache_miss() {
        let cache = LlmCache::new(100, 60);
        let msgs = vec![Message::user("hello")];
        let opts = CompletionOptions::default();
        assert!(cache.get(&msgs, &opts).is_none());
    }

    #[test]
    fn test_llm_cache_hit() {
        let cache = LlmCache::new(100, 60);
        let msgs = vec![Message::user("hello")];
        let opts = CompletionOptions::default();
        cache.insert(&msgs, &opts, "cached response".to_string());
        assert_eq!(cache.get(&msgs, &opts), Some("cached response".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_llm_cache_clear() {
        let cache = LlmCache::new(100, 60);
        let msgs = vec![Message::user("x")];
        cache.insert(&msgs, &CompletionOptions::default(), "r".to_string());
        cache.clear();
        assert!(cache.is_empty());
    }

    // ── LlmRetry ─────────────────────────────────────────────────────────────
    #[test]
    fn test_llm_retry_exponential() {
        let r = LlmRetry::new(5, 1000);
        assert_eq!(r.delay_for_attempt(0), 0);
        assert_eq!(r.delay_for_attempt(1), 1000);
        assert_eq!(r.delay_for_attempt(2), 2000);
        assert_eq!(r.delay_for_attempt(3), 4000);
    }

    #[test]
    fn test_llm_retry_linear() {
        let r = LlmRetry {
            max_attempts: 3,
            initial_delay_ms: 500,
            max_delay_ms: 5000,
            exponential: false,
        };
        assert_eq!(r.delay_for_attempt(1), 500);
        assert_eq!(r.delay_for_attempt(2), 500);
    }

    #[test]
    fn test_llm_retry_cap() {
        let r = LlmRetry {
            max_attempts: 10,
            initial_delay_ms: 1000,
            max_delay_ms: 5000,
            exponential: true,
        };
        assert!(r.delay_for_attempt(10) <= 5000);
    }

    #[test]
    fn test_llm_retry_no_retry() {
        let r = LlmRetry::no_retry();
        assert_eq!(r.max_attempts, 1);
        assert_eq!(r.delay_for_attempt(0), 0);
    }

    // ── LlmRateLimiter ───────────────────────────────────────────────────────
    #[test]
    fn test_rate_limiter_consume() {
        let rl = LlmRateLimiter::new(1000);
        assert!(rl.try_consume(100));
        assert_eq!(rl.remaining(), 900);
        assert!(rl.try_consume(900));
        assert!(!rl.try_consume(1));
    }

    // ── LlmCostTracker ───────────────────────────────────────────────────────
    #[test]
    fn test_cost_tracker_record() {
        let mut t = LlmCostTracker::new();
        let usage = TokenUsage {
            prompt: 1000,
            completion: 500,
            total: 1500,
        };
        t.record(&usage, 0.01, 0.03);
        assert_eq!(t.prompt_tokens, 1000);
        assert_eq!(t.completion_tokens, 500);
        assert_eq!(t.requests, 1);
        assert!((t.estimated_cost_usd - 0.025).abs() < 0.001);
    }

    #[test]
    fn test_cost_tracker_total_tokens() {
        let mut t = LlmCostTracker::new();
        t.prompt_tokens = 500;
        t.completion_tokens = 300;
        assert_eq!(t.total_tokens(), 800);
    }

    #[test]
    fn test_cost_tracker_reset() {
        let mut t = LlmCostTracker::new();
        let usage = TokenUsage {
            prompt: 100,
            completion: 50,
            total: 150,
        };
        t.record(&usage, 0.01, 0.01);
        t.reset();
        assert_eq!(t.total_tokens(), 0);
        assert_eq!(t.requests, 0);
    }

    // ── LlmStreamingResponse ──────────────────────────────────────────────────
    #[test]
    fn test_streaming_response() {
        let mut r = LlmStreamingResponse::new();
        r.push_token("Hello");
        r.push_token(" world");
        r.complete("stop");
        assert_eq!(r.text(), "Hello world");
        assert_eq!(r.token_count(), 2);
        assert!(r.is_complete());
    }

    // ── LlmFunctionCall ───────────────────────────────────────────────────────
    #[test]
    fn test_function_call_new() {
        let fc = LlmFunctionCall::new("call_1", "disassemble", serde_json::json!({"addr": 0x1000}));
        assert_eq!(fc.name, "disassemble");
        assert_eq!(fc.id, "call_1");
    }

    #[test]
    fn test_function_result_success() {
        let r = LlmFunctionResult::success("c1", "tool", serde_json::json!({"result": "ok"}));
        assert!(!r.is_error);
    }

    #[test]
    fn test_function_result_error() {
        let r = LlmFunctionResult::error("c2", "tool", "timeout");
        assert!(r.is_error);
    }

    // ── LlmSystemPrompt ───────────────────────────────────────────────────────
    #[test]
    fn test_system_prompt_re_expert() {
        let p = LlmSystemPrompt::re_expert()
            .with_context("Binary", "ELF x86_64")
            .with_constraint("Be concise")
            .build();
        assert!(p.contains("reverse engineer"));
        assert!(p.contains("ELF x86_64"));
        assert!(p.contains("Be concise"));
    }

    #[test]
    fn test_system_prompt_malware_analyst() {
        let p = LlmSystemPrompt::malware_analyst().build();
        assert!(p.contains("malware analyst"));
    }

    #[test]
    fn test_system_prompt_with_output_format() {
        let p = LlmSystemPrompt::re_expert()
            .with_output_format("JSON only")
            .build();
        assert!(p.contains("JSON only"));
    }

    // ── LlmPromptTemplate ────────────────────────────────────────────────────
    #[test]
    fn test_prompt_template_render() {
        let t = LlmPromptTemplate::new("test", "Analyze {{func}} at {{addr}}");
        let mut vars = HashMap::new();
        vars.insert("func".to_string(), "main".to_string());
        vars.insert("addr".to_string(), "0x1000".to_string());
        let rendered = t.render(&vars).unwrap();
        assert_eq!(rendered, "Analyze main at 0x1000");
    }

    #[test]
    fn test_prompt_template_missing_var() {
        let t = LlmPromptTemplate::new("test", "{{missing}}");
        let vars = HashMap::new();
        assert!(t.render(&vars).is_err());
    }

    // ── LlmContextWindow ──────────────────────────────────────────────────────
    #[test]
    fn test_context_window_build() {
        let mut cw = LlmContextWindow::new(2048);
        cw.set_system("RE expert");
        cw.push(Message::user("analyze function"));
        let built = cw.build();
        assert_eq!(built[0].role, "system");
        assert!(cw.used_tokens() > 0);
        assert!(cw.remaining_tokens() < 2048);
    }

    // ── LlmJsonMode ───────────────────────────────────────────────────────────
    #[test]
    fn test_json_mode_wrap() {
        let w = LlmJsonMode::wrap_prompt("analyze this");
        assert!(w.contains("analyze this"));
        assert!(w.contains("JSON"));
    }

    #[test]
    fn test_json_mode_parse_direct() {
        let v = LlmJsonMode::parse(r#"{"key": 1}"#).unwrap();
        assert_eq!(v["key"], 1);
    }

    #[test]
    fn test_json_mode_parse_fenced() {
        let v = LlmJsonMode::parse("```json\n{\"x\": true}\n```").unwrap();
        assert_eq!(v["x"], true);
    }

    #[test]
    fn test_json_mode_validate_keys_ok() {
        let v = serde_json::json!({"a": 1, "b": 2});
        assert!(LlmJsonMode::validate_keys(&v, &["a", "b"]).is_ok());
    }

    #[test]
    fn test_json_mode_validate_keys_missing() {
        let v = serde_json::json!({"a": 1});
        assert!(LlmJsonMode::validate_keys(&v, &["a", "b"]).is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// §31.2 — Multi-backend LLM layer
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Role ─────────────────────────────────────────────────────────────────────

/// Role of a message participant in a §31.2 chat conversation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
            Self::Assistant => write!(f, "assistant"),
        }
    }
}

// ─── ChatMessage (§31.2) ──────────────────────────────────────────────────────

/// A §31.2 chat message with a typed role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}

impl ChatMessage {
    #[must_use]
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: content.into(),
        }
    }

    #[must_use]
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
        }
    }

    #[must_use]
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
        }
    }

    /// Convert to a plain `Message` for use with older clients.
    #[must_use]
    pub fn to_plain(&self) -> Message {
        Message {
            role: self.role.to_string(),
            content: self.content.clone(),
        }
    }
}

impl From<Message> for ChatMessage {
    fn from(m: Message) -> Self {
        let role = match m.role.as_str() {
            "system" => Role::System,
            "assistant" => Role::Assistant,
            _ => Role::User,
        };
        Self {
            role,
            content: m.content,
        }
    }
}

impl From<&Message> for ChatMessage {
    fn from(m: &Message) -> Self {
        Self::from(m.clone())
    }
}

// ─── ToolDef ──────────────────────────────────────────────────────────────────

/// Definition of a callable tool exposed to the model (§31.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    /// Unique tool name (`snake_case`, max 64 chars).
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// JSON Schema (draft 7) for the tool's input parameters.
    pub input_schema: serde_json::Value,
}

impl ToolDef {
    /// Create a new tool definition.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
        }
    }

    /// Convenience: create a no-parameter tool.
    #[must_use]
    pub fn simple(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(
            name,
            description,
            serde_json::json!({ "type": "object", "properties": {} }),
        )
    }
}

// ─── ToolUseBlock ─────────────────────────────────────────────────────────────

/// A single tool invocation returned by the model (§31.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUseBlock {
    /// Opaque identifier assigned by the model.
    pub id: String,
    /// Name of the tool being called.
    pub name: String,
    /// Model-supplied input arguments (must match `ToolDef::input_schema`).
    pub input: serde_json::Value,
}

// ─── StopReason ───────────────────────────────────────────────────────────────

/// Why the model stopped generating (§31.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Normal end of response.
    EndTurn,
    /// Model requested one or more tool calls.
    ToolUse,
    /// Response was cut off at `max_tokens`.
    MaxTokens,
    /// A custom stop sequence was matched.
    Stop,
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndTurn => write!(f, "end_turn"),
            Self::ToolUse => write!(f, "tool_use"),
            Self::MaxTokens => write!(f, "max_tokens"),
            Self::Stop => write!(f, "stop"),
        }
    }
}

impl StopReason {
    /// Convert a string stop reason to the enum.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "end_turn" | "stop" => Self::EndTurn,
            "tool_use" | "tool_calls" => Self::ToolUse,
            "max_tokens" | "length" => Self::MaxTokens,
            _ => Self::Stop,
        }
    }
}

impl std::str::FromStr for StopReason {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

// ─── BackendResponse ─────────────────────────────────────────────────────────

/// Full response from a §31.2 backend `chat()` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendResponse {
    /// Text content of the assistant's reply (may be empty if `stop_reason == ToolUse`).
    pub content: String,
    /// Zero or more tool invocations requested by the model.
    pub tool_uses: Vec<ToolUseBlock>,
    /// Why the model stopped.
    pub stop_reason: StopReason,
}

impl BackendResponse {
    /// Convenience: create a plain text response.
    #[must_use]
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            tool_uses: Vec::new(),
            stop_reason: StopReason::EndTurn,
        }
    }

    /// True when the model has requested at least one tool call.
    #[must_use]
    pub const fn has_tool_uses(&self) -> bool {
        !self.tool_uses.is_empty()
    }
}

// ─── LlmBackendV2 trait ───────────────────────────────────────────────────────

/// §31.2 backend trait — implemented by Anthropic, `OpenAI`, and Ollama backends.
#[async_trait]
pub trait LlmBackendV2: Send + Sync {
    /// Send a chat request with optional tool definitions.
    async fn chat(
        &self,
        msgs: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<BackendResponse, LlmError>;

    /// Streaming variant — collects tokens and returns assembled response.
    /// A production implementation should return a `futures::Stream`; for now
    /// this delegates to `chat()` to keep dependency surface minimal.
    async fn streaming(
        &self,
        msgs: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<BackendResponse, LlmError> {
        self.chat(msgs, tools).await
    }

    /// Model identifier string (e.g. `"claude-opus-4-5"`, `"gpt-4o"`).
    fn model_id(&self) -> &str;

    /// Maximum output tokens the model accepts in a single call.
    fn max_tokens(&self) -> u32;
}

// ─── AnthropicBackendV2 ───────────────────────────────────────────────────────

/// §31.2 Anthropic (Claude) backend — calls `https://api.anthropic.com/v1/messages`.
pub struct AnthropicBackendV2 {
    pub api_key: String,
    pub model: String,
    pub max_tokens: u32,
    client: reqwest::Client,
}

impl AnthropicBackendV2 {
    /// Create with explicit parameters.
    ///
    /// # Panics
    ///
    /// Panics if the `reqwest` TLS client cannot be built (e.g., rustls initialisation fails).
    #[must_use]
    pub fn new(api_key: impl Into<String>, model: impl Into<String>, max_tokens: u32) -> Self {
        Self {
            api_key: api_key.into(),
            model: model.into(),
            max_tokens,
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .expect("reqwest client"),
        }
    }

    /// Create a client backed by the given `reqwest::Client` (for testing).
    #[must_use]
    pub fn with_client(
        api_key: impl Into<String>,
        model: impl Into<String>,
        max_tokens: u32,
        client: reqwest::Client,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            model: model.into(),
            max_tokens,
            client,
        }
    }

    fn build_request_body(&self, msgs: &[ChatMessage], tools: &[ToolDef]) -> serde_json::Value {
        // Anthropic separates system from conversation messages.
        let system_text: String = msgs
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        let messages: Vec<serde_json::Value> = msgs
            .iter()
            .filter(|m| m.role != Role::System)
            .map(|m| serde_json::json!({ "role": m.role.to_string(), "content": m.content }))
            .collect();

        let tool_defs: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        });

        if !system_text.is_empty() {
            body["system"] = serde_json::json!(system_text);
        }
        if !tool_defs.is_empty() {
            body["tools"] = serde_json::json!(tool_defs);
        }

        body
    }

    fn parse_response(body: &str) -> Result<BackendResponse, LlmError> {
        let json: serde_json::Value =
            serde_json::from_str(body).map_err(|e| LlmError::ParseError(e.to_string()))?;

        let stop_reason_str = json["stop_reason"].as_str().unwrap_or("end_turn");
        let stop_reason = StopReason::parse(stop_reason_str);

        let mut text_content = String::new();
        let mut tool_uses = Vec::new();

        if let Some(content_arr) = json["content"].as_array() {
            for block in content_arr {
                match block["type"].as_str() {
                    Some("text") => {
                        if let Some(t) = block["text"].as_str() {
                            text_content.push_str(t);
                        }
                    }
                    Some("tool_use") => {
                        let id = block["id"].as_str().unwrap_or("").to_string();
                        let name = block["name"].as_str().unwrap_or("").to_string();
                        let input = block["input"].clone();
                        tool_uses.push(ToolUseBlock { id, name, input });
                    }
                    _ => {}
                }
            }
        }

        Ok(BackendResponse {
            content: text_content,
            tool_uses,
            stop_reason,
        })
    }
}

#[async_trait]
impl LlmBackendV2 for AnthropicBackendV2 {
    async fn chat(
        &self,
        msgs: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<BackendResponse, LlmError> {
        let body = self.build_request_body(msgs, tools);

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let status = resp.status().as_u16();
        let resp_body = resp
            .text()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        match status {
            401 => return Err(LlmError::AuthError("invalid Anthropic API key".to_string())),
            429 => {
                return Err(LlmError::RateLimited {
                    retry_after_ms: 2000,
                });
            }
            200 => {}
            other => {
                return Err(LlmError::HttpError {
                    status: other,
                    body: resp_body,
                });
            }
        }

        Self::parse_response(&resp_body)
    }

    fn model_id(&self) -> &str {
        &self.model
    }
    fn max_tokens(&self) -> u32 {
        self.max_tokens
    }
}

// ─── OpenAiBackendV2 ─────────────────────────────────────────────────────────

/// §31.2 OpenAI-compatible backend — calls `/v1/chat/completions`.
pub struct OpenAiBackendV2 {
    pub api_key: String,
    pub base_url: String,
    pub model: String,
    pub max_tokens: u32,
    client: reqwest::Client,
}

impl OpenAiBackendV2 {
    /// Create a backend for the official `OpenAI` API.
    #[must_use]
    pub fn new_openai(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self::new(api_key, "https://api.openai.com", model, 4096)
    }

    /// Create a backend for any OpenAI-compatible endpoint.
    ///
    /// # Panics
    ///
    /// Panics if the `reqwest` TLS client cannot be built (e.g., rustls initialisation fails).
    #[must_use]
    pub fn new(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        model: impl Into<String>,
        max_tokens: u32,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into(),
            model: model.into(),
            max_tokens,
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .expect("reqwest client"),
        }
    }

    /// Inject a custom client (useful in tests with `wiremock` or similar).
    #[must_use]
    pub fn with_client(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        model: impl Into<String>,
        max_tokens: u32,
        client: reqwest::Client,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into(),
            model: model.into(),
            max_tokens,
            client,
        }
    }

    fn build_request_body(&self, msgs: &[ChatMessage], tools: &[ToolDef]) -> serde_json::Value {
        let messages: Vec<serde_json::Value> = msgs
            .iter()
            .map(|m| serde_json::json!({ "role": m.role.to_string(), "content": m.content }))
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        });

        if !tools.is_empty() {
            let tool_defs: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = serde_json::json!(tool_defs);
        }

        body
    }

    fn parse_response(body: &str) -> Result<BackendResponse, LlmError> {
        let json: serde_json::Value =
            serde_json::from_str(body).map_err(|e| LlmError::ParseError(e.to_string()))?;

        let finish_reason = json["choices"][0]["finish_reason"]
            .as_str()
            .unwrap_or("stop");
        let stop_reason = match finish_reason {
            "tool_calls" => StopReason::ToolUse,
            "length" => StopReason::MaxTokens,
            _ => StopReason::EndTurn,
        };

        let text = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let mut tool_uses = Vec::new();
        if let Some(calls) = json["choices"][0]["message"]["tool_calls"].as_array() {
            for call in calls {
                let id = call["id"].as_str().unwrap_or("").to_string();
                let name = call["function"]["name"].as_str().unwrap_or("").to_string();
                let raw_args = call["function"]["arguments"].as_str().unwrap_or("{}");
                let input =
                    serde_json::from_str(raw_args).unwrap_or_else(|_| serde_json::json!({}));
                tool_uses.push(ToolUseBlock { id, name, input });
            }
        }

        Ok(BackendResponse {
            content: text,
            tool_uses,
            stop_reason,
        })
    }
}

#[async_trait]
impl LlmBackendV2 for OpenAiBackendV2 {
    async fn chat(
        &self,
        msgs: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<BackendResponse, LlmError> {
        let body = self.build_request_body(msgs, tools);
        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let status = resp.status().as_u16();
        let resp_body = resp
            .text()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        match status {
            401 => return Err(LlmError::AuthError("invalid OpenAI API key".to_string())),
            429 => {
                return Err(LlmError::RateLimited {
                    retry_after_ms: 1000,
                });
            }
            200 => {}
            other => {
                return Err(LlmError::HttpError {
                    status: other,
                    body: resp_body,
                });
            }
        }

        Self::parse_response(&resp_body)
    }

    fn model_id(&self) -> &str {
        &self.model
    }
    fn max_tokens(&self) -> u32 {
        self.max_tokens
    }
}

// ─── OllamaBackendV2 ─────────────────────────────────────────────────────────

/// §31.2 Ollama backend — calls `/api/chat` on a local Ollama server.
pub struct OllamaBackendV2 {
    pub base_url: String,
    pub model: String,
    pub max_tokens: u32,
    client: reqwest::Client,
}

impl OllamaBackendV2 {
    /// Create a backend connecting to `http://localhost:11434`.
    #[must_use]
    pub fn localhost(model: impl Into<String>) -> Self {
        Self::new("http://localhost:11434", model, 4096)
    }

    /// Create a backend connecting to `base_url`.
    #[must_use]
    pub fn new(base_url: impl Into<String>, model: impl Into<String>, max_tokens: u32) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            max_tokens,
            client: reqwest::Client::new(),
        }
    }

    /// Inject a custom client (for testing).
    #[must_use]
    pub fn with_client(
        base_url: impl Into<String>,
        model: impl Into<String>,
        max_tokens: u32,
        client: reqwest::Client,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            max_tokens,
            client,
        }
    }

    fn build_request_body(&self, msgs: &[ChatMessage], tools: &[ToolDef]) -> serde_json::Value {
        let messages: Vec<serde_json::Value> = msgs
            .iter()
            .map(|m| serde_json::json!({ "role": m.role.to_string(), "content": m.content }))
            .collect();

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "stream": false,
            "options": { "num_predict": self.max_tokens },
        });

        // Ollama supports tools in newer versions via the same OpenAI-compatible format.
        if !tools.is_empty() {
            let tool_defs: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect();
            body["tools"] = serde_json::json!(tool_defs);
        }

        body
    }

    fn parse_response(body: &str) -> Result<BackendResponse, LlmError> {
        let json: serde_json::Value =
            serde_json::from_str(body).map_err(|e| LlmError::ParseError(e.to_string()))?;

        // Ollama's non-streaming /api/chat response format.
        let content = json["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let done_reason = json["done_reason"].as_str().unwrap_or("stop");

        let stop_reason = match done_reason {
            "length" => StopReason::MaxTokens,
            _ => StopReason::EndTurn,
        };

        // Ollama tool calls (if present) use OpenAI format inside message.tool_calls.
        let mut tool_uses = Vec::new();
        if let Some(calls) = json["message"]["tool_calls"].as_array() {
            for call in calls {
                let id = call["id"].as_str().unwrap_or("tc_0").to_string();
                let name = call["function"]["name"].as_str().unwrap_or("").to_string();
                let raw_args = call["function"]["arguments"].as_str().unwrap_or("{}");
                let input =
                    serde_json::from_str(raw_args).unwrap_or_else(|_| serde_json::json!({}));
                tool_uses.push(ToolUseBlock { id, name, input });
            }
        }

        let final_stop = if tool_uses.is_empty() {
            stop_reason
        } else {
            StopReason::ToolUse
        };

        Ok(BackendResponse {
            content,
            tool_uses,
            stop_reason: final_stop,
        })
    }
}

#[async_trait]
impl LlmBackendV2 for OllamaBackendV2 {
    async fn chat(
        &self,
        msgs: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<BackendResponse, LlmError> {
        let body = self.build_request_body(msgs, tools);
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        let status = resp.status().as_u16();
        let resp_body = resp
            .text()
            .await
            .map_err(|e| LlmError::IoError(e.to_string()))?;

        if status != 200 {
            return Err(LlmError::HttpError {
                status,
                body: resp_body,
            });
        }

        Self::parse_response(&resp_body)
    }

    fn model_id(&self) -> &str {
        &self.model
    }
    fn max_tokens(&self) -> u32 {
        self.max_tokens
    }
}

// ─── LlmRouter ───────────────────────────────────────────────────────────────

/// Routes chat requests to different backends based on task type (§31.2).
///
/// Backends are registered with a symbolic task-type label such as
/// `"analysis"`, `"synthesis"`, `"local"`, or `"default"`.  The router
/// selects the first backend whose label matches the requested task type;
/// if none matches, the backend labelled `"default"` is used; if there is
/// no `"default"`, the first registered backend is used.
pub struct LlmRouter {
    backends: Vec<(String, Box<dyn LlmBackendV2>)>,
}

impl LlmRouter {
    /// Create an empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
        }
    }

    /// Register a backend under a task-type label.
    pub fn add(&mut self, task_type: impl Into<String>, backend: Box<dyn LlmBackendV2>) {
        self.backends.push((task_type.into(), backend));
    }

    /// Select the backend for a given task type.
    ///
    /// Resolution order:
    /// 1. Exact label match.
    /// 2. Label `"default"`.
    /// 3. First registered backend.
    ///
    /// # Panics
    /// Panics if no backends have been registered.
    #[must_use]
    pub fn select_backend(&self, task_type: &str) -> &dyn LlmBackendV2 {
        // 1. Exact match
        if let Some((_, b)) = self.backends.iter().find(|(label, _)| label == task_type) {
            return b.as_ref();
        }
        // 2. Default
        if let Some((_, b)) = self.backends.iter().find(|(label, _)| label == "default") {
            return b.as_ref();
        }
        // 3. First registered
        self.backends
            .first()
            .map(|(_, b)| b.as_ref())
            .expect("LlmRouter: no backends registered")
    }

    /// Send a chat request via the backend selected for `task_type`.
    ///
    /// # Errors
    ///
    /// Returns an [`LlmError`] if the selected backend fails to complete the request.
    pub async fn chat(
        &self,
        task_type: &str,
        msgs: &[ChatMessage],
        tools: &[ToolDef],
    ) -> Result<BackendResponse, LlmError> {
        self.select_backend(task_type).chat(msgs, tools).await
    }

    /// Number of registered backends.
    #[must_use]
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// True when no backends have been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// List all registered task-type labels.
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        self.backends.iter().map(|(l, _)| l.as_str()).collect()
    }
}

impl Default for LlmRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── MockBackendV2 ────────────────────────────────────────────────────────────

/// In-process mock backend for tests — no network calls.
pub struct MockBackendV2 {
    pub model: String,
    pub max_tokens: u32,
    responses: parking_lot::Mutex<Vec<BackendResponse>>,
}

impl MockBackendV2 {
    /// Create with a fixed model id.
    #[must_use]
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            max_tokens: 4096,
            responses: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Queue a plain-text response.
    pub fn queue_text(&self, text: impl Into<String>) {
        self.responses.lock().push(BackendResponse::text(text));
    }

    /// Queue a full response.
    pub fn queue(&self, response: BackendResponse) {
        self.responses.lock().push(response);
    }

    fn dequeue(&self) -> BackendResponse {
        let mut lock = self.responses.lock();
        if lock.is_empty() {
            return BackendResponse::text("mock response");
        }
        if lock.len() == 1 {
            lock[0].clone()
        } else {
            lock.remove(0)
        }
    }
}

#[async_trait]
impl LlmBackendV2 for MockBackendV2 {
    async fn chat(
        &self,
        _msgs: &[ChatMessage],
        _tools: &[ToolDef],
    ) -> Result<BackendResponse, LlmError> {
        Ok(self.dequeue())
    }

    fn model_id(&self) -> &str {
        &self.model
    }
    fn max_tokens(&self) -> u32 {
        self.max_tokens
    }
}

// ─── §31.2 tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod v2_tests {
    use super::*;

    // ── Role ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_role_display() {
        assert_eq!(Role::System.to_string(), "system");
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::Assistant.to_string(), "assistant");
    }

    #[test]
    fn test_role_serde_roundtrip() {
        let r = Role::User;
        let s = serde_json::to_string(&r).unwrap();
        let back: Role = serde_json::from_str(&s).unwrap();
        assert_eq!(back, Role::User);
    }

    // ── ChatMessage ───────────────────────────────────────────────────────────

    #[test]
    fn test_chat_message_constructors() {
        let s = ChatMessage::system("be helpful");
        assert_eq!(s.role, Role::System);
        let u = ChatMessage::user("hello");
        assert_eq!(u.role, Role::User);
        let a = ChatMessage::assistant("hi");
        assert_eq!(a.role, Role::Assistant);
    }

    #[test]
    fn test_chat_message_to_plain() {
        let cm = ChatMessage::user("test");
        let plain = cm.to_plain();
        assert_eq!(plain.role, "user");
        assert_eq!(plain.content, "test");
    }

    // ── ToolDef ───────────────────────────────────────────────────────────────

    #[test]
    fn test_tool_def_new() {
        let t = ToolDef::new(
            "disassemble",
            "Disassemble a function",
            serde_json::json!({ "type": "object", "properties": { "addr": { "type": "string" } } }),
        );
        assert_eq!(t.name, "disassemble");
        assert!(t.input_schema["properties"]["addr"]["type"].as_str() == Some("string"));
    }

    #[test]
    fn test_tool_def_simple() {
        let t = ToolDef::simple("ping", "no-op ping tool");
        assert_eq!(t.name, "ping");
        assert_eq!(t.input_schema["type"], "object");
    }

    #[test]
    fn test_tool_def_serde() {
        let t = ToolDef::simple("x", "desc");
        let s = serde_json::to_string(&t).unwrap();
        let back: ToolDef = serde_json::from_str(&s).unwrap();
        assert_eq!(back.name, "x");
    }

    // ── ToolUseBlock ──────────────────────────────────────────────────────────

    #[test]
    fn test_tool_use_block_serde() {
        let tu = ToolUseBlock {
            id: "id_1".to_string(),
            name: "rename_sym".to_string(),
            input: serde_json::json!({ "addr": "0x1000", "new_name": "main" }),
        };
        let s = serde_json::to_string(&tu).unwrap();
        let back: ToolUseBlock = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, "id_1");
        assert_eq!(back.name, "rename_sym");
    }

    // ── StopReason ────────────────────────────────────────────────────────────

    #[test]
    fn test_stop_reason_display() {
        assert_eq!(StopReason::EndTurn.to_string(), "end_turn");
        assert_eq!(StopReason::ToolUse.to_string(), "tool_use");
        assert_eq!(StopReason::MaxTokens.to_string(), "max_tokens");
        assert_eq!(StopReason::Stop.to_string(), "stop");
    }

    #[test]
    fn test_stop_reason_from_str() {
        assert_eq!(StopReason::parse("end_turn"), StopReason::EndTurn);
        assert_eq!(StopReason::parse("stop"), StopReason::EndTurn);
        assert_eq!(StopReason::parse("tool_use"), StopReason::ToolUse);
        assert_eq!(StopReason::parse("tool_calls"), StopReason::ToolUse);
        assert_eq!(StopReason::parse("max_tokens"), StopReason::MaxTokens);
        assert_eq!(StopReason::parse("length"), StopReason::MaxTokens);
        assert_eq!(StopReason::parse("unknown"), StopReason::Stop);
    }

    #[test]
    fn test_stop_reason_serde() {
        let sr = StopReason::ToolUse;
        let s = serde_json::to_string(&sr).unwrap();
        assert_eq!(s, "\"tool_use\"");
        let back: StopReason = serde_json::from_str(&s).unwrap();
        assert_eq!(back, StopReason::ToolUse);
    }

    // ── BackendResponse ───────────────────────────────────────────────────────

    #[test]
    fn test_backend_response_text() {
        let r = BackendResponse::text("hello world");
        assert_eq!(r.content, "hello world");
        assert!(!r.has_tool_uses());
        assert_eq!(r.stop_reason, StopReason::EndTurn);
    }

    #[test]
    fn test_backend_response_has_tool_uses() {
        let r = BackendResponse {
            content: String::new(),
            tool_uses: vec![ToolUseBlock {
                id: "x".to_string(),
                name: "fn".to_string(),
                input: serde_json::json!({}),
            }],
            stop_reason: StopReason::ToolUse,
        };
        assert!(r.has_tool_uses());
    }

    // ── AnthropicBackendV2 parse ───────────────────────────────────────────────

    #[test]
    fn test_anthropic_parse_text_response() {
        let body = serde_json::json!({
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "stop_reason": "end_turn",
            "content": [{ "type": "text", "text": "Hello from Claude" }],
            "usage": { "input_tokens": 10, "output_tokens": 5 }
        })
        .to_string();

        let resp = AnthropicBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.content, "Hello from Claude");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert!(resp.tool_uses.is_empty());
    }

    #[test]
    fn test_anthropic_parse_tool_use_response() {
        let body = serde_json::json!({
            "id": "msg_02",
            "type": "message",
            "role": "assistant",
            "stop_reason": "tool_use",
            "content": [
                { "type": "tool_use", "id": "tu_1", "name": "disassemble", "input": { "addr": "0x1000" } }
            ],
            "usage": { "input_tokens": 20, "output_tokens": 10 }
        }).to_string();

        let resp = AnthropicBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(resp.tool_uses.len(), 1);
        assert_eq!(resp.tool_uses[0].name, "disassemble");
        assert_eq!(resp.tool_uses[0].input["addr"], "0x1000");
    }

    #[test]
    fn test_anthropic_parse_mixed_content() {
        let body = serde_json::json!({
            "stop_reason": "tool_use",
            "content": [
                { "type": "text", "text": "Let me call a tool." },
                { "type": "tool_use", "id": "tu_2", "name": "get_bytes", "input": { "size": 16 } }
            ]
        })
        .to_string();

        let resp = AnthropicBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.content, "Let me call a tool.");
        assert_eq!(resp.tool_uses[0].name, "get_bytes");
    }

    // ── OpenAiBackendV2 parse ────────────────────────────────────────────────

    #[test]
    fn test_openai_parse_text_response() {
        let body = serde_json::json!({
            "id": "chatcmpl-abc",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "Hello from GPT" },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        })
        .to_string();

        let resp = OpenAiBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.content, "Hello from GPT");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert!(resp.tool_uses.is_empty());
    }

    #[test]
    fn test_openai_parse_tool_call_response() {
        let args = serde_json::to_string(&serde_json::json!({ "addr": "0x2000" })).unwrap();
        let body = serde_json::json!({
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "disassemble", "arguments": args }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        })
        .to_string();

        let resp = OpenAiBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(resp.tool_uses.len(), 1);
        assert_eq!(resp.tool_uses[0].name, "disassemble");
    }

    #[test]
    fn test_openai_parse_max_tokens() {
        let body = serde_json::json!({
            "choices": [{
                "message": { "role": "assistant", "content": "truncated..." },
                "finish_reason": "length"
            }]
        })
        .to_string();

        let resp = OpenAiBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::MaxTokens);
    }

    // ── OllamaBackendV2 parse ─────────────────────────────────────────────────

    #[test]
    fn test_ollama_parse_text_response() {
        let body = serde_json::json!({
            "model": "llama3",
            "message": { "role": "assistant", "content": "Hello from Ollama" },
            "done": true,
            "done_reason": "stop",
            "prompt_eval_count": 15,
            "eval_count": 8
        })
        .to_string();

        let resp = OllamaBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.content, "Hello from Ollama");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
    }

    #[test]
    fn test_ollama_parse_tool_calls() {
        let args = serde_json::to_string(&serde_json::json!({ "x": 1 })).unwrap();
        let body = serde_json::json!({
            "model": "llama3.2",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{ "id": "tc_1", "function": { "name": "my_tool", "arguments": args } }]
            },
            "done": true,
            "done_reason": "stop"
        }).to_string();

        let resp = OllamaBackendV2::parse_response(&body).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(resp.tool_uses[0].name, "my_tool");
    }

    // ── MockBackendV2 ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_mock_backend_default_response() {
        let b = MockBackendV2::new("mock-model");
        let msgs = vec![ChatMessage::user("hi")];
        let resp = b.chat(&msgs, &[]).await.unwrap();
        assert_eq!(resp.content, "mock response");
    }

    #[tokio::test]
    async fn test_mock_backend_queued_text() {
        let b = MockBackendV2::new("m");
        b.queue_text("first");
        b.queue_text("second");
        let msgs = vec![ChatMessage::user("x")];
        let r1 = b.chat(&msgs, &[]).await.unwrap();
        assert_eq!(r1.content, "first");
        let r2 = b.chat(&msgs, &[]).await.unwrap();
        assert_eq!(r2.content, "second");
    }

    #[tokio::test]
    async fn test_mock_backend_repeats_last() {
        let b = MockBackendV2::new("m");
        b.queue_text("only");
        let msgs = vec![ChatMessage::user("x")];
        let r1 = b.chat(&msgs, &[]).await.unwrap();
        let r2 = b.chat(&msgs, &[]).await.unwrap();
        assert_eq!(r1.content, "only");
        assert_eq!(r2.content, "only");
    }

    #[tokio::test]
    async fn test_mock_backend_tool_use_response() {
        let b = MockBackendV2::new("m");
        b.queue(BackendResponse {
            content: String::new(),
            tool_uses: vec![ToolUseBlock {
                id: "x".to_string(),
                name: "fn".to_string(),
                input: serde_json::json!({}),
            }],
            stop_reason: StopReason::ToolUse,
        });
        let msgs = vec![ChatMessage::user("call a tool")];
        let resp = b.chat(&msgs, &[]).await.unwrap();
        assert!(resp.has_tool_uses());
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
    }

    #[test]
    fn test_mock_backend_model_id() {
        let b = MockBackendV2::new("fake-model");
        assert_eq!(b.model_id(), "fake-model");
        assert_eq!(b.max_tokens(), 4096);
    }

    // ── LlmRouter ─────────────────────────────────────────────────────────────

    #[test]
    fn test_router_empty() {
        let r = LlmRouter::new();
        assert!(r.is_empty());
        assert_eq!(r.backend_count(), 0);
    }

    #[test]
    fn test_router_add_and_labels() {
        let mut r = LlmRouter::new();
        r.add("analysis", Box::new(MockBackendV2::new("a")));
        r.add("default", Box::new(MockBackendV2::new("b")));
        assert_eq!(r.backend_count(), 2);
        let labels = r.labels();
        assert!(labels.contains(&"analysis"));
        assert!(labels.contains(&"default"));
    }

    #[test]
    fn test_router_exact_match() {
        let mut r = LlmRouter::new();
        r.add("analysis", Box::new(MockBackendV2::new("analysis-model")));
        r.add("default", Box::new(MockBackendV2::new("default-model")));
        let b = r.select_backend("analysis");
        assert_eq!(b.model_id(), "analysis-model");
    }

    #[test]
    fn test_router_default_fallback() {
        let mut r = LlmRouter::new();
        r.add("analysis", Box::new(MockBackendV2::new("analysis-model")));
        r.add("default", Box::new(MockBackendV2::new("default-model")));
        let b = r.select_backend("synthesis");
        assert_eq!(b.model_id(), "default-model");
    }

    #[test]
    fn test_router_first_fallback() {
        let mut r = LlmRouter::new();
        r.add("local", Box::new(MockBackendV2::new("local-model")));
        let b = r.select_backend("anything");
        assert_eq!(b.model_id(), "local-model");
    }

    #[tokio::test]
    async fn test_router_chat_routes_correctly() {
        let mut r = LlmRouter::new();
        let b = MockBackendV2::new("analysis-model");
        b.queue_text("analysis result");
        r.add("analysis", Box::new(b));

        let msgs = vec![ChatMessage::user("analyze this binary")];
        let resp = r.chat("analysis", &msgs, &[]).await.unwrap();
        assert_eq!(resp.content, "analysis result");
    }

    #[tokio::test]
    async fn test_router_chat_with_tools() {
        let mut r = LlmRouter::new();
        let b = MockBackendV2::new("m");
        b.queue(BackendResponse {
            content: String::new(),
            tool_uses: vec![ToolUseBlock {
                id: "t1".to_string(),
                name: "get_bytes".to_string(),
                input: serde_json::json!({ "addr": "0x1000", "size": 16 }),
            }],
            stop_reason: StopReason::ToolUse,
        });
        r.add("default", Box::new(b));

        let tools = vec![ToolDef::new(
            "get_bytes",
            "Read bytes from an address",
            serde_json::json!({ "type": "object", "properties": { "addr": { "type": "string" }, "size": { "type": "integer" } } }),
        )];
        let msgs = vec![ChatMessage::user("read 16 bytes at 0x1000")];
        let resp = r.chat("default", &msgs, &tools).await.unwrap();
        assert!(resp.has_tool_uses());
        assert_eq!(resp.tool_uses[0].name, "get_bytes");
    }

    // ── AnthropicBackendV2 construction ───────────────────────────────────────

    #[test]
    fn test_anthropic_backend_v2_construction() {
        let b = AnthropicBackendV2::new("sk-ant-key", "claude-opus-4-5", 8192);
        assert_eq!(b.model_id(), "claude-opus-4-5");
        assert_eq!(b.max_tokens(), 8192);
        assert_eq!(b.api_key, "sk-ant-key");
    }

    #[test]
    fn test_anthropic_build_request_body_no_tools() {
        let b = AnthropicBackendV2::new("k", "claude-3-5-haiku-20241022", 1024);
        let msgs = vec![
            ChatMessage::system("be helpful"),
            ChatMessage::user("hello"),
        ];
        let body = b.build_request_body(&msgs, &[]);
        assert_eq!(body["model"], "claude-3-5-haiku-20241022");
        assert_eq!(body["system"], "be helpful");
        assert!(body["messages"].as_array().unwrap().len() == 1);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn test_anthropic_build_request_body_with_tools() {
        let b = AnthropicBackendV2::new("k", "claude-opus-4-5", 4096);
        let msgs = vec![ChatMessage::user("analyze")];
        let tools = vec![ToolDef::simple("my_tool", "a tool")];
        let body = b.build_request_body(&msgs, &tools);
        let tool_arr = body["tools"].as_array().unwrap();
        assert_eq!(tool_arr.len(), 1);
        assert_eq!(tool_arr[0]["name"], "my_tool");
    }

    // ── OpenAiBackendV2 construction ──────────────────────────────────────────

    #[test]
    fn test_openai_backend_v2_construction() {
        let b = OpenAiBackendV2::new_openai("sk-key", "gpt-4o");
        assert_eq!(b.model_id(), "gpt-4o");
        assert_eq!(b.base_url, "https://api.openai.com");
    }

    #[test]
    fn test_openai_build_request_body_with_tools() {
        let b = OpenAiBackendV2::new("k", "https://api.openai.com", "gpt-4o", 4096);
        let msgs = vec![ChatMessage::user("hello")];
        let tools = vec![ToolDef::simple("ping", "ping tool")];
        let body = b.build_request_body(&msgs, &tools);
        let tool_arr = body["tools"].as_array().unwrap();
        assert_eq!(tool_arr[0]["type"], "function");
        assert_eq!(tool_arr[0]["function"]["name"], "ping");
    }

    // ── OllamaBackendV2 construction ──────────────────────────────────────────

    #[test]
    fn test_ollama_backend_v2_construction() {
        let b = OllamaBackendV2::localhost("llama3");
        assert_eq!(b.model_id(), "llama3");
        assert_eq!(b.base_url, "http://localhost:11434");
    }

    #[test]
    fn test_ollama_build_request_body() {
        let b = OllamaBackendV2::new("http://localhost:11434", "mistral", 2048);
        let msgs = vec![ChatMessage::user("hi")];
        let body = b.build_request_body(&msgs, &[]);
        assert_eq!(body["model"], "mistral");
        assert_eq!(body["stream"], false);
    }
}

// ─── Additional utility fns (§wire) ──────────────────────────────────────────

/// Estimate whether a message list fits within a given token budget.
#[must_use]
pub fn messages_fit_budget(messages: &[Message], budget: u32) -> bool {
    TokenCounter::count_messages(messages) <= budget
}

/// Count text tokens using the shared BPE approximation.
#[must_use]
pub fn approx_token_count(text: &str) -> u32 {
    TokenCounter::count_text(text)
}

/// Wrap a prompt so the LLM responds with pure JSON.
#[must_use]
pub fn wrap_json_prompt(prompt: &str) -> String {
    LlmJsonMode::wrap_prompt(prompt)
}
