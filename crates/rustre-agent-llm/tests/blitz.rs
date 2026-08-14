//! Blitz integration tests for rustre-agent-llm public API.

use rustre_agent_llm::{
    AnthropicBackend, AnthropicClient, CompletionOptions, ContextManager, LlmBackend, LlmChoice,
    LlmClient, LlmConfig, LlmError, LlmMessage, LlmModel, LlmProvider, LlmProviderError,
    LlmResponse, LlmRole, LlmUsage, LocalOllamaClient, Message, MockLlmProvider, OpenAiBackend,
    OpenAiClient, TokenCounter, TokenUsage, ToolDefinition, ToolUse,
};

// ─── Message ─────────────────────────────────────────────────────────────────

#[test]
fn message_system_role() {
    let m = Message::system("s");
    assert_eq!(m.role, "system");
    assert_eq!(m.content, "s");
}

#[test]
fn message_user_role() {
    let m = Message::user("u");
    assert_eq!(m.role, "user");
}

#[test]
fn message_assistant_role() {
    let m = Message::assistant("a");
    assert_eq!(m.role, "assistant");
}

#[test]
fn message_empty_content() {
    let m = Message::user("");
    assert_eq!(m.content, "");
}

#[test]
fn message_clone_and_debug() {
    let m = Message::user("hello");
    let c = m.clone();
    assert_eq!(c.role, m.role);
    assert!(!format!("{m:?}").is_empty());
}

#[test]
fn message_serde_roundtrip() {
    let m = Message::assistant("hi");
    let s = serde_json::to_string(&m).unwrap();
    let back: Message = serde_json::from_str(&s).unwrap();
    assert_eq!(back.role, "assistant");
    assert_eq!(back.content, "hi");
}

// ─── CompletionOptions ───────────────────────────────────────────────────────

#[test]
fn completion_options_default_values() {
    let o = CompletionOptions::default();
    assert_eq!(o.max_tokens, 4096);
    assert!((o.temperature - 0.2).abs() < f32::EPSILON);
    assert!((o.top_p - 1.0).abs() < f32::EPSILON);
    assert!(o.stop_sequences.is_empty());
}

#[test]
fn completion_options_custom() {
    let o = CompletionOptions {
        max_tokens: 100,
        temperature: 0.7,
        stop_sequences: vec!["END".into()],
        top_p: 0.9,
    };
    let s = serde_json::to_string(&o).unwrap();
    let back: CompletionOptions = serde_json::from_str(&s).unwrap();
    assert_eq!(back.max_tokens, 100);
    assert_eq!(back.stop_sequences, vec!["END".to_string()]);
}

// ─── TokenUsage ──────────────────────────────────────────────────────────────

#[test]
fn token_usage_sum() {
    let u = TokenUsage {
        prompt: 7,
        completion: 3,
        total: 10,
    };
    assert_eq!(u.prompt + u.completion, u.total);
}

#[test]
fn token_usage_zero() {
    let u = TokenUsage {
        prompt: 0,
        completion: 0,
        total: 0,
    };
    assert_eq!(u.total, 0);
}

// ─── ToolDefinition / ToolUse ────────────────────────────────────────────────

#[test]
fn tool_definition_new() {
    let td = ToolDefinition::new("name", "desc", serde_json::json!({}));
    assert_eq!(td.name, "name");
    assert_eq!(td.description, "desc");
}

#[test]
fn tool_definition_serde_roundtrip() {
    let td = ToolDefinition::new("n", "d", serde_json::json!({"x":1}));
    let s = serde_json::to_string(&td).unwrap();
    let back: ToolDefinition = serde_json::from_str(&s).unwrap();
    assert_eq!(back.name, "n");
    assert_eq!(back.parameters["x"], 1);
}

#[test]
fn tool_use_roundtrip() {
    let t = ToolUse {
        id: "1".into(),
        name: "foo".into(),
        arguments: serde_json::json!({"a": 1}),
    };
    let s = serde_json::to_string(&t).unwrap();
    let back: ToolUse = serde_json::from_str(&s).unwrap();
    assert_eq!(back.id, "1");
    assert_eq!(back.arguments["a"], 1);
}

// ─── LlmError ────────────────────────────────────────────────────────────────

#[test]
fn llm_error_http_display() {
    let e = LlmError::HttpError {
        status: 500,
        body: "boom".into(),
    };
    let s = e.to_string();
    assert!(s.contains("500"));
    assert!(s.contains("boom"));
}

#[test]
fn llm_error_parse_display() {
    let e = LlmError::ParseError("bad".into());
    assert!(e.to_string().contains("bad"));
}

#[test]
fn llm_error_auth_display() {
    let e = LlmError::AuthError("nope".into());
    assert!(e.to_string().contains("nope"));
}

#[test]
fn llm_error_rate_limited_display() {
    let e = LlmError::RateLimited { retry_after_ms: 250 };
    assert!(e.to_string().contains("250"));
}

#[test]
fn llm_error_context_too_long_display() {
    let e = LlmError::ContextTooLong {
        tokens: 200,
        limit: 100,
    };
    let s = e.to_string();
    assert!(s.contains("200") && s.contains("100"));
}

#[test]
fn llm_error_timeout_display() {
    let e = LlmError::Timeout { ms: 9 };
    assert!(e.to_string().contains('9'));
}

#[test]
fn llm_error_from_io() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
    let e: LlmError = io.into();
    assert!(matches!(e, LlmError::IoError(_)));
}

#[test]
fn llm_error_from_serde() {
    let err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
    let e: LlmError = err.into();
    assert!(matches!(e, LlmError::SerializationError(_)));
}

// ─── TokenCounter ────────────────────────────────────────────────────────────

#[test]
fn token_counter_empty() {
    assert_eq!(TokenCounter::count_text(""), 0);
}

#[test]
fn token_counter_short() {
    assert_eq!(TokenCounter::count_text("hello"), 2);
}

#[test]
fn token_counter_single_char() {
    assert_eq!(TokenCounter::count_text("x"), 1);
}

#[test]
fn token_counter_messages_empty() {
    assert_eq!(TokenCounter::count_messages(&[]), 0);
}

#[test]
fn token_counter_messages_overhead() {
    let m = vec![Message::user("")];
    // empty content = 0 tokens + 4 overhead
    assert_eq!(TokenCounter::count_messages(&m), 4);
}

#[test]
fn token_counter_fits_within() {
    let m = vec![Message::user("hi")];
    assert!(TokenCounter::fits_in_context(&m, 1000));
}

#[test]
fn token_counter_does_not_fit() {
    let m = vec![Message::user("x".repeat(1000))];
    assert!(!TokenCounter::fits_in_context(&m, 5));
}

#[test]
fn token_counter_boundary_equal() {
    let m = vec![Message::user("")]; // exactly 4 tokens
    assert!(TokenCounter::fits_in_context(&m, 4));
    assert!(!TokenCounter::fits_in_context(&m, 3));
}

// ─── ContextManager ──────────────────────────────────────────────────────────

#[test]
fn context_manager_new_empty() {
    let cm = ContextManager::new(1024);
    assert!(cm.is_empty());
    assert_eq!(cm.len(), 0);
    assert!(cm.build().is_empty());
}

#[test]
fn context_manager_set_system() {
    let mut cm = ContextManager::new(1024);
    cm.set_system("you are helpful");
    let b = cm.build();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].role, "system");
}

#[test]
fn context_manager_push_increases_len() {
    let mut cm = ContextManager::new(1024);
    cm.push(Message::user("a"));
    cm.push(Message::user("b"));
    assert_eq!(cm.len(), 2);
    assert!(!cm.is_empty());
}

#[test]
fn context_manager_build_chronological() {
    let mut cm = ContextManager::new(2048);
    cm.set_system("sys");
    cm.push(Message::user("first"));
    cm.push(Message::assistant("second"));
    cm.push(Message::user("third"));
    let b = cm.build();
    assert_eq!(b[0].role, "system");
    assert_eq!(b[1].content, "first");
    assert_eq!(b[2].content, "second");
    assert_eq!(b[3].content, "third");
}

#[test]
fn context_manager_truncates_oldest() {
    let mut cm = ContextManager::new(30);
    cm.set_system("s");
    for i in 0..50 {
        cm.push(Message::user(format!("msg {i} with padding text here")));
    }
    let b = cm.build();
    assert!(TokenCounter::count_messages(&b) <= 30 + 10);
    // newest preserved: last pushed should appear
    let has_last = b.iter().any(|m| m.content.contains("msg 49"));
    assert!(has_last);
}

#[test]
fn context_manager_zero_budget() {
    let cm = ContextManager::new(0);
    assert!(cm.build().is_empty());
}

// ─── OpenAiClient ────────────────────────────────────────────────────────────

#[test]
fn openai_client_new_openai() {
    let c = OpenAiClient::new_openai("sk-x", "gpt-4o");
    assert_eq!(c.model_name(), "gpt-4o");
    assert_eq!(c.max_context_tokens(), 128_000);
}

#[test]
fn openai_client_new_custom() {
    let c = OpenAiClient::new_custom("h", 8080, "k", "m", 2048);
    assert_eq!(c.model_name(), "m");
    assert_eq!(c.max_context_tokens(), 2048);
}

#[test]
fn openai_client_is_llm_client() {
    let c = OpenAiClient::new_openai("k", "m");
    let _: &dyn LlmClient = &c;
}

// ─── AnthropicClient ─────────────────────────────────────────────────────────

#[test]
fn anthropic_client_model() {
    let c = AnthropicClient::new("k", "claude-opus-4-5");
    assert_eq!(c.model_name(), "claude-opus-4-5");
    assert_eq!(c.max_context_tokens(), 200_000);
}

#[test]
fn anthropic_client_build_headers() {
    let c = AnthropicClient::new("the-key", "m");
    let h = c.build_headers();
    assert_eq!(h.get("x-api-key").map(String::as_str), Some("the-key"));
    assert_eq!(
        h.get("anthropic-version").map(String::as_str),
        Some("2023-06-01")
    );
}

// ─── LocalOllamaClient ───────────────────────────────────────────────────────

#[test]
fn ollama_default_host() {
    let c = LocalOllamaClient::new("llama3");
    assert_eq!(c.model_name(), "llama3");
    assert_eq!(c.max_context_tokens(), 32_768);
}

#[test]
fn ollama_custom_host() {
    let c = LocalOllamaClient::new_at("1.2.3.4", 9999, "m");
    assert_eq!(c.model_name(), "m");
}

// ─── LlmRole / LlmMessage ────────────────────────────────────────────────────

#[test]
fn llm_role_display_all() {
    assert_eq!(LlmRole::System.to_string(), "System");
    assert_eq!(LlmRole::User.to_string(), "User");
    assert_eq!(LlmRole::Assistant.to_string(), "Assistant");
}

#[test]
fn llm_role_equality() {
    assert_eq!(LlmRole::User, LlmRole::User);
    assert_ne!(LlmRole::User, LlmRole::System);
}

#[test]
fn llm_message_constructors() {
    assert_eq!(LlmMessage::user("a").role, LlmRole::User);
    assert_eq!(LlmMessage::system("a").role, LlmRole::System);
    assert_eq!(LlmMessage::assistant("a").role, LlmRole::Assistant);
}

#[test]
fn llm_message_from_message() {
    let m = Message::system("s");
    let lm: LlmMessage = m.into();
    assert_eq!(lm.role, LlmRole::System);
}

#[test]
fn llm_message_from_message_user_default() {
    let m = Message {
        role: "weird".into(),
        content: "c".into(),
    };
    let lm: LlmMessage = m.into();
    assert_eq!(lm.role, LlmRole::User);
}

#[test]
fn llm_message_from_message_ref() {
    let m = Message::assistant("x");
    let lm: LlmMessage = (&m).into();
    assert_eq!(lm.role, LlmRole::Assistant);
}

// ─── LlmModel ────────────────────────────────────────────────────────────────

#[test]
fn llm_model_display_builtin() {
    assert_eq!(LlmModel::Gpt4.to_string(), "Gpt4");
    assert_eq!(LlmModel::Gpt35Turbo.to_string(), "Gpt35Turbo");
    assert_eq!(LlmModel::Claude3Opus.to_string(), "Claude3Opus");
    assert_eq!(LlmModel::Claude3Sonnet.to_string(), "Claude3Sonnet");
    assert_eq!(LlmModel::Claude3Haiku.to_string(), "Claude3Haiku");
    assert_eq!(LlmModel::Llama3.to_string(), "Llama3");
}

#[test]
fn llm_model_display_custom() {
    assert_eq!(LlmModel::Custom("x".into()).to_string(), "custom:x");
}

#[test]
fn llm_model_eq() {
    assert_eq!(LlmModel::Gpt4, LlmModel::Gpt4);
    assert_ne!(LlmModel::Gpt4, LlmModel::Llama3);
    assert_eq!(
        LlmModel::Custom("a".into()),
        LlmModel::Custom("a".into())
    );
}

// ─── LlmConfig ───────────────────────────────────────────────────────────────

#[test]
fn llm_config_defaults() {
    let c = LlmConfig::new(LlmModel::Gpt4, "k");
    assert_eq!(c.max_tokens, 4096);
    assert!((c.temperature - 0.2).abs() < f32::EPSILON);
    assert_eq!(c.base_url, "https://api.openai.com");
}

#[test]
fn llm_config_builder_chain() {
    let c = LlmConfig::new(LlmModel::Llama3, "k")
        .with_base_url("http://x")
        .with_max_tokens(7)
        .with_temperature(1.5);
    assert_eq!(c.base_url, "http://x");
    assert_eq!(c.max_tokens, 7);
    assert!((c.temperature - 1.5).abs() < f32::EPSILON);
}

// ─── LlmResponse ─────────────────────────────────────────────────────────────

#[test]
fn llm_response_first_text_some() {
    let r = LlmResponse {
        choices: vec![LlmChoice {
            text: "abc".into(),
            finish_reason: "stop".into(),
            index: 0,
        }],
        usage: LlmUsage {
            prompt_tokens: 1,
            completion_tokens: 1,
            total_tokens: 2,
        },
        model: "m".into(),
    };
    assert_eq!(r.first_text(), Some("abc"));
}

#[test]
fn llm_response_first_text_none() {
    let r = LlmResponse {
        choices: vec![],
        usage: LlmUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        },
        model: "m".into(),
    };
    assert_eq!(r.first_text(), None);
}

// ─── LlmProviderError ────────────────────────────────────────────────────────

#[test]
fn llm_provider_error_variants() {
    let e1 = LlmProviderError::ApiError {
        code: 1,
        message: "m".into(),
    };
    assert!(e1.to_string().contains('1'));
    assert!(LlmProviderError::Timeout.to_string().contains("timed"));
    assert!(LlmProviderError::RateLimit.to_string().contains("rate"));
    assert!(
        LlmProviderError::InvalidConfig("bad".into())
            .to_string()
            .contains("bad")
    );
    assert!(
        LlmProviderError::Parse("p".into())
            .to_string()
            .contains('p')
    );
}

// ─── MockLlmProvider ─────────────────────────────────────────────────────────

#[test]
fn mock_provider_name() {
    assert_eq!(MockLlmProvider::new().name(), "mock");
}

#[test]
fn mock_provider_default() {
    let p = MockLlmProvider::default();
    assert_eq!(p.name(), "mock");
}

#[tokio::test]
async fn mock_provider_default_response() {
    let p = MockLlmProvider::new();
    let cfg = LlmConfig::new(LlmModel::Gpt4, "");
    let r = p.complete(vec![], &cfg).await.unwrap();
    assert_eq!(r.first_text(), Some("mock response"));
    assert_eq!(r.usage.total_tokens, 15);
}

#[tokio::test]
async fn mock_provider_queue_dequeue() {
    let p = MockLlmProvider::new();
    p.queue("one");
    p.queue("two");
    let cfg = LlmConfig::new(LlmModel::Gpt4, "");
    assert_eq!(p.complete(vec![], &cfg).await.unwrap().first_text(), Some("one"));
    assert_eq!(p.complete(vec![], &cfg).await.unwrap().first_text(), Some("two"));
}

#[tokio::test]
async fn mock_provider_last_repeats() {
    let p = MockLlmProvider::new();
    p.queue("solo");
    let cfg = LlmConfig::new(LlmModel::Gpt4, "");
    let _ = p.complete(vec![], &cfg).await.unwrap();
    let r = p.complete(vec![], &cfg).await.unwrap();
    assert_eq!(r.first_text(), Some("solo"));
}

#[tokio::test]
async fn mock_provider_model_in_response() {
    let p = MockLlmProvider::new();
    let cfg = LlmConfig::new(LlmModel::Claude3Opus, "");
    let r = p.complete(vec![], &cfg).await.unwrap();
    assert_eq!(r.model, "Claude3Opus");
}

// ─── AnthropicBackend / OpenAiBackend ────────────────────────────────────────

#[test]
fn anthropic_backend_metadata() {
    let b = AnthropicBackend::new("k", "claude-x");
    assert_eq!(b.backend_name(), "anthropic");
    assert_eq!(b.model_id(), "claude-x");
    assert_eq!(b.context_length(), 200_000);
}

#[test]
fn anthropic_backend_constructors() {
    assert_eq!(AnthropicBackend::claude_opus("k").model_id(), "claude-opus-4-5");
    assert_eq!(AnthropicBackend::claude_sonnet("k").model_id(), "claude-sonnet-4-5");
    assert_eq!(AnthropicBackend::claude_haiku("k").model_id(), "claude-haiku-3-5");
}

#[tokio::test]
async fn anthropic_backend_count_tokens() {
    let b = AnthropicBackend::new("k", "m");
    let n = b.count_tokens("hello").await.unwrap();
    assert_eq!(n, TokenCounter::count_text("hello"));
}

#[tokio::test]
async fn anthropic_backend_embed_unsupported() {
    let b = AnthropicBackend::new("k", "m");
    let r = b.embed("text").await;
    assert!(matches!(r, Err(LlmError::ParseError(_))));
}

#[test]
fn openai_backend_metadata() {
    let b = OpenAiBackend::new("k", "gpt-4");
    assert_eq!(b.backend_name(), "openai");
    assert_eq!(b.model_id(), "gpt-4");
}

#[test]
fn openai_backend_constructors() {
    assert_eq!(OpenAiBackend::gpt4("k").model_id(), "gpt-4");
    assert_eq!(OpenAiBackend::gpt4_turbo("k").model_id(), "gpt-4-turbo-preview");
    assert_eq!(OpenAiBackend::gpt4o("k").model_id(), "gpt-4o");
}

// ─── Send/Sync bounds ────────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn trait_objects_are_send_sync() {
    assert_send_sync::<Box<dyn LlmClient>>();
    assert_send_sync::<Box<dyn LlmProvider>>();
    assert_send_sync::<Box<dyn LlmBackend>>();
}

#[test]
fn mock_provider_send_sync() {
    assert_send_sync::<MockLlmProvider>();
}
