//! Deep adversarial tests for rustre-agent-llm (X003).
//!
//! Targets only types that don't need network: `TokenCounter`, `ContextManager`,
//! `LlmContextWindow`, `LlmCache`, `LlmRetry`, `LlmRateLimiter`, `LlmCostTracker`,
//! `LlmStreamingResponse`, `LlmPromptTemplate`, `LlmJsonMode`, `LlmSystemPrompt`,
//! `EmbeddingResponse`, `ChatMessage` / Role, `StopReason`, `MockLlmProvider`,
//! `LlmConfig`, `LlmRole`, `LlmModel`, `ToolDef`, `BackendResponse`, LlmFunctionCall/Result.

use rustre_agent_llm::*;
use std::collections::HashMap;
use std::sync::Arc;

const fn lcg_seed() -> u64 {
    0xDEAD_BEEF_CAFE_BABE
}

const fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

// ── TokenCounter ──────────────────────────────────────────────────────────

#[test]
fn tc_empty_is_zero() {
    assert_eq!(TokenCounter::count_text(""), 0);
}

#[test]
fn tc_monotonic_in_length() {
    // longer strings produce >= token counts of shorter substrings.
    let mut s = String::new();
    let mut last = 0u32;
    for i in 0..200 {
        s.push((b'a' + (i % 26) as u8) as char);
        let n = TokenCounter::count_text(&s);
        assert!(n >= last, "non-monotonic at i={i}: {last} -> {n}");
        last = n;
    }
}

#[test]
fn tc_boundary_lengths() {
    // (chars + 3) / 4 — verify exact at boundaries.
    assert_eq!(TokenCounter::count_text(""), 0);
    assert_eq!(TokenCounter::count_text("x"), 1);     // (1+3)/4 = 1
    assert_eq!(TokenCounter::count_text("xxxx"), 1);  // (4+3)/4 = 1
    assert_eq!(TokenCounter::count_text("xxxxx"), 2); // (5+3)/4 = 2
}

#[test]
fn tc_lcg_fuzz_never_panics() {
    let mut s = lcg_seed();
    for _ in 0..200 {
        let len = (lcg(&mut s) as usize) % 4096;
        // Build a string of allowed ASCII
        let txt: String = (0..len)
            .map(|i| {
                let c = ((lcg(&mut s) >> 8) as u8) & 0x7f;
                if c < 0x20 { (b'a' + (i as u8 % 26)) as char } else { c as char }
            })
            .collect();
        let _n = TokenCounter::count_text(&txt);
        let msgs = vec![Message::user(txt)];
        let _ = TokenCounter::count_messages(&msgs);
        let _ = TokenCounter::fits_in_context(&msgs, 100);
    }
}

#[test]
fn tc_messages_includes_overhead() {
    let msgs = vec![Message::user(""), Message::system("")];
    // Two empty messages -> 4*2 = 8 overhead.
    assert_eq!(TokenCounter::count_messages(&msgs), 8);
}

#[test]
fn tc_fits_in_context_boundary() {
    let msgs = vec![Message::user("xxxx")]; // 1+4=5
    assert!(TokenCounter::fits_in_context(&msgs, 5));
    assert!(!TokenCounter::fits_in_context(&msgs, 4));
}

// ── ContextManager ────────────────────────────────────────────────────────

#[test]
fn cm_chronological_order_preserved() {
    let mut cm = ContextManager::new(10_000);
    cm.set_system("sys");
    for i in 0..10 {
        cm.push(Message::user(format!("m{i}")));
    }
    let b = cm.build();
    assert_eq!(b[0].role, "system");
    // After system, expect chronological m0,m1,...
    for i in 0..10 {
        assert_eq!(b[i + 1].content, format!("m{i}"));
    }
}

#[test]
fn cm_truncates_oldest_when_overflowing() {
    let mut cm = ContextManager::new(40);
    cm.set_system("s");
    for i in 0..50 {
        cm.push(Message::user(format!("msg-{i:03}")));
    }
    let built = cm.build();
    assert_eq!(built[0].role, "system");
    // newest must be present, oldest must be dropped
    let last = built.last().unwrap();
    assert_eq!(last.content, "msg-049");
    assert!(!built.iter().any(|m| m.content == "msg-000"));
}

#[test]
fn cm_no_system_works() {
    let mut cm = ContextManager::new(1024);
    cm.push(Message::user("only user"));
    let b = cm.build();
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].role, "user");
}

#[test]
fn cm_tiny_budget_no_panic() {
    let mut cm = ContextManager::new(0);
    cm.set_system("x");
    cm.push(Message::user("y"));
    let b = cm.build();
    // System always included; history dropped.
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].role, "system");
}

#[test]
fn cm_len_and_is_empty() {
    let mut cm = ContextManager::new(100);
    assert!(cm.is_empty());
    assert_eq!(cm.len(), 0);
    cm.push(Message::user("a"));
    cm.push(Message::user("b"));
    assert!(!cm.is_empty());
    assert_eq!(cm.len(), 2);
}

// ── LlmContextWindow ─────────────────────────────────────────────────────

#[test]
fn cw_remaining_plus_used_le_max() {
    let mut cw = LlmContextWindow::new(4096);
    cw.set_system("expert");
    for i in 0..20 {
        cw.push(Message::user(format!("msg {i}")));
    }
    assert!(cw.used_tokens() + cw.remaining_tokens() <= 4096 + 4);
}

#[test]
fn cw_underflow_is_saturated() {
    let mut cw = LlmContextWindow::new(10);
    cw.set_system("big system ".repeat(50));
    cw.push(Message::user("text ".repeat(50)));
    // Must not panic; remaining_tokens saturates at 0.
    let _ = cw.used_tokens();
    let _ = cw.remaining_tokens();
}

// ── Message constructors / serde round-trip ──────────────────────────────

#[test]
fn message_serde_roundtrip_50x() {
    let mut s = lcg_seed();
    for _ in 0..50 {
        let kind = lcg(&mut s) % 3;
        let m = match kind {
            0 => Message::system(format!("sys{}", lcg(&mut s))),
            1 => Message::user(format!("u{}", lcg(&mut s))),
            _ => Message::assistant(format!("a{}", lcg(&mut s))),
        };
        let j = serde_json::to_string(&m).unwrap();
        let back: Message = serde_json::from_str(&j).unwrap();
        assert_eq!(back.role, m.role);
        assert_eq!(back.content, m.content);
    }
}

// ── LlmRole / LlmModel display ────────────────────────────────────────────

#[test]
fn llmrole_display_values() {
    assert_eq!(LlmRole::System.to_string(), "System");
    assert_eq!(LlmRole::User.to_string(), "User");
    assert_eq!(LlmRole::Assistant.to_string(), "Assistant");
}

#[test]
fn llmmodel_display_all() {
    assert_eq!(LlmModel::Gpt4.to_string(), "Gpt4");
    assert_eq!(LlmModel::Gpt35Turbo.to_string(), "Gpt35Turbo");
    assert_eq!(LlmModel::Claude3Opus.to_string(), "Claude3Opus");
    assert_eq!(LlmModel::Claude3Sonnet.to_string(), "Claude3Sonnet");
    assert_eq!(LlmModel::Claude3Haiku.to_string(), "Claude3Haiku");
    assert_eq!(LlmModel::Llama3.to_string(), "Llama3");
    assert_eq!(LlmModel::Custom("foo".into()).to_string(), "custom:foo");
}

#[test]
fn llmrole_eq_and_clone() {
    let r1 = LlmRole::User;
    let r2 = r1.clone();
    assert_eq!(r1, r2);
    assert_ne!(r1, LlmRole::System);
}

// ── Message → LlmMessage / ChatMessage conversion ─────────────────────────

#[test]
fn message_into_llmmessage_role_map() {
    let s: LlmMessage = Message::system("s").into();
    let u: LlmMessage = Message::user("u").into();
    let a: LlmMessage = Message::assistant("a").into();
    assert_eq!(s.role, LlmRole::System);
    assert_eq!(u.role, LlmRole::User);
    assert_eq!(a.role, LlmRole::Assistant);
    // Unknown role -> User
    let weird: LlmMessage = Message {
        role: "function".into(),
        content: "x".into(),
    }
    .into();
    assert_eq!(weird.role, LlmRole::User);
}

#[test]
fn message_into_chatmessage_role_map() {
    let s: ChatMessage = Message::system("a").into();
    assert_eq!(s.role, Role::System);
    let u: ChatMessage = Message::user("a").into();
    assert_eq!(u.role, Role::User);
    let a: ChatMessage = Message::assistant("a").into();
    assert_eq!(a.role, Role::Assistant);
    let w: ChatMessage = Message {
        role: "tool".into(),
        content: "x".into(),
    }
    .into();
    assert_eq!(w.role, Role::User);
}

#[test]
fn chatmessage_to_plain_roundtrip() {
    for cm in [
        ChatMessage::system("s"),
        ChatMessage::user("u"),
        ChatMessage::assistant("a"),
    ] {
        let plain = cm.to_plain();
        let back: ChatMessage = (&plain).into();
        assert_eq!(back.role, cm.role);
        assert_eq!(back.content, cm.content);
    }
}

// ── Role display + hash/eq consistency ────────────────────────────────────

#[test]
fn role_display_and_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let roles = [Role::System, Role::User, Role::Assistant];
    for a in &roles {
        for b in &roles {
            if a == b {
                let mut h1 = DefaultHasher::new();
                a.hash(&mut h1);
                let mut h2 = DefaultHasher::new();
                b.hash(&mut h2);
                assert_eq!(h1.finish(), h2.finish());
            }
        }
    }
    assert_eq!(Role::System.to_string(), "system");
    assert_eq!(Role::User.to_string(), "user");
    assert_eq!(Role::Assistant.to_string(), "assistant");
}

// ── StopReason from_str / Display round-trip ──────────────────────────────

#[test]
fn stop_reason_display_fromstr_roundtrip() {
    // Note: Display for Stop yields "stop", which from_str maps to EndTurn
    // (an OpenAI alias). So we exclude Stop from the strict round-trip set
    // and verify the alias behaviour separately in `stop_reason_aliases`.
    for sr in [
        StopReason::EndTurn,
        StopReason::ToolUse,
        StopReason::MaxTokens,
    ] {
        let s = sr.to_string();
        let back = StopReason::parse(&s);
        assert_eq!(back, sr);
    }
    // Document the asymmetry: Display(Stop) = "stop" -> EndTurn.
    assert_eq!(StopReason::Stop.to_string(), "stop");
    assert_eq!(StopReason::parse("stop"), StopReason::EndTurn);
}

#[test]
fn stop_reason_aliases() {
    assert_eq!(StopReason::parse("stop"), StopReason::EndTurn);
    assert_eq!(StopReason::parse("tool_calls"), StopReason::ToolUse);
    assert_eq!(StopReason::parse("length"), StopReason::MaxTokens);
    assert_eq!(StopReason::parse("totally-unknown"), StopReason::Stop);
}

// ── LlmCache ──────────────────────────────────────────────────────────────

#[test]
fn cache_capacity_evicts_oldest() {
    let cache = LlmCache::new(3, 600);
    let opts = CompletionOptions::default();
    for i in 0..5 {
        let msgs = vec![Message::user(format!("k{i}"))];
        cache.insert(&msgs, &opts, format!("v{i}"));
    }
    assert!(cache.len() <= 3);
}

#[test]
fn cache_hit_after_insert_50x() {
    let cache = LlmCache::new(200, 600);
    let opts = CompletionOptions::default();
    for i in 0..50 {
        let msgs = vec![Message::user(format!("query-{i}"))];
        cache.insert(&msgs, &opts, format!("resp-{i}"));
        assert_eq!(cache.get(&msgs, &opts), Some(format!("resp-{i}")));
    }
}

#[test]
fn cache_clear_resets() {
    let cache = LlmCache::new(10, 600);
    let msgs = vec![Message::user("x")];
    cache.insert(&msgs, &CompletionOptions::default(), "r".into());
    assert!(!cache.is_empty());
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn cache_threaded_stress() {
    let cache = Arc::new(LlmCache::new(1024, 600));
    let mut handles = Vec::new();
    for t in 0..4 {
        let c = cache.clone();
        handles.push(std::thread::spawn(move || {
            let opts = CompletionOptions::default();
            for i in 0..100 {
                let msgs = vec![Message::user(format!("t{t}-{i}"))];
                c.insert(&msgs, &opts, format!("v{t}-{i}"));
                let _ = c.get(&msgs, &opts);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── LlmRetry ──────────────────────────────────────────────────────────────

#[test]
fn retry_zero_attempt_is_zero_delay() {
    let r = LlmRetry::new(5, 1_000);
    assert_eq!(r.delay_for_attempt(0), 0);
}

#[test]
fn retry_exponential_doubles_until_cap() {
    let r = LlmRetry::new(20, 100);
    let mut prev = r.delay_for_attempt(1);
    for a in 2..15 {
        let cur = r.delay_for_attempt(a);
        assert!(cur >= prev);
        prev = cur;
    }
    assert!(r.delay_for_attempt(50) <= r.max_delay_ms);
}

#[test]
fn retry_no_overflow_at_max_u32() {
    let r = LlmRetry::new(u32::MAX, 1_000_000);
    let _ = r.delay_for_attempt(u32::MAX);
    let _ = r.delay_for_attempt(31);
    let _ = r.delay_for_attempt(63);
}

#[test]
fn retry_default_is_3_attempts() {
    let r = LlmRetry::default();
    assert_eq!(r.max_attempts, 3);
}

// ── LlmRateLimiter ────────────────────────────────────────────────────────

#[test]
fn ratelimiter_exact_budget_consume() {
    let rl = LlmRateLimiter::new(100);
    assert!(rl.try_consume(100));
    assert_eq!(rl.remaining(), 0);
    assert!(!rl.try_consume(1));
}

#[test]
fn ratelimiter_zero_request_ok() {
    let rl = LlmRateLimiter::new(10);
    assert!(rl.try_consume(0));
    assert_eq!(rl.remaining(), 10);
}

#[test]
fn ratelimiter_threaded_invariant() {
    let rl = Arc::new(LlmRateLimiter::new(10_000));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let r = rl.clone();
        handles.push(std::thread::spawn(move || {
            let mut consumed = 0u32;
            for _ in 0..100 {
                if r.try_consume(1) {
                    consumed += 1;
                }
            }
            consumed
        }));
    }
    let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 400);
    assert_eq!(rl.remaining(), 10_000 - 400);
}

// ── LlmCostTracker ────────────────────────────────────────────────────────

#[test]
fn cost_tracker_accumulates() {
    let mut t = LlmCostTracker::new();
    for _ in 0..10 {
        t.record(
            &TokenUsage {
                prompt: 100,
                completion: 100,
                total: 200,
            },
            0.01,
            0.02,
        );
    }
    assert_eq!(t.prompt_tokens, 1000);
    assert_eq!(t.completion_tokens, 1000);
    assert_eq!(t.requests, 10);
    assert_eq!(t.total_tokens(), 2000);
    assert!(t.estimated_cost_usd > 0.0);
}

#[test]
fn cost_tracker_reset_zeroes_all() {
    let mut t = LlmCostTracker::new();
    t.record(
        &TokenUsage {
            prompt: 50,
            completion: 50,
            total: 100,
        },
        0.01,
        0.01,
    );
    t.reset();
    assert_eq!(t.total_tokens(), 0);
    assert_eq!(t.requests, 0);
    assert!(t.estimated_cost_usd.abs() < 1e-9);
}

// ── LlmStreamingResponse ─────────────────────────────────────────────────

#[test]
fn streaming_50_tokens_join_in_order() {
    let mut r = LlmStreamingResponse::new();
    let mut expected = String::new();
    for i in 0..50 {
        let t = format!("t{i}");
        expected.push_str(&t);
        r.push_token(&t);
    }
    assert_eq!(r.token_count(), 50);
    assert_eq!(r.text(), expected);
    assert!(!r.is_complete());
    r.complete("stop");
    assert!(r.is_complete());
}

// ── LlmPromptTemplate ────────────────────────────────────────────────────

#[test]
fn template_substitutes_multiple_keys() {
    let t = LlmPromptTemplate::new("p", "{{a}} and {{b}} then {{a}}");
    let mut vars = HashMap::new();
    vars.insert("a".into(), "X".into());
    vars.insert("b".into(), "Y".into());
    let rendered = t.render(&vars).unwrap();
    assert_eq!(rendered, "X and Y then X");
}

#[test]
fn template_no_placeholders() {
    let t = LlmPromptTemplate::new("p", "plain text");
    let vars = HashMap::new();
    assert_eq!(t.render(&vars).unwrap(), "plain text");
}

#[test]
fn template_lcg_fuzz_no_panic() {
    let mut s = lcg_seed();
    for _ in 0..100 {
        let n = (lcg(&mut s) % 5) as usize;
        let mut tmpl = String::new();
        for i in 0..n {
            tmpl.push_str(&format!("pre{i} {{{{k{i}}}}} post{i} "));
        }
        let t = LlmPromptTemplate::new("x", tmpl);
        let mut vars = HashMap::new();
        if lcg(&mut s) & 1 == 0 {
            for i in 0..n {
                vars.insert(format!("k{i}"), format!("v{i}"));
            }
        }
        let _ = t.render(&vars);
    }
}

// ── LlmJsonMode ──────────────────────────────────────────────────────────

#[test]
fn jsonmode_parses_plain() {
    let v = LlmJsonMode::parse(r#"{"a":1}"#).unwrap();
    assert_eq!(v["a"], 1);
}

#[test]
fn jsonmode_parses_fenced_with_lang() {
    let v = LlmJsonMode::parse("```json\n{\"k\":\"v\"}\n```").unwrap();
    assert_eq!(v["k"], "v");
}

#[test]
fn jsonmode_parses_fenced_no_lang() {
    let v = LlmJsonMode::parse("```\n{\"k\":2}\n```").unwrap();
    assert_eq!(v["k"], 2);
}

#[test]
fn jsonmode_parse_invalid_errs() {
    let r = LlmJsonMode::parse("not json at all");
    assert!(r.is_err());
}

#[test]
fn jsonmode_validate_keys_ok_and_err() {
    let v = serde_json::json!({"a":1,"b":2,"c":3});
    assert!(LlmJsonMode::validate_keys(&v, &["a", "b"]).is_ok());
    assert!(LlmJsonMode::validate_keys(&v, &["missing"]).is_err());
    let arr = serde_json::json!([1, 2]);
    assert!(LlmJsonMode::validate_keys(&arr, &["a"]).is_err());
}

#[test]
fn jsonmode_wrap_adds_directive() {
    let w = LlmJsonMode::wrap_prompt("hi");
    assert!(w.starts_with("hi"));
    assert!(w.contains("JSON"));
}

// ── LlmSystemPrompt ──────────────────────────────────────────────────────

#[test]
fn system_prompt_combines_sections() {
    let p = LlmSystemPrompt::vuln_researcher()
        .with_context("Target", "libc")
        .with_context("Goal", "find UAF")
        .with_output_format("markdown")
        .with_constraint("no speculation")
        .with_constraint("cite line numbers")
        .build();
    assert!(p.contains("vulnerability"));
    assert!(p.contains("libc"));
    assert!(p.contains("find UAF"));
    assert!(p.contains("markdown"));
    assert!(p.contains("no speculation"));
    assert!(p.contains("cite line numbers"));
}

// ── EmbeddingResponse cosine ─────────────────────────────────────────────

#[test]
fn embedding_cosine_bounds() {
    let mut s = lcg_seed();
    for _ in 0..30 {
        let dim = ((lcg(&mut s) % 16) + 1) as usize;
        let a: Vec<f32> = (0..dim)
            .map(|_| (lcg(&mut s) as i32 as f32) / 1e9)
            .collect();
        let b: Vec<f32> = (0..dim)
            .map(|_| (lcg(&mut s) as i32 as f32) / 1e9)
            .collect();
        let ea = EmbeddingResponse::new(a, "m", 0);
        let eb = EmbeddingResponse::new(b, "m", 0);
        let sim = ea.cosine_similarity(&eb);
        assert!(sim.is_finite());
        assert!((-1.0..=1.0).contains(&sim), "sim out of range: {sim}");
    }
}

#[test]
fn embedding_cosine_self_is_one_or_zero() {
    let e = EmbeddingResponse::new(vec![3.0, 4.0], "m", 0);
    let sim = e.cosine_similarity(&e);
    assert!((sim - 1.0).abs() < 1e-6);
    let zero = EmbeddingResponse::new(vec![0.0, 0.0], "m", 0);
    assert_eq!(zero.cosine_similarity(&zero), 0.0);
}

// ── ToolDef / ToolDefinition / ToolUse / LlmFunctionCall ──────────────────

#[test]
fn tooldef_serde_roundtrip() {
    let t = ToolDef::new(
        "rename",
        "rename a symbol",
        serde_json::json!({"type":"object","properties":{"x":{"type":"string"}}}),
    );
    let j = serde_json::to_string(&t).unwrap();
    let back: ToolDef = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, "rename");
    assert_eq!(back.description, t.description);
}

#[test]
fn tooldef_simple_has_object_schema() {
    let t = ToolDef::simple("ping", "pong");
    assert_eq!(t.input_schema["type"], "object");
}

#[test]
fn tooluse_serde_roundtrip_30x() {
    let mut s = lcg_seed();
    for i in 0..30 {
        let tu = ToolUse {
            id: format!("id{i}"),
            name: format!("name{i}"),
            arguments: serde_json::json!({"i": i, "n": lcg(&mut s) as i64}),
        };
        let j = serde_json::to_string(&tu).unwrap();
        let back: ToolUse = serde_json::from_str(&j).unwrap();
        assert_eq!(back.id, tu.id);
        assert_eq!(back.name, tu.name);
        assert_eq!(back.arguments, tu.arguments);
    }
}

#[test]
fn function_result_error_marks_is_error() {
    let r = LlmFunctionResult::error("c1", "tool", "boom");
    assert!(r.is_error);
    assert_eq!(r.content["error"], "boom");
    let s = LlmFunctionResult::success("c2", "tool", serde_json::json!(42));
    assert!(!s.is_error);
}

// ── BackendResponse ──────────────────────────────────────────────────────

#[test]
fn backend_response_text_has_no_tool_uses() {
    let r = BackendResponse::text("hi");
    assert!(!r.has_tool_uses());
    assert_eq!(r.stop_reason, StopReason::EndTurn);
}

#[test]
fn backend_response_with_tool_use() {
    let r = BackendResponse {
        content: String::new(),
        tool_uses: vec![ToolUseBlock {
            id: "x".into(),
            name: "n".into(),
            input: serde_json::json!({}),
        }],
        stop_reason: StopReason::ToolUse,
    };
    assert!(r.has_tool_uses());
}

// ── LlmConfig builder ────────────────────────────────────────────────────

#[test]
fn llmconfig_builder_chains() {
    let c = LlmConfig::new(LlmModel::Gpt4, "k")
        .with_base_url("http://example")
        .with_max_tokens(123)
        .with_temperature(0.7);
    assert_eq!(c.base_url, "http://example");
    assert_eq!(c.max_tokens, 123);
    assert!((c.temperature - 0.7).abs() < 1e-6);
    assert_eq!(c.model, LlmModel::Gpt4);
}

// ── LlmError display ─────────────────────────────────────────────────────

#[test]
fn llm_error_display_variants() {
    let e1 = LlmError::HttpError {
        status: 500,
        body: "x".into(),
    };
    assert!(e1.to_string().contains("500"));
    let e2 = LlmError::ParseError("bad".into());
    assert!(e2.to_string().contains("bad"));
    let e3 = LlmError::AuthError("nope".into());
    assert!(e3.to_string().contains("nope"));
    let e4 = LlmError::RateLimited { retry_after_ms: 7 };
    assert!(e4.to_string().contains('7'));
}

// ── MockLlmProvider (tokio) ──────────────────────────────────────────────

#[tokio::test]
async fn mock_provider_queue_then_default() {
    let p = MockLlmProvider::new();
    let cfg = LlmConfig::new(LlmModel::Llama3, "");
    let r0 = p.complete(vec![], &cfg).await.unwrap();
    assert_eq!(r0.first_text(), Some("mock response"));
    p.queue("alpha");
    let r1 = p.complete(vec![], &cfg).await.unwrap();
    assert_eq!(r1.first_text(), Some("alpha"));
    // With one queued, the single response repeats.
    let r2 = p.complete(vec![], &cfg).await.unwrap();
    assert_eq!(r2.first_text(), Some("alpha"));
    p.queue("beta");
    p.queue("gamma");
    let a = p.complete(vec![], &cfg).await.unwrap();
    let b = p.complete(vec![], &cfg).await.unwrap();
    // First removed, second sticks.
    assert_eq!(a.first_text(), Some("alpha"));
    assert!(matches!(b.first_text(), Some("beta" | "gamma")));
}

// ── ChatRequest builder ───────────────────────────────────────────────────

#[test]
fn chatrequest_builder_basic() {
    let r = ChatRequest::new("m", vec![Message::user("hi")])
        .with_max_tokens(7)
        .with_temperature(0.9)
        .with_stop(vec!["X".into()])
        .streaming();
    assert_eq!(r.max_tokens, 7);
    assert!(r.stream);
    assert_eq!(r.stop_sequences, vec!["X"]);
    assert_eq!(r.model, "m");
}

// ── EmbeddingRequest construction ────────────────────────────────────────

#[test]
fn embedding_request_normalize_default_true() {
    let r = EmbeddingRequest::new("m", "text");
    assert!(r.normalize);
    assert_eq!(r.model, "m");
}

// ── CompletionOptions default ────────────────────────────────────────────

#[test]
fn completion_options_default_sane() {
    let o = CompletionOptions::default();
    assert!(o.temperature >= 0.0);
    assert!(o.top_p > 0.0 && o.top_p <= 1.0);
    assert!(o.max_tokens > 0);
}
