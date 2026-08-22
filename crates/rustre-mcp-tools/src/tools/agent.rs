//! MCP wrappers for the rustre-agent crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{ap_vars_from_json};

pub struct AgentShannonEntropyTool;

pub struct AgentBumpPriorityTool;

pub struct AgentLlmCountTokensTool;

pub struct AgentLlmTrimToBudgetTool;

pub struct AgentLlmExtractCodeBlocksTool;
impl AgentLlmExtractCodeBlocksTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_extract_code_blocks".to_string(),
            description:
                "Extract all fenced ``` code blocks from a markdown-style LLM \
                 response via rustre_agent_llm::llm_response_parser::extract_code_blocks."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["text"],
                "properties": { "text": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmExtractCodeBlocksTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let blocks = rustre_agent_llm::llm_response_parser::extract_code_blocks(text);
        let out: Vec<Value> = blocks.iter().map(|b| json!({
            "language": b.language,
            "content": b.content,
            "start_offset": b.start_offset,
            "end_offset": b.end_offset,
        })).collect();
        Ok(ToolResult::text(json!({
            "count": out.len(),
            "blocks": out,
            "source": "rustre_agent_llm::llm_response_parser::extract_code_blocks",
        }).to_string()))
    }
}

pub struct AgentLlmBuiltinModelsTool;
impl AgentLlmBuiltinModelsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_builtin_models".to_string(),
            description:
                "Return the built-in LLM model catalogue \
                 (Anthropic, OpenAI, Google, Local) via \
                 rustre_agent_llm::model_selector::builtin_models."
                    .to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmBuiltinModelsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let models = rustre_agent_llm::model_selector::builtin_models();
        let out: Vec<Value> = models.iter().map(|m| json!({
            "id": m.id,
            "display_name": m.display_name,
            "provider": format!("{:?}", m.provider),
            "context_window": m.context_window,
            "output_limit": m.output_limit,
            "cost_per_1k_input_tokens": m.cost_per_1k_input_tokens,
            "cost_per_1k_output_tokens": m.cost_per_1k_output_tokens,
            "avg_latency_ms": m.avg_latency_ms,
        })).collect();
        Ok(ToolResult::text(json!({
            "count": out.len(),
            "models": out,
            "source": "rustre_agent_llm::model_selector::builtin_models",
        }).to_string()))
    }
}

pub struct AgentLlmEstimateCostTool;
impl AgentLlmEstimateCostTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_estimate_cost".to_string(),
            description:
                "Estimate USD cost for a given model id and input/output token \
                 counts via rustre_agent_llm::model_selector::estimate_cost. \
                 The model id must belong to the built-in catalogue."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["model_id", "input_tokens", "output_tokens"],
                "properties": {
                    "model_id": { "type": "string" },
                    "input_tokens": { "type": "integer", "minimum": 0 },
                    "output_tokens": { "type": "integer", "minimum": 0 }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmEstimateCostTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("model_id").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'model_id'".into()))?;
        let input_tokens = u32::try_from(
            args.get("input_tokens").and_then(Value::as_u64)
                .ok_or_else(|| McpError::InvalidParams("missing 'input_tokens'".into()))?
        ).map_err(|_| McpError::InvalidParams("'input_tokens' too large".into()))?;
        let output_tokens = u32::try_from(
            args.get("output_tokens").and_then(Value::as_u64)
                .ok_or_else(|| McpError::InvalidParams("missing 'output_tokens'".into()))?
        ).map_err(|_| McpError::InvalidParams("'output_tokens' too large".into()))?;

        let models = rustre_agent_llm::model_selector::builtin_models();
        let model = models.iter().find(|m| m.id == id)
            .ok_or_else(|| McpError::InvalidParams(format!("unknown model_id '{id}'")))?;
        let cost = rustre_agent_llm::model_selector::estimate_cost(model, input_tokens, output_tokens);
        Ok(ToolResult::text(json!({
            "model_id": id,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost,
            "source": "rustre_agent_llm::model_selector::estimate_cost",
        }).to_string()))
    }
}

pub struct AgentCastU64ToF64Tool;

pub struct AgentCastUsizeToF64Tool;

pub struct AgentCastI64ToF64Tool;

pub struct AgentParseConfidenceTool;

pub struct AgentParseVulnerabilitiesTool;

pub struct AgentBuiltinWorkflowsTool;

pub struct AgentLlmMessageSystemTool;

pub struct AgentLlmMessageUserTool;

pub struct AgentPromptsTemplateNewTool;

pub struct AgentPromptsErrorDisplayTool;

pub struct AgentIdNewWireTool;

pub struct AgentMessageRoleAsStrWireTool;

pub struct AgentPromptsBuiltinTemplatesCountTool;

pub struct AgentPromptsRegistryCountTool;

pub struct AgentLlmMessageUserWireTool;

pub struct AgentLlmMessageAssistantWireTool;

pub struct AgentWorkflowBuiltinListTool;

pub struct AgentWorkflowTemplatesListTool;

pub struct AgentCastU64ToF32Tool;
impl AgentCastU64ToF32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_cast_u64_to_f32".to_string(),
            description: "Saturating cast u64 to f32 via rustre_agent::casts::u64_to_f32.".to_string(),
            input_schema: json!({"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentCastU64ToF32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let x = args.get("x").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'x'".into()))?;
        let v = rustre_agent::casts::u64_to_f32(x);
        Ok(ToolResult::text(json!({"input": x, "output": v, "source":"rustre_agent::casts::u64_to_f32"}).to_string()))
    }
}

pub struct AgentCastF64ToF32Tool;
impl AgentCastF64ToF32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_cast_f64_to_f32".to_string(),
            description: "Saturating narrow f64 to f32 via rustre_agent::casts::f64_to_f32.".to_string(),
            input_schema: json!({"type":"object","properties":{"x":{"type":"number"}},"required":["x"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentCastF64ToF32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let x = args.get("x").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'x'".into()))?;
        let v = rustre_agent::casts::f64_to_f32(x);
        Ok(ToolResult::text(json!({"input": x, "output": v, "source":"rustre_agent::casts::f64_to_f32"}).to_string()))
    }
}

pub struct AgentCastF64ToU64Tool;
impl AgentCastF64ToU64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_cast_f64_to_u64".to_string(),
            description: "Saturating cast f64 to u64 via rustre_agent::casts::f64_to_u64.".to_string(),
            input_schema: json!({"type":"object","properties":{"x":{"type":"number"}},"required":["x"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentCastF64ToU64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let x = args.get("x").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'x'".into()))?;
        let v = rustre_agent::casts::f64_to_u64(x);
        Ok(ToolResult::text(json!({"input": x, "output": v, "source":"rustre_agent::casts::f64_to_u64"}).to_string()))
    }
}

pub struct AgentCastF64ToU32Tool;
impl AgentCastF64ToU32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_cast_f64_to_u32".to_string(),
            description: "Saturating cast f64 to u32 via rustre_agent::casts::f64_to_u32.".to_string(),
            input_schema: json!({"type":"object","properties":{"x":{"type":"number"}},"required":["x"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentCastF64ToU32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let x = args.get("x").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'x'".into()))?;
        let v = rustre_agent::casts::f64_to_u32(x);
        Ok(ToolResult::text(json!({"input": x, "output": v, "source":"rustre_agent::casts::f64_to_u32"}).to_string()))
    }
}

pub struct AgentCastU64ToUsizeTool;
impl AgentCastU64ToUsizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_cast_u64_to_usize".to_string(),
            description: "Saturating cast u64 to usize via rustre_agent::casts::u64_to_usize.".to_string(),
            input_schema: json!({"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentCastU64ToUsizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let x = args.get("x").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'x'".into()))?;
        let v = rustre_agent::casts::u64_to_usize(x);
        Ok(ToolResult::text(json!({"input": x, "output": v, "source":"rustre_agent::casts::u64_to_usize"}).to_string()))
    }
}

pub struct AgentCastU64ToU32Tool;
impl AgentCastU64ToU32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_cast_u64_to_u32".to_string(),
            description: "Saturating cast u64 to u32 via rustre_agent::casts::u64_to_u32.".to_string(),
            input_schema: json!({"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentCastU64ToU32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let x = args.get("x").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'x'".into()))?;
        let v = rustre_agent::casts::u64_to_u32(x);
        Ok(ToolResult::text(json!({"input": x, "output": v, "source":"rustre_agent::casts::u64_to_u32"}).to_string()))
    }
}

pub struct AgentStandardRePipelineTool;
impl AgentStandardRePipelineTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_standard_re_pipeline".to_string(),
            description: "Build the standard RE task scheduler pipeline via rustre_agent::task_planner::TaskPlanner::standard_re_pipeline. Returns ordered task list and ready tasks.".to_string(),
            input_schema: json!({"type":"object","properties":{"goal":{"type":"string"}},"required":["goal"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentStandardRePipelineTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let goal = args.get("goal").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'goal'".into()))?;
        let sched = rustre_agent::task_planner::TaskPlanner::standard_re_pipeline(goal);
        let topo = sched.topological_order().unwrap_or_default();
        let ready: Vec<u64> = sched.ready_tasks().iter().map(|t| t.id).collect();
        Ok(ToolResult::text(json!({
            "task_count": sched.graph().len(),
            "topological_order": topo,
            "ready_tasks": ready,
            "source": "rustre_agent::task_planner::TaskPlanner::standard_re_pipeline",
        }).to_string()))
    }
}

pub struct AgentLlmTokenCounterCountTextTool;
impl AgentLlmTokenCounterCountTextTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_token_counter_count_text".to_string(),
            description: "Estimate token count for text via rustre_agent_llm::TokenCounter::count_text (~chars/4 heuristic).".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmTokenCounterCountTextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let tokens = rustre_agent_llm::TokenCounter::count_text(text);
        Ok(ToolResult::text(json!({"tokens":tokens,"source":"rustre_agent_llm::TokenCounter::count_text"}).to_string()))
    }
}

pub struct AgentLlmTokenCounterCountMessagesTool;
impl AgentLlmTokenCounterCountMessagesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_token_counter_count_messages".to_string(),
            description: "Estimate total tokens for a list of {role, content} messages via rustre_agent_llm::TokenCounter::count_messages.".to_string(),
            input_schema: json!({"type":"object","required":["messages"],"properties":{"messages":{"type":"array","items":{"type":"object","properties":{"role":{"type":"string"},"content":{"type":"string"}}}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmTokenCounterCountMessagesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("messages").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'messages'".into()))?;
        let msgs: Vec<rustre_agent_llm::Message> = arr.iter().map(|v| {
            let role = v.get("role").and_then(Value::as_str).unwrap_or("user").to_string();
            let content = v.get("content").and_then(Value::as_str).unwrap_or("").to_string();
            rustre_agent_llm::Message { role, content }
        }).collect();
        let tokens = rustre_agent_llm::TokenCounter::count_messages(&msgs);
        Ok(ToolResult::text(json!({"tokens":tokens,"count":msgs.len(),"source":"rustre_agent_llm::TokenCounter::count_messages"}).to_string()))
    }
}

pub struct AgentLlmTokenCounterFitsInContextTool;
impl AgentLlmTokenCounterFitsInContextTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_token_counter_fits_in_context".to_string(),
            description: "Check whether messages fit within max_tokens via rustre_agent_llm::TokenCounter::fits_in_context.".to_string(),
            input_schema: json!({"type":"object","required":["messages","max_tokens"],"properties":{"messages":{"type":"array"},"max_tokens":{"type":"integer","minimum":0}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmTokenCounterFitsInContextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("messages").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'messages'".into()))?;
        let max_tokens = args.get("max_tokens").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_tokens'".into()))? as u32;
        let msgs: Vec<rustre_agent_llm::Message> = arr.iter().map(|v| rustre_agent_llm::Message {
            role: v.get("role").and_then(Value::as_str).unwrap_or("user").to_string(),
            content: v.get("content").and_then(Value::as_str).unwrap_or("").to_string(),
        }).collect();
        let fits = rustre_agent_llm::TokenCounter::fits_in_context(&msgs, max_tokens);
        Ok(ToolResult::text(json!({"fits":fits,"max_tokens":max_tokens,"source":"rustre_agent_llm::TokenCounter::fits_in_context"}).to_string()))
    }
}

pub struct AgentLlmContextManagerBuildTool;
impl AgentLlmContextManagerBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_context_manager_build".to_string(),
            description: "Build a truncated message list preserving system prompt and newest history within max_tokens via rustre_agent_llm::ContextManager.".to_string(),
            input_schema: json!({"type":"object","required":["max_tokens","messages"],"properties":{"max_tokens":{"type":"integer"},"system":{"type":"string"},"messages":{"type":"array"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmContextManagerBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let max_tokens = args.get("max_tokens").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_tokens'".into()))? as u32;
        let mut cm = rustre_agent_llm::ContextManager::new(max_tokens);
        if let Some(sys) = args.get("system").and_then(Value::as_str) { cm.set_system(sys); }
        if let Some(arr) = args.get("messages").and_then(Value::as_array) {
            for v in arr {
                let role = v.get("role").and_then(Value::as_str).unwrap_or("user");
                let content = v.get("content").and_then(Value::as_str).unwrap_or("").to_string();
                let m = match role {
                    "system" => rustre_agent_llm::Message::system(content),
                    "assistant" => rustre_agent_llm::Message::assistant(content),
                    _ => rustre_agent_llm::Message::user(content),
                };
                cm.push(m);
            }
        }
        let built = cm.build();
        let out: Vec<Value> = built.iter().map(|m| json!({"role":m.role,"content":m.content})).collect();
        Ok(ToolResult::text(json!({"messages":out,"count":built.len(),"source":"rustre_agent_llm::ContextManager::build"}).to_string()))
    }
}

pub struct AgentLlmMessageAssistantTool;
impl AgentLlmMessageAssistantTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_message_assistant".to_string(),
            description: "Construct an assistant Message via rustre_agent_llm::Message::assistant.".to_string(),
            input_schema: json!({"type":"object","required":["content"],"properties":{"content":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmMessageAssistantTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let content = args.get("content").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'content'".into()))?;
        let m = rustre_agent_llm::Message::assistant(content);
        Ok(ToolResult::text(json!({"role":m.role,"content":m.content,"source":"rustre_agent_llm::Message::assistant"}).to_string()))
    }
}

pub struct AgentLlmLlmModelDisplayTool;
impl AgentLlmLlmModelDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_llm_model_display".to_string(),
            description: "Display name for a known LlmModel variant via rustre_agent_llm::LlmModel Display impl. Variants: Gpt4, Gpt35Turbo, Claude3Opus, Claude3Sonnet, Claude3Haiku, Llama3, or Custom(name).".to_string(),
            input_schema: json!({"type":"object","required":["variant"],"properties":{"variant":{"type":"string"},"custom_name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLlmModelDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let variant = args.get("variant").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?;
        let model = match variant {
            "Gpt4" => rustre_agent_llm::LlmModel::Gpt4,
            "Gpt35Turbo" => rustre_agent_llm::LlmModel::Gpt35Turbo,
            "Claude3Opus" => rustre_agent_llm::LlmModel::Claude3Opus,
            "Claude3Sonnet" => rustre_agent_llm::LlmModel::Claude3Sonnet,
            "Claude3Haiku" => rustre_agent_llm::LlmModel::Claude3Haiku,
            "Llama3" => rustre_agent_llm::LlmModel::Llama3,
            "Custom" => {
                let n = args.get("custom_name").and_then(Value::as_str).unwrap_or("").to_string();
                rustre_agent_llm::LlmModel::Custom(n)
            }
            other => return Err(McpError::InvalidParams(format!("unknown variant: {other}"))),
        };
        Ok(ToolResult::text(json!({"display":model.to_string(),"source":"rustre_agent_llm::LlmModel::Display"}).to_string()))
    }
}

pub struct AgentLlmLlmRoleDisplayTool;
impl AgentLlmLlmRoleDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_llm_role_display".to_string(),
            description: "Display name for a LlmRole (System|User|Assistant) via rustre_agent_llm::LlmRole Display impl.".to_string(),
            input_schema: json!({"type":"object","required":["role"],"properties":{"role":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLlmRoleDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let r = args.get("role").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'role'".into()))?;
        let role = match r {
            "System" | "system" => rustre_agent_llm::LlmRole::System,
            "User" | "user" => rustre_agent_llm::LlmRole::User,
            "Assistant" | "assistant" => rustre_agent_llm::LlmRole::Assistant,
            other => return Err(McpError::InvalidParams(format!("unknown role: {other}"))),
        };
        Ok(ToolResult::text(json!({"display":role.to_string(),"source":"rustre_agent_llm::LlmRole::Display"}).to_string()))
    }
}

pub struct AgentLlmMockProviderCompleteTool;
impl AgentLlmMockProviderCompleteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_mock_provider_complete".to_string(),
            description: "Run a MockLlmProvider with queued responses; returns the first_text after complete() via rustre_agent_llm::MockLlmProvider.".to_string(),
            input_schema: json!({"type":"object","properties":{"queued":{"type":"array","items":{"type":"string"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmMockProviderCompleteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_agent_llm::MockLlmProvider::new();
        if let Some(arr) = args.get("queued").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() { p.queue(s.to_string()); }
            }
        }
        let cfg = rustre_agent_llm::LlmConfig::new(rustre_agent_llm::LlmModel::Gpt4, "");
        let resp = <rustre_agent_llm::MockLlmProvider as rustre_agent_llm::LlmProvider>::complete(&p, vec![], &cfg).await
            .map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "first_text": resp.first_text(),
            "model": resp.model,
            "prompt_tokens": resp.usage.prompt_tokens,
            "completion_tokens": resp.usage.completion_tokens,
            "total_tokens": resp.usage.total_tokens,
            "source":"rustre_agent_llm::MockLlmProvider::complete"
        }).to_string()))
    }
}

pub struct AgentPromptsRenderTool;
impl AgentPromptsRenderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_render_template".to_string(),
            description: "Render a {{var}}-placeholder template with a JSON vars object via rustre_agent_prompts::PromptRenderer::render.".to_string(),
            input_schema: json!({"type":"object","required":["template","vars"],"properties":{"template":{"type":"string"},"vars":{"type":"object"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsRenderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let template = args.get("template").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'template'".into()))?;
        let vars = ap_vars_from_json(&args, "vars");
        let rendered = rustre_agent_prompts::PromptRenderer::render(template, &vars)
            .map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"rendered": rendered, "source": "rustre_agent_prompts::PromptRenderer::render"}).to_string()))
    }
}

pub struct AgentPromptsBuiltinNamesTool;
impl AgentPromptsBuiltinNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_builtin_template_names".to_string(),
            description: "List names of built-in RE prompt templates from rustre_agent_prompts::builtin_prompt_templates.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsBuiltinNamesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let names: Vec<String> = rustre_agent_prompts::builtin_prompt_templates().into_iter().map(|t| t.name).collect();
        Ok(ToolResult::text(json!({"names": names, "source": "rustre_agent_prompts::builtin_prompt_templates"}).to_string()))
    }
}

pub struct AgentPromptsRegistryListTool;
impl AgentPromptsRegistryListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_registry_list_names".to_string(),
            description: "Return the sorted list of template names in a fresh rustre_agent_prompts::PromptRegistry.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsRegistryListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_agent_prompts::PromptRegistry::new();
        Ok(ToolResult::text(json!({"names": reg.list_names(), "count": reg.count(), "source": "rustre_agent_prompts::PromptRegistry"}).to_string()))
    }
}

pub struct AgentPromptsRegistryRenderTool;
impl AgentPromptsRegistryRenderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_registry_render".to_string(),
            description: "Look up a built-in SpecPromptTemplate by name and render it with the given vars.".to_string(),
            input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"},"vars":{"type":"object"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsRegistryRenderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let vars = ap_vars_from_json(&args, "vars");
        let reg = rustre_agent_prompts::PromptRegistry::new();
        let t = reg.get(name).ok_or_else(|| McpError::InvalidParams(format!("template not found: {name}")))?;
        let rendered = t.render(&vars).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"rendered": rendered, "name": name, "source": "rustre_agent_prompts::PromptRegistry::get+render"}).to_string()))
    }
}

pub struct AgentPromptsContextBuilderTool;
impl AgentPromptsContextBuilderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_context_build".to_string(),
            description: "Build a structured context string with disasm/decompiled/strings/imports sections via rustre_agent_prompts::ContextBuilder.".to_string(),
            input_schema: json!({"type":"object","properties":{"disassembly":{"type":"string"},"decompiled":{"type":"string"},"strings":{"type":"array","items":{"type":"string"}},"imports":{"type":"array","items":{"type":"string"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsContextBuilderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut b = rustre_agent_prompts::ContextBuilder::new();
        if let Some(s) = args.get("disassembly").and_then(Value::as_str) { b = b.disassembly(s.to_string()); }
        if let Some(s) = args.get("decompiled").and_then(Value::as_str) { b = b.decompiled(s.to_string()); }
        if let Some(arr) = args.get("strings").and_then(Value::as_array) {
            let v: Vec<String> = arr.iter().filter_map(|x| x.as_str().map(String::from)).collect();
            b = b.strings(&v);
        }
        if let Some(arr) = args.get("imports").and_then(Value::as_array) {
            let v: Vec<String> = arr.iter().filter_map(|x| x.as_str().map(String::from)).collect();
            b = b.imports(&v);
        }
        Ok(ToolResult::text(json!({"context": b.build(), "source": "rustre_agent_prompts::ContextBuilder"}).to_string()))
    }
}

pub struct AgentPromptsFewShotRoundTripTool;
impl AgentPromptsFewShotRoundTripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_few_shot_roundtrip".to_string(),
            description: "In-memory FewShotDatabase: insert examples and retrieve up to limit by task_type.".to_string(),
            input_schema: json!({"type":"object","required":["examples","task_type"],"properties":{"examples":{"type":"array"},"task_type":{"type":"string"},"limit":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsFewShotRoundTripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("examples").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'examples'".into()))?;
        let task = args.get("task_type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'task_type'".into()))?;
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(10) as usize;
        let db = rustre_agent_prompts::FewShotDatabase::in_memory().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        for v in arr {
            let ex = rustre_agent_prompts::FewShotExample {
                task_type: v.get("task_type").and_then(Value::as_str).unwrap_or("").to_string(),
                input: v.get("input").and_then(Value::as_str).unwrap_or("").to_string(),
                output: v.get("output").and_then(Value::as_str).unwrap_or("").to_string(),
                explanation: v.get("explanation").and_then(Value::as_str).unwrap_or("").to_string(),
            };
            db.insert(&ex).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        }
        let results = db.get_by_task(task, limit).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let total = db.count().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "results": results.iter().map(|e| json!({"task_type":e.task_type,"input":e.input,"output":e.output,"explanation":e.explanation})).collect::<Vec<_>>(),
            "total_stored": total,
            "source": "rustre_agent_prompts::FewShotDatabase"
        }).to_string()))
    }
}

pub struct AgentPromptsTemplateVarSpecTool;
impl AgentPromptsTemplateVarSpecTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_template_var_spec".to_string(),
            description: "Construct rustre_agent_prompts::TemplateVar (required or optional) and echo its metadata.".to_string(),
            input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"},"default":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsTemplateVarSpecTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let v = if let Some(d) = args.get("default").and_then(Value::as_str) {
            rustre_agent_prompts::TemplateVar::optional(name, d)
        } else {
            rustre_agent_prompts::TemplateVar::required(name)
        };
        Ok(ToolResult::text(json!({"name": v.name, "required": v.required, "default": v.default, "source": "rustre_agent_prompts::TemplateVar"}).to_string()))
    }
}

pub struct AgentPromptsSpecTemplateRenderTool;
impl AgentPromptsSpecTemplateRenderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompts_spec_template_render".to_string(),
            description: "Build a SpecPromptTemplate with declared required vars and render it.".to_string(),
            input_schema: json!({"type":"object","required":["name","template"],"properties":{"name":{"type":"string"},"template":{"type":"string"},"required_vars":{"type":"array","items":{"type":"string"}},"vars":{"type":"object"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsSpecTemplateRenderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let template = args.get("template").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'template'".into()))?;
        let mut t = rustre_agent_prompts::SpecPromptTemplate::new(name, template);
        if let Some(arr) = args.get("required_vars").and_then(Value::as_array) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    t = t.with_var(rustre_agent_prompts::TemplateVar::required(s));
                }
            }
        }
        let vars = ap_vars_from_json(&args, "vars");
        let rendered = t.render(&vars).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"rendered": rendered, "required_count": t.required_vars().len(), "source": "rustre_agent_prompts::SpecPromptTemplate"}).to_string()))
    }
}

pub struct AgentLlmLibMessageFromMessageTool;
impl AgentLlmLibMessageFromMessageTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_message_from_message".to_string(),
            description: "Convert a Message into an LlmMessage.".to_string(),
            input_schema: json!({"type":"object","properties":{"role":{"type":"string"},"content":{"type":"string"}},"required":["role","content"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibMessageFromMessageTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let role = args.get("role").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'role'".into()))?.to_string();
        let content = args.get("content").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'content'".into()))?.to_string();
        let m = rustre_agent_llm::Message { role, content };
        let lm: rustre_agent_llm::LlmMessage = m.into();
        Ok(ToolResult::text(json!({"role": lm.role.to_string(),"content": lm.content,"source":"rustre_agent_llm::LlmMessage::from<Message>"}).to_string()))
    }
}

pub struct AgentLlmLibConfigBuildTool;
impl AgentLlmLibConfigBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_config_build".to_string(),
            description: "Build an LlmConfig via new + builders.".to_string(),
            input_schema: json!({"type":"object","properties":{"model":{"type":"string"},"api_key":{"type":"string"},"base_url":{"type":"string"},"max_tokens":{"type":"integer"},"temperature":{"type":"number"}},"required":["model","api_key"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibConfigBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_agent_llm::{LlmConfig, LlmModel};
        let model_s = args.get("model").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'model'".into()))?;
        let model = match model_s {
            "Gpt4" => LlmModel::Gpt4, "Gpt35Turbo" => LlmModel::Gpt35Turbo,
            "Claude3Opus" => LlmModel::Claude3Opus, "Claude3Sonnet" => LlmModel::Claude3Sonnet,
            "Claude3Haiku" => LlmModel::Claude3Haiku, "Llama3" => LlmModel::Llama3,
            other => LlmModel::Custom(other.to_string()),
        };
        let api_key = args.get("api_key").and_then(Value::as_str).unwrap_or("");
        let mut cfg = LlmConfig::new(model, api_key);
        if let Some(b) = args.get("base_url").and_then(Value::as_str) { cfg = cfg.with_base_url(b); }
        if let Some(n) = args.get("max_tokens").and_then(Value::as_u64) { cfg = cfg.with_max_tokens(n as u32); }
        if let Some(t) = args.get("temperature").and_then(Value::as_f64) { cfg = cfg.with_temperature(t as f32); }
        Ok(ToolResult::text(json!({"model": cfg.model.to_string(),"base_url": cfg.base_url,"max_tokens": cfg.max_tokens,"temperature": cfg.temperature,"source":"rustre_agent_llm::LlmConfig"}).to_string()))
    }
}

pub struct AgentLlmLibResponseFirstTextTool;
impl AgentLlmLibResponseFirstTextTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_response_first_text".to_string(),
            description: "Return first choice text.".to_string(),
            input_schema: json!({"type":"object","properties":{"choices":{"type":"array"}},"required":["choices"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibResponseFirstTextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_agent_llm::{LlmChoice, LlmResponse, LlmUsage};
        let arr = args.get("choices").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'choices'".into()))?;
        let choices: Vec<LlmChoice> = arr.iter().enumerate().map(|(i, v)| LlmChoice {
            text: v.get("text").and_then(Value::as_str).unwrap_or("").to_string(),
            finish_reason: v.get("finish_reason").and_then(Value::as_str).unwrap_or("stop").to_string(),
            index: v.get("index").and_then(Value::as_u64).unwrap_or(i as u64) as u32,
        }).collect();
        let resp = LlmResponse { choices, usage: LlmUsage { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }, model: String::new() };
        Ok(ToolResult::text(json!({"first_text": resp.first_text(),"source":"rustre_agent_llm::LlmResponse::first_text"}).to_string()))
    }
}

pub struct AgentLlmLibRoleParseTool;
impl AgentLlmLibRoleParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_role_parse".to_string(),
            description: "Normalize role string.".to_string(),
            input_schema: json!({"type":"object","properties":{"role":{"type":"string"}},"required":["role"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibRoleParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let role = args.get("role").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'role'".into()))?;
        let msg = match role.to_ascii_lowercase().as_str() {
            "system" => rustre_agent_llm::Message::system(""),
            "assistant" => rustre_agent_llm::Message::assistant(""),
            _ => rustre_agent_llm::Message::user(""),
        };
        let lm: rustre_agent_llm::LlmMessage = (&msg).into();
        Ok(ToolResult::text(json!({"message_role": msg.role,"llm_role": lm.role.to_string(),"source":"rustre_agent_llm::Message"}).to_string()))
    }
}

pub struct AgentLlmLibCompletionOptionsDefaultTool;
impl AgentLlmLibCompletionOptionsDefaultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_completion_options_default".to_string(),
            description: "Return default CompletionOptions.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibCompletionOptionsDefaultTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let o = rustre_agent_llm::CompletionOptions::default();
        Ok(ToolResult::text(json!({"max_tokens": o.max_tokens,"temperature": o.temperature,"top_p": o.top_p,"stop_sequences": o.stop_sequences,"source":"rustre_agent_llm::CompletionOptions::default"}).to_string()))
    }
}

pub struct AgentLlmLibTokenUsageTotalTool;
impl AgentLlmLibTokenUsageTotalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_token_usage_total".to_string(),
            description: "Compute total tokens.".to_string(),
            input_schema: json!({"type":"object","properties":{"prompt":{"type":"integer"},"completion":{"type":"integer"}},"required":["prompt","completion"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibTokenUsageTotalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("prompt").and_then(Value::as_u64).unwrap_or(0) as u32;
        let c = args.get("completion").and_then(Value::as_u64).unwrap_or(0) as u32;
        let u = rustre_agent_llm::TokenUsage { prompt: p, completion: c, total: p.saturating_add(c) };
        Ok(ToolResult::text(json!({"prompt": u.prompt,"completion": u.completion,"total": u.total,"source":"rustre_agent_llm::TokenUsage"}).to_string()))
    }
}

pub struct AgentLlmLibContextManagerLenTool;
impl AgentLlmLibContextManagerLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_context_manager_len".to_string(),
            description: "Build ContextManager.".to_string(),
            input_schema: json!({"type":"object","properties":{"max_tokens":{"type":"integer"},"system":{"type":"string"},"messages":{"type":"array"}},"required":["max_tokens"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibContextManagerLenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let max = args.get("max_tokens").and_then(Value::as_u64).unwrap_or(2048) as u32;
        let mut cm = rustre_agent_llm::ContextManager::new(max);
        if let Some(s) = args.get("system").and_then(Value::as_str) { cm.set_system(s); }
        if let Some(arr) = args.get("messages").and_then(Value::as_array) {
            for v in arr {
                let role = v.get("role").and_then(Value::as_str).unwrap_or("user");
                let content = v.get("content").and_then(Value::as_str).unwrap_or("").to_string();
                let m = match role {
                    "system" => rustre_agent_llm::Message::system(content),
                    "assistant" => rustre_agent_llm::Message::assistant(content),
                    _ => rustre_agent_llm::Message::user(content),
                };
                cm.push(m);
            }
        }
        let built = cm.build();
        Ok(ToolResult::text(json!({"len": cm.len(),"is_empty": cm.is_empty(),"built_count": built.len(),"source":"rustre_agent_llm::ContextManager"}).to_string()))
    }
}

pub struct AgentLlmLibToolDefinitionNewTool;
impl AgentLlmLibToolDefinitionNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_tool_definition_new".to_string(),
            description: "Construct a ToolDefinition.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"description":{"type":"string"},"parameters":{}},"required":["name","description"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibToolDefinitionNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let desc = args.get("description").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'description'".into()))?;
        let params = args.get("parameters").cloned().unwrap_or(Value::Null);
        let td = rustre_agent_llm::ToolDefinition::new(name, desc, params);
        Ok(ToolResult::text(json!({"name": td.name,"description": td.description,"parameters": td.parameters,"source":"rustre_agent_llm::ToolDefinition::new"}).to_string()))
    }
}

pub struct AgentLlmLibListModelVariantsTool;
impl AgentLlmLibListModelVariantsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_list_model_variants".to_string(),
            description: "List all built-in LlmModel variants.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibListModelVariantsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_agent_llm::LlmModel;
        let variants: Vec<String> = [LlmModel::Gpt4, LlmModel::Gpt35Turbo, LlmModel::Claude3Opus, LlmModel::Claude3Sonnet, LlmModel::Claude3Haiku, LlmModel::Llama3].iter().map(std::string::ToString::to_string).collect();
        Ok(ToolResult::text(json!({"variants": variants,"count": 6,"source":"rustre_agent_llm::LlmModel"}).to_string()))
    }
}

pub struct AgentLlmLibCompletionResponseBuildTool;
impl AgentLlmLibCompletionResponseBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_llm_lib_completion_response_build".to_string(),
            description: "Build a CompletionResponse.".to_string(),
            input_schema: json!({"type":"object","properties":{"content":{"type":"string"},"finish_reason":{"type":"string"},"prompt":{"type":"integer"},"completion":{"type":"integer"}},"required":["content"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentLlmLibCompletionResponseBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let content = args.get("content").and_then(Value::as_str).unwrap_or("").to_string();
        let finish = args.get("finish_reason").and_then(Value::as_str).unwrap_or("stop").to_string();
        let p = args.get("prompt").and_then(Value::as_u64).unwrap_or(0) as u32;
        let c = args.get("completion").and_then(Value::as_u64).unwrap_or(0) as u32;
        let r = rustre_agent_llm::CompletionResponse { content, finish_reason: finish, usage: rustre_agent_llm::TokenUsage { prompt: p, completion: c, total: p.saturating_add(c) } };
        Ok(ToolResult::text(json!({"content": r.content,"finish_reason": r.finish_reason,"total": r.usage.total,"source":"rustre_agent_llm::CompletionResponse"}).to_string()))
    }
}

pub struct AgentPromptsV2RenderPairsTool;
impl AgentPromptsV2RenderPairsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_render_pairs".to_string(),
            description: "Render template via PromptRenderer::render_pairs.".to_string(),
            input_schema: json!({"type":"object","properties":{"template":{"type":"string"},"pairs":{"type":"array"}}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2RenderPairsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tpl = args.get("template").and_then(Value::as_str).unwrap_or("");
        let pairs_json = args.get("pairs").cloned().unwrap_or(json!([]));
        let pairs: Vec<(String,String)> = pairs_json.as_array().map(|arr| arr.iter().filter_map(|p| {
            let k = p.get("k").and_then(Value::as_str)?; let v = p.get("v").and_then(Value::as_str)?;
            Some((k.to_string(), v.to_string()))
        }).collect()).unwrap_or_default();
        let refs: Vec<(&str,&str)> = pairs.iter().map(|(a,b)| (a.as_str(), b.as_str())).collect();
        match rustre_agent_prompts::PromptRenderer::render_pairs(tpl, &refs) {
            Ok(s) => Ok(ToolResult::text(json!({"rendered": s, "source":"rustre_agent_prompts::PromptRenderer::render_pairs"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"error": e.to_string()}).to_string())),
        }
    }
}

pub struct AgentPromptsV2ContextBuilderFullTool;
impl AgentPromptsV2ContextBuilderFullTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_context_builder_full".to_string(),
            description: "Build ContextBuilder with disassembly/decompiled/strings/imports.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2ContextBuilderFullTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let d = args.get("disasm").and_then(Value::as_str).unwrap_or("").to_string();
        let c = args.get("decompiled").and_then(Value::as_str).unwrap_or("").to_string();
        let s: Vec<String> = args.get("strings").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let i: Vec<String> = args.get("imports").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let ctx = rustre_agent_prompts::ContextBuilder::new().disassembly(d).decompiled(c).strings(&s).imports(&i).build();
        let clen = ctx.len();
        Ok(ToolResult::text(json!({"context": ctx, "len": clen, "source":"rustre_agent_prompts::ContextBuilder"}).to_string()))
    }
}

pub struct AgentPromptsV2TemplateRegistryBuiltinsTool;
impl AgentPromptsV2TemplateRegistryBuiltinsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_template_registry_builtins".to_string(),
            description: "List built-in TemplateRegistry names and count.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2TemplateRegistryBuiltinsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_agent_prompts::TemplateRegistry::with_builtins();
        let names: Vec<String> = rustre_agent_prompts::builtin_prompt_templates().iter().map(|t| t.name.clone()).collect();
        Ok(ToolResult::text(json!({"count": reg.len(), "names": names, "source":"rustre_agent_prompts::TemplateRegistry::with_builtins"}).to_string()))
    }
}

pub struct AgentPromptsV2FewShotSimilarityTool;
impl AgentPromptsV2FewShotSimilarityTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_few_shot_similarity".to_string(),
            description: "In-memory FewShotDatabase with embeddings + find_similar.".to_string(),
            input_schema: json!({"type":"object","properties":{"k":{"type":"integer"}}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2FewShotSimilarityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("k").and_then(Value::as_u64).unwrap_or(2) as usize;
        let db = rustre_agent_prompts::FewShotDatabase::in_memory().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let ex1 = rustre_agent_prompts::FewShotExample{task_type:"t".into(),input:"a".into(),output:"b".into(),explanation:"e".into()};
        let id1 = db.insert(&ex1).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let ex2 = rustre_agent_prompts::FewShotExample{task_type:"t".into(),input:"c".into(),output:"d".into(),explanation:"e".into()};
        let id2 = db.insert(&ex2).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        db.embed_example(&id1.to_string(), vec![1.0, 0.0, 0.0]);
        db.embed_example(&id2.to_string(), vec![0.0, 1.0, 0.0]);
        let results = db.find_similar(&[1.0, 0.1, 0.0], k);
        Ok(ToolResult::text(json!({"count": results.len(), "top_input": results.first().map(|r| r.input.clone()), "source":"rustre_agent_prompts::FewShotDatabase::find_similar"}).to_string()))
    }
}

pub struct AgentPromptsV2FewShotCountFilterTool;
impl AgentPromptsV2FewShotCountFilterTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_few_shot_count_filter".to_string(),
            description: "Insert then count and filter FewShotDatabase by task.".to_string(),
            input_schema: json!({"type":"object","properties":{"task":{"type":"string"},"n":{"type":"integer"}}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2FewShotCountFilterTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let task = args.get("task").and_then(Value::as_str).unwrap_or("q").to_string();
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize;
        let db = rustre_agent_prompts::FewShotDatabase::in_memory().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        for i in 0..n {
            db.insert(&rustre_agent_prompts::FewShotExample{task_type: task.clone(), input: format!("in{i}"), output: format!("out{i}"), explanation: "x".into()}).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        }
        let total = db.count().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let got = db.get_by_task(&task, 10).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"total": total, "matched": got.len(), "source":"rustre_agent_prompts::FewShotDatabase"}).to_string()))
    }
}

pub struct AgentPromptsV2PromptChainExecuteTool;
impl AgentPromptsV2PromptChainExecuteTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_prompt_chain_execute".to_string(),
            description: "2-step PromptChain::execute with uppercase transform.".to_string(),
            input_schema: json!({"type":"object","properties":{"input":{"type":"string"}}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2PromptChainExecuteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let input = args.get("input").and_then(Value::as_str).unwrap_or("hello").to_string();
        let mut chain = rustre_agent_prompts::PromptChain::new();
        let t1 = rustre_agent_prompts::PromptTemplate::new("s1","Step1: {{input}}", vec!["input".into()], "");
        let t2 = rustre_agent_prompts::PromptTemplate::new("s2","Step2: {{prev}}", vec!["prev".into()], "");
        chain.push(t1, Some("prev".into()));
        chain.push(t2, None);
        let mut vars = std::collections::HashMap::new();
        vars.insert("input".to_string(), input);
        let outputs = chain.execute(vars, str::to_uppercase).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"outputs": outputs, "source":"rustre_agent_prompts::PromptChain::execute"}).to_string()))
    }
}

pub struct AgentPromptsV2SpecRegistryBuiltinsTool;
impl AgentPromptsV2SpecRegistryBuiltinsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_spec_registry_builtins".to_string(),
            description: "List builtin SpecPromptTemplate names.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2SpecRegistryBuiltinsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_agent_prompts::PromptRegistry::new();
        Ok(ToolResult::text(json!({"count": reg.count(), "names": reg.list_names(), "source":"rustre_agent_prompts::PromptRegistry"}).to_string()))
    }
}

pub struct AgentPromptsV2SpecTemplateVarKindsTool;
impl AgentPromptsV2SpecTemplateVarKindsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_spec_template_var_kinds".to_string(),
            description: "TemplateVar required + optional kinds.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"default":{"type":"string"}}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2SpecTemplateVarKindsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("name").and_then(Value::as_str).unwrap_or("x").to_string();
        let d = args.get("default").and_then(Value::as_str).unwrap_or("v").to_string();
        let req = rustre_agent_prompts::TemplateVar::required(n.clone());
        let opt = rustre_agent_prompts::TemplateVar::optional(n, d);
        Ok(ToolResult::text(json!({
            "required":{"name":req.name,"required":req.required,"has_default":req.default.is_some()},
            "optional":{"name":opt.name,"required":opt.required,"default":opt.default},
            "source":"rustre_agent_prompts::TemplateVar"
        }).to_string()))
    }
}

pub struct AgentPromptsV2EngineBuiltinsTool;
impl AgentPromptsV2EngineBuiltinsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_engine_builtins".to_string(),
            description: "List engine::builtin_prompts ids.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2EngineBuiltinsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let list = rustre_agent_prompts::engine::builtin_prompts();
        let ids: Vec<String> = list.iter().map(|t| t.id.clone()).collect();
        Ok(ToolResult::text(json!({"count": list.len(), "ids": ids, "source":"rustre_agent_prompts::engine::builtin_prompts"}).to_string()))
    }
}

pub struct AgentPromptsV2EnginePromptVariableTool;
impl AgentPromptsV2EnginePromptVariableTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "agent_prompts_v2_engine_prompt_variable".to_string(),
            description: "engine::PromptVariable required + optional constructors.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"desc":{"type":"string"},"default":{"type":"string"}}}),
            parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptsV2EnginePromptVariableTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("name").and_then(Value::as_str).unwrap_or("code").to_string();
        let d = args.get("desc").and_then(Value::as_str).unwrap_or("desc").to_string();
        let def = args.get("default").and_then(Value::as_str).unwrap_or("(none)").to_string();
        let r = rustre_agent_prompts::engine::PromptVariable::required(n.clone(), d.clone());
        let o = rustre_agent_prompts::engine::PromptVariable::optional(n, d, def);
        Ok(ToolResult::text(json!({
            "required":{"name":r.name,"description":r.description,"required":r.required},
            "optional":{"name":o.name,"description":o.description,"required":o.required,"default":o.default},
            "source":"rustre_agent_prompts::engine::PromptVariable"
        }).to_string()))
    }
}

pub struct AgentRateLimiterAvailableTool;
impl AgentRateLimiterAvailableTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_rate_limiter_available".to_string(), description: "Available tokens for a fresh rustre_agent::AgentRateLimiter.".to_string(), input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"refill_per_second":{"type":"integer"}},"required":["capacity","refill_per_second"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentRateLimiterAvailableTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as u32; let refill = args.get("refill_per_second").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'refill_per_second'".into()))? as u32; let rl = rustre_agent::AgentRateLimiter::new(cap, refill); Ok(ToolResult::text(json!({"available": rl.available(), "source":"rustre_agent::AgentRateLimiter::available"}).to_string())) } }

pub struct AgentRateLimiterTryAcquireTool;
impl AgentRateLimiterTryAcquireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_rate_limiter_try_acquire".to_string(), description: "Try to acquire N tokens from a fresh rustre_agent::AgentRateLimiter.".to_string(), input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"refill_per_second":{"type":"integer"},"count":{"type":"integer"}},"required":["capacity","refill_per_second","count"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentRateLimiterTryAcquireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as u32; let refill = args.get("refill_per_second").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'refill_per_second'".into()))? as u32; let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))? as u32; let rl = rustre_agent::AgentRateLimiter::new(cap, refill); let ok = rl.try_acquire(count); Ok(ToolResult::text(json!({"acquired": ok, "available_after": rl.available(), "source":"rustre_agent::AgentRateLimiter::try_acquire"}).to_string())) } }

pub struct AgentMetricsSuccessRateTool;
impl AgentMetricsSuccessRateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_metrics_success_rate".to_string(), description: "rustre_agent::AgentMetrics::success_rate from completed/failed.".to_string(), input_schema: json!({"type":"object","properties":{"completed":{"type":"integer"},"failed":{"type":"integer"}},"required":["completed","failed"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentMetricsSuccessRateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("completed").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'completed'".into()))?; let f = args.get("failed").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'failed'".into()))?; let mut m = rustre_agent::AgentMetrics::new(); for _ in 0..c { m.record_success(0, 0); } for _ in 0..f { m.record_failure(); } Ok(ToolResult::text(json!({"success_rate": m.success_rate(), "source":"rustre_agent::AgentMetrics::success_rate"}).to_string())) } }

pub struct AgentMetricsAvgDurationMsTool;
impl AgentMetricsAvgDurationMsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_metrics_avg_duration_ms".to_string(), description: "rustre_agent::AgentMetrics::avg_duration_ms across given durations.".to_string(), input_schema: json!({"type":"object","properties":{"durations_ms":{"type":"array","items":{"type":"integer"}}},"required":["durations_ms"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentMetricsAvgDurationMsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("durations_ms").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'durations_ms'".into()))?; let mut m = rustre_agent::AgentMetrics::new(); for v in arr { m.record_success(v.as_u64().unwrap_or(0), 0); } Ok(ToolResult::text(json!({"avg_duration_ms": m.avg_duration_ms(), "count": arr.len(), "source":"rustre_agent::AgentMetrics::avg_duration_ms"}).to_string())) } }

pub struct AgentMetricsToolSuccessRateTool;
impl AgentMetricsToolSuccessRateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_metrics_tool_success_rate".to_string(), description: "rustre_agent::AgentMetrics::tool_success_rate.".to_string(), input_schema: json!({"type":"object","properties":{"successes":{"type":"integer"},"failures":{"type":"integer"}},"required":["successes","failures"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentMetricsToolSuccessRateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("successes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'successes'".into()))?; let f = args.get("failures").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'failures'".into()))?; let mut m = rustre_agent::AgentMetrics::new(); for _ in 0..s { m.record_tool_call(true); } for _ in 0..f { m.record_tool_call(false); } Ok(ToolResult::text(json!({"tool_success_rate": m.tool_success_rate(), "source":"rustre_agent::AgentMetrics::tool_success_rate"}).to_string())) } }

pub struct AgentPromptGenRenameTool;
impl AgentPromptGenRenameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_prompt_gen_rename".to_string(), description: "rustre_agent::AgentPromptGenerator::rename_prompt.".to_string(), input_schema: json!({"type":"object","properties":{"system_prefix":{"type":"string"},"max_context_chars":{"type":"integer"},"code":{"type":"string"}},"required":["system_prefix","max_context_chars","code"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentPromptGenRenameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let sp = args.get("system_prefix").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'system_prefix'".into()))?; let mc = args.get("max_context_chars").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_context_chars'".into()))? as usize; let code = args.get("code").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))?; let g = rustre_agent::AgentPromptGenerator::new(sp, mc); let prompt = g.rename_prompt(code); Ok(ToolResult::text(json!({"prompt": prompt, "source":"rustre_agent::AgentPromptGenerator::rename_prompt"}).to_string())) } }

pub struct AgentPromptGenMalwareTool;
impl AgentPromptGenMalwareTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_prompt_gen_malware".to_string(), description: "rustre_agent::AgentPromptGenerator::malware_prompt.".to_string(), input_schema: json!({"type":"object","properties":{"system_prefix":{"type":"string"},"max_context_chars":{"type":"integer"},"behavior":{"type":"string"},"iocs":{"type":"array","items":{"type":"string"}}},"required":["system_prefix","max_context_chars","behavior","iocs"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentPromptGenMalwareTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let sp = args.get("system_prefix").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'system_prefix'".into()))?; let mc = args.get("max_context_chars").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_context_chars'".into()))? as usize; let behavior = args.get("behavior").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'behavior'".into()))?; let iocs_arr = args.get("iocs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'iocs'".into()))?; let iocs: Vec<String> = iocs_arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let g = rustre_agent::AgentPromptGenerator::new(sp, mc); let prompt = g.malware_prompt(behavior, &iocs); Ok(ToolResult::text(json!({"prompt": prompt, "source":"rustre_agent::AgentPromptGenerator::malware_prompt"}).to_string())) } }

pub struct AgentMemoryStoreLenTool;
impl AgentMemoryStoreLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_memory_store_len".to_string(), description: "Store entries into rustre_agent::AgentMemory and report len/is_empty.".to_string(), input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"entries":{"type":"array","items":{"type":"object","properties":{"key":{"type":"string"},"value":{}}}}},"required":["capacity","entries"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentMemoryStoreLenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as usize; let arr = args.get("entries").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'entries'".into()))?; let mem = rustre_agent::AgentMemory::new(cap); for v in arr { let k = v.get("key").and_then(Value::as_str).unwrap_or(""); let val = v.get("value").cloned().unwrap_or(Value::Null); mem.store(rustre_agent::MemoryEntry::new(k, val)); } Ok(ToolResult::text(json!({"len": mem.len(), "is_empty": mem.is_empty(), "source":"rustre_agent::AgentMemory"}).to_string())) } }

pub struct AgentTaskQueueLenDrainTool;
impl AgentTaskQueueLenDrainTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_task_queue_len_drain".to_string(), description: "Push N tasks into rustre_agent::AgentTaskQueue and report len then drain count.".to_string(), input_schema: json!({"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentTaskQueueLenDrainTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))?; let q = rustre_agent::AgentTaskQueue::new(); for i in 0..n { q.push(rustre_agent::AgentTask::new(i, format!("t{i}"), rustre_agent::ExtendedCapability::Analyze, rustre_agent::TaskPriority::Normal, Value::Null)); } let len_before = q.len(); let drained = q.drain().len(); Ok(ToolResult::text(json!({"len_before": len_before, "drained": drained, "is_empty_after": q.is_empty(), "source":"rustre_agent::AgentTaskQueue"}).to_string())) } }

pub struct AgentMessageKindFlagsTool;
impl AgentMessageKindFlagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_message_kind_flags".to_string(), description: "Build rustre_agent::SpecAgentMessage and report is_query/is_response.".to_string(), input_schema: json!({"type":"object","properties":{"kind":{"type":"string","enum":["Query","Response","Event","Error","Shutdown"]}},"required":["kind"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AgentMessageKindFlagsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let k = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?; let kind = match k { "Query" => rustre_agent::MessageKind::Query, "Response" => rustre_agent::MessageKind::Response, "Event" => rustre_agent::MessageKind::Event, "Error" => rustre_agent::MessageKind::Error, "Shutdown" => rustre_agent::MessageKind::Shutdown, _ => return Err(McpError::InvalidParams("bad 'kind'".into())) }; let msg = rustre_agent::SpecAgentMessage::new(rustre_agent::AgentId::new(1), rustre_agent::AgentId::new(2), kind, Value::Null); Ok(ToolResult::text(json!({"is_query": msg.is_query(), "is_response": msg.is_response(), "kind": format!("{}", msg.kind), "source":"rustre_agent::SpecAgentMessage"}).to_string())) } }

pub struct AgentReasoningNewV2Tool;
impl AgentReasoningNewV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_reasoning_new_v2".to_string(), description: "AgentReasoning::new(task_id).".to_string(), input_schema: json!({"type":"object","properties":{"task_id":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentReasoningNewV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let tid = args.get("task_id").and_then(Value::as_u64).unwrap_or(0); let r = rustre_agent::AgentReasoning::new(tid); Ok(ToolResult::text(json!({"task_id":r.task_id,"step_count":r.step_count(),"source":"rustre_agent::AgentReasoning::new"}).to_string())) } }

pub struct AgentReasoningAddStepV2Tool;
impl AgentReasoningAddStepV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_reasoning_add_step_v2".to_string(), description: "AgentReasoning::add_step.".to_string(), input_schema: json!({"type":"object","properties":{"thought":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentReasoningAddStepV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let thought = args.get("thought").and_then(Value::as_str).unwrap_or("t"); let mut r = rustre_agent::AgentReasoning::new(1); r.add_step(thought, Some("c".to_string())); r.set_answer("done"); Ok(ToolResult::text(json!({"step_count":r.step_count(),"final_answer":r.final_answer,"source":"rustre_agent::AgentReasoning::add_step"}).to_string())) } }

pub struct AgentPlanNewV2Tool;
impl AgentPlanNewV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_plan_new_v2".to_string(), description: "AgentPlan::new.".to_string(), input_schema: json!({"type":"object","properties":{"goal":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentPlanNewV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let goal = args.get("goal").and_then(Value::as_str).unwrap_or("analyze"); let p = rustre_agent::AgentPlan::new(goal); Ok(ToolResult::text(json!({"goal":p.goal,"step_count":p.step_count(),"estimated_total_ms":p.estimated_total_ms,"source":"rustre_agent::AgentPlan::new"}).to_string())) } }

pub struct AgentSessionNewV2Tool;
impl AgentSessionNewV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_session_new_v2".to_string(), description: "AgentSession::new.".to_string(), input_schema: json!({"type":"object","properties":{"session_id":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentSessionNewV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let sid = args.get("session_id").and_then(Value::as_str).unwrap_or("s1"); let s = rustre_agent::AgentSession::new(sid); Ok(ToolResult::text(json!({"session_id":s.session_id,"is_active":s.is_active(),"source":"rustre_agent::AgentSession::new"}).to_string())) } }

pub struct AgentConversationAddMessageV2Tool;
impl AgentConversationAddMessageV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_conversation_add_message_v2".to_string(), description: "AgentConversation::add_message.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentConversationAddMessageV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mut c = rustre_agent::AgentConversation::new("s"); c.add_message(rustre_agent::MessageRole::User, "hi"); c.add_message(rustre_agent::MessageRole::Assistant, "hello"); Ok(ToolResult::text(json!({"message_count":c.message_count(),"user_messages":c.user_messages().len(),"assistant_messages":c.assistant_messages().len(),"source":"rustre_agent::AgentConversation::add_message"}).to_string())) } }

pub struct AgentMemoryStoreLenV2Tool;
impl AgentMemoryStoreLenV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_memory_store_len_v2".to_string(), description: "AgentMemory::store.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentMemoryStoreLenV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let mem = rustre_agent::AgentMemory::new(16); mem.store(rustre_agent::MemoryEntry::new("k", serde_json::Value::Null)); Ok(ToolResult::text(json!({"len":mem.len(),"is_empty":mem.is_empty(),"get_ok":mem.get("k").is_some(),"source":"rustre_agent::AgentMemory::store"}).to_string())) } }

pub struct AgentMemoryEntryWithTagsV2Tool;
impl AgentMemoryEntryWithTagsV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_memory_entry_with_tags_v2".to_string(), description: "MemoryEntry::with_tags.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentMemoryEntryWithTagsV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let e = rustre_agent::MemoryEntry::new("k", serde_json::Value::Null).with_tags(vec!["a".into(),"b".into()]); Ok(ToolResult::text(json!({"key":e.key,"tag_count":e.tags.len(),"tags":e.tags,"source":"rustre_agent::MemoryEntry::with_tags"}).to_string())) } }

pub struct AgentMetricsNewV2Tool;
impl AgentMetricsNewV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_metrics_new_v2".to_string(), description: "AgentMetrics::new.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentMetricsNewV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let m = rustre_agent::AgentMetrics::new(); Ok(ToolResult::text(json!({"success_rate":m.success_rate(),"avg_duration_ms":m.avg_duration_ms(),"tool_success_rate":m.tool_success_rate(),"source":"rustre_agent::AgentMetrics::new"}).to_string())) } }

pub struct AgentPluginRegistryEmptyV2Tool;
impl AgentPluginRegistryEmptyV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_plugin_registry_empty_v2".to_string(), description: "AgentPluginRegistry::new.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentPluginRegistryEmptyV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let r = rustre_agent::AgentPluginRegistry::new(); Ok(ToolResult::text(json!({"plugin_count":r.plugin_count(),"plugin_names":r.plugin_names(),"source":"rustre_agent::AgentPluginRegistry::new"}).to_string())) } }

pub struct AgentPromptGeneratorRenameV2Tool;
impl AgentPromptGeneratorRenameV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_prompt_generator_rename_v2".to_string(), description: "AgentPromptGenerator::rename_prompt.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentPromptGeneratorRenameV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let g = rustre_agent::AgentPromptGenerator::new("prefix", 4096); let p = g.rename_prompt("int f(){return 0;}"); Ok(ToolResult::text(json!({"prompt_len":p.len(),"source":"rustre_agent::AgentPromptGenerator::rename_prompt"}).to_string())) } }

pub struct AgentRateLimiterResetV2Tool;
impl AgentRateLimiterResetV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_rate_limiter_reset_v2".to_string(), description: "AgentRateLimiter::reset.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentRateLimiterResetV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let l = rustre_agent::AgentRateLimiter::new(10, 1); let ok = l.try_acquire(3); let after = l.available(); l.reset(); Ok(ToolResult::text(json!({"acquired":ok,"available_after_take":after,"available_after_reset":l.available(),"source":"rustre_agent::AgentRateLimiter::reset"}).to_string())) } }

pub struct AgentSelfImprovementAvgRatingV2Tool;
impl AgentSelfImprovementAvgRatingV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "agent_self_improvement_avg_rating_v2".to_string(), description: "AgentSelfImprovement::default.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for AgentSelfImprovementAvgRatingV2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let s = rustre_agent::AgentSelfImprovement::default(); Ok(ToolResult::text(json!({"average_rating":s.average_rating(),"feedback_count":s.feedback_count(),"source":"rustre_agent::AgentSelfImprovement::default"}).to_string())) } }

pub struct AgentTaskQueuePeekPopTool;
impl AgentTaskQueuePeekPopTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_task_queue_peek_pop".to_string(),
            description: "Push a list of {id,priority} tasks into a queue, then peek+pop the highest.".to_string(),
            input_schema: json!({"type":"object","properties":{"tasks":{"type":"array","items":{"type":"object"}}},"required":["tasks"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentTaskQueuePeekPopTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("tasks").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'tasks'".into()))?;
        let q = rustre_agent::AgentTaskQueue::new();
        for t in arr {
            let id = t.get("id").and_then(Value::as_u64).unwrap_or(0);
            let pri = match t.get("priority").and_then(Value::as_str).unwrap_or("Normal") {
                "Low" => rustre_agent::TaskPriority::Low,
                "High" => rustre_agent::TaskPriority::High,
                "Critical" => rustre_agent::TaskPriority::Critical,
                _ => rustre_agent::TaskPriority::Normal,
            };
            q.push(rustre_agent::AgentTask::new(id, "task", rustre_agent::ExtendedCapability::Analyze, pri, json!({})));
        }
        let peeked = q.peek().map(|t| t.id);
        let popped = q.pop().map(|t| t.id);
        Ok(ToolResult::text(json!({"len_after_pop": q.len(), "peeked": peeked, "popped": popped, "source":"rustre_agent::AgentTaskQueue"}).to_string()))
    }
}

pub struct AgentMemoryStoreGetTool;
impl AgentMemoryStoreGetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_memory_store_get".to_string(),
            description: "Store a MemoryEntry with tags then look it up by key and tag.".to_string(),
            input_schema: json!({"type":"object","properties":{"key":{"type":"string"},"value":{},"tags":{"type":"array","items":{"type":"string"}},"capacity":{"type":"integer"}},"required":["key","value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentMemoryStoreGetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key = args.get("key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?;
        let value = args.get("value").cloned().unwrap_or(Value::Null);
        let tags: Vec<String> = args.get("tags").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(16) as usize;
        let mem = rustre_agent::AgentMemory::new(cap);
        let entry = rustre_agent::MemoryEntry::new(key, value).with_tags(tags.clone());
        mem.store(entry);
        let got = mem.get(key).is_some();
        let by_tag = tags.first().map(|t| mem.find_by_tag(t).len()).unwrap_or(0);
        Ok(ToolResult::text(json!({"stored": got, "len": mem.len(), "found_by_first_tag": by_tag, "source":"rustre_agent::AgentMemory"}).to_string()))
    }
}

pub struct AgentMetricsSummaryTool;
impl AgentMetricsSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_metrics_summary".to_string(),
            description: "Compute success rate, avg duration, and tool success rate from a synthetic AgentMetrics run.".to_string(),
            input_schema: json!({"type":"object","properties":{"successes":{"type":"array","items":{"type":"object"}},"failures":{"type":"integer"},"tool_calls":{"type":"array","items":{"type":"boolean"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentMetricsSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut m = rustre_agent::AgentMetrics::new();
        if let Some(arr) = args.get("successes").and_then(Value::as_array) {
            for s in arr {
                let d = s.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
                let t = s.get("tokens").and_then(Value::as_u64).unwrap_or(0);
                m.record_success(d, t);
            }
        }
        let fails = args.get("failures").and_then(Value::as_u64).unwrap_or(0);
        for _ in 0..fails { m.record_failure(); }
        if let Some(arr) = args.get("tool_calls").and_then(Value::as_array) {
            for b in arr { m.record_tool_call(b.as_bool().unwrap_or(false)); }
        }
        Ok(ToolResult::text(json!({
            "success_rate": m.success_rate(),
            "avg_duration_ms": m.avg_duration_ms(),
            "tool_success_rate": m.tool_success_rate(),
            "tasks_completed": m.tasks_completed,
            "tasks_failed": m.tasks_failed,
            "source":"rustre_agent::AgentMetrics"
        }).to_string()))
    }
}

pub struct AgentRateLimiterAcquireTool;
impl AgentRateLimiterAcquireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_rate_limiter_acquire".to_string(),
            description: "Create an AgentRateLimiter and try_acquire a sequence of token counts.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"refill_per_second":{"type":"integer"},"acquires":{"type":"array","items":{"type":"integer"}}},"required":["capacity","refill_per_second","acquires"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentRateLimiterAcquireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as u32;
        let refill = args.get("refill_per_second").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'refill_per_second'".into()))? as u32;
        let acqs = args.get("acquires").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'acquires'".into()))?;
        let rl = rustre_agent::AgentRateLimiter::new(cap, refill);
        let mut results = Vec::new();
        for n in acqs {
            let c = n.as_u64().unwrap_or(0) as u32;
            results.push(rl.try_acquire(c));
        }
        Ok(ToolResult::text(json!({"acquired": results, "available": rl.available(), "source":"rustre_agent::AgentRateLimiter"}).to_string()))
    }
}

pub struct AgentPromptGenDisasmTool;
impl AgentPromptGenDisasmTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompt_gen_disasm".to_string(),
            description: "Build a disassembly explanation prompt via AgentPromptGenerator.".to_string(),
            input_schema: json!({"type":"object","properties":{"system_prefix":{"type":"string"},"max_chars":{"type":"integer"},"disasm":{"type":"string"},"arch":{"type":"string"}},"required":["disasm","arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptGenDisasmTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let prefix = args.get("system_prefix").and_then(Value::as_str).unwrap_or("You are an RE expert.");
        let max_chars = args.get("max_chars").and_then(Value::as_u64).unwrap_or(4000) as usize;
        let disasm = args.get("disasm").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'disasm'".into()))?;
        let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let g = rustre_agent::AgentPromptGenerator::new(prefix, max_chars);
        let prompt = g.disassembly_prompt(disasm, arch);
        let n = prompt.len();
        Ok(ToolResult::text(json!({"prompt": prompt, "len": n, "source":"rustre_agent::AgentPromptGenerator::disassembly_prompt"}).to_string()))
    }
}

pub struct AgentPromptGenVulnTool;
impl AgentPromptGenVulnTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompt_gen_vuln".to_string(),
            description: "Build a vulnerability analysis prompt via AgentPromptGenerator.".to_string(),
            input_schema: json!({"type":"object","properties":{"system_prefix":{"type":"string"},"max_chars":{"type":"integer"},"code":{"type":"string"}},"required":["code"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptGenVulnTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let prefix = args.get("system_prefix").and_then(Value::as_str).unwrap_or("sys");
        let max_chars = args.get("max_chars").and_then(Value::as_u64).unwrap_or(4000) as usize;
        let code = args.get("code").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))?;
        let g = rustre_agent::AgentPromptGenerator::new(prefix, max_chars);
        let prompt = g.vuln_analysis_prompt(code);
        let n = prompt.len();
        Ok(ToolResult::text(json!({"prompt": prompt, "len": n, "source":"rustre_agent::AgentPromptGenerator::vuln_analysis_prompt"}).to_string()))
    }
}

pub struct AgentPromptGenYaraTool;
impl AgentPromptGenYaraTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_prompt_gen_yara".to_string(),
            description: "Build a YARA rule generation prompt via AgentPromptGenerator.".to_string(),
            input_schema: json!({"type":"object","properties":{"system_prefix":{"type":"string"},"strings":{"type":"array","items":{"type":"string"}},"imports":{"type":"array","items":{"type":"string"}}},"required":["strings","imports"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentPromptGenYaraTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let prefix = args.get("system_prefix").and_then(Value::as_str).unwrap_or("sys");
        let strings: Vec<String> = args.get("strings").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let imports: Vec<String> = args.get("imports").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let g = rustre_agent::AgentPromptGenerator::new(prefix, 8192);
        let prompt = g.yara_prompt(&strings, &imports);
        Ok(ToolResult::text(json!({"prompt": prompt, "source":"rustre_agent::AgentPromptGenerator::yara_prompt"}).to_string()))
    }
}

pub struct AgentResponseExtractJsonTool;
impl AgentResponseExtractJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_response_extract_json".to_string(),
            description: "Extract JSON from an LLM response (direct, code-fenced, or mixed text).".to_string(),
            input_schema: json!({"type":"object","properties":{"response":{"type":"string"}},"required":["response"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentResponseExtractJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let resp = args.get("response").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'response'".into()))?;
        let v = rustre_agent::AgentResponseParser::extract_json(resp)
            .map_err(|e| McpError::InternalError(format!("extract_json: {e}")))?;
        Ok(ToolResult::text(json!({"json": v, "source":"rustre_agent::AgentResponseParser::extract_json"}).to_string()))
    }
}

pub struct AgentResponseParseRenamesTool;
impl AgentResponseParseRenamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_response_parse_renames".to_string(),
            description: "Parse rename suggestions map from an LLM response.".to_string(),
            input_schema: json!({"type":"object","properties":{"response":{"type":"string"}},"required":["response"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentResponseParseRenamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let resp = args.get("response").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'response'".into()))?;
        let map = rustre_agent::AgentResponseParser::parse_renames(resp)
            .map_err(|e| McpError::InternalError(format!("parse_renames: {e}")))?;
        let count = map.len();
        Ok(ToolResult::text(json!({"renames": map, "count": count, "source":"rustre_agent::AgentResponseParser::parse_renames"}).to_string()))
    }
}

pub struct AgentSelfImprovementSummaryTool;
impl AgentSelfImprovementSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_self_improvement_summary".to_string(),
            description: "Record a batch of feedback entries and summarize average, positive, negative counts.".to_string(),
            input_schema: json!({"type":"object","properties":{"feedback":{"type":"array","items":{"type":"object"}}},"required":["feedback"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentSelfImprovementSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("feedback").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'feedback'".into()))?;
        let si = rustre_agent::AgentSelfImprovement::new();
        for f in arr {
            let id = f.get("task_id").and_then(Value::as_u64).unwrap_or(0);
            let resp = f.get("response").and_then(Value::as_str).unwrap_or("");
            let rating = f.get("rating").and_then(Value::as_i64).unwrap_or(0) as i8;
            let comment = f.get("comment").and_then(Value::as_str).unwrap_or("");
            si.record_feedback(id, resp, rating, comment);
        }
        Ok(ToolResult::text(json!({
            "count": si.feedback_count(),
            "average_rating": si.average_rating(),
            "positive": si.positive_feedback().len(),
            "negative": si.negative_feedback().len(),
            "source":"rustre_agent::AgentSelfImprovement"
        }).to_string()))
    }
}

pub struct AgentReasoningBuildTool;
impl AgentReasoningBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_reasoning_build".to_string(),
            description: "Build an AgentReasoning chain from a list of thought steps and a final answer.".to_string(),
            input_schema: json!({"type":"object","properties":{"task_id":{"type":"integer"},"steps":{"type":"array","items":{"type":"object"}},"answer":{"type":"string"}},"required":["task_id","steps"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentReasoningBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let task_id = args.get("task_id").and_then(Value::as_u64).unwrap_or(0);
        let steps = args.get("steps").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'steps'".into()))?;
        let answer = args.get("answer").and_then(Value::as_str).unwrap_or("");
        let mut r = rustre_agent::AgentReasoning::new(task_id);
        for s in steps {
            let thought = s.get("thought").and_then(Value::as_str).unwrap_or("");
            let concl = s.get("conclusion").and_then(Value::as_str).map(String::from);
            r.add_step(thought, concl);
        }
        r.set_answer(answer);
        Ok(ToolResult::text(json!({
            "step_count": r.step_count(),
            "final_answer": r.final_answer,
            "task_id": r.task_id,
            "source":"rustre_agent::AgentReasoning"
        }).to_string()))
    }
}

pub struct AgentObservationBuildTool;
impl AgentObservationBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "agent_observation_build".to_string(),
            description: "Construct an AgentObservation with kind, address, confidence, and evidence.".to_string(),
            input_schema: json!({"type":"object","properties":{"kind":{"type":"string"},"description":{"type":"string"},"confidence":{"type":"number"},"address":{"type":"integer"},"evidence":{"type":"array","items":{"type":"string"}}},"required":["kind","description","confidence"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for AgentObservationBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let kind_s = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let kind = match kind_s {
            "FunctionBehavior" => rustre_agent::ObservationKind::FunctionBehavior,
            "StringEvidence" => rustre_agent::ObservationKind::StringEvidence,
            "SuspiciousPattern" => rustre_agent::ObservationKind::SuspiciousPattern,
            "CryptoUsage" => rustre_agent::ObservationKind::CryptoUsage,
            "NetworkActivity" => rustre_agent::ObservationKind::NetworkActivity,
            "FilesystemActivity" => rustre_agent::ObservationKind::FilesystemActivity,
            "RegistryActivity" => rustre_agent::ObservationKind::RegistryActivity,
            "KnownSignature" => rustre_agent::ObservationKind::KnownSignature,
            _ => rustre_agent::ObservationKind::Anomaly,
        };
        let desc = args.get("description").and_then(Value::as_str).unwrap_or("");
        let conf = args.get("confidence").and_then(Value::as_f64).unwrap_or(0.5) as f32;
        let mut obs = rustre_agent::AgentObservation::new(kind, desc, conf);
        if let Some(addr) = args.get("address").and_then(Value::as_u64) {
            obs = obs.at_address(addr);
        }
        if let Some(ev) = args.get("evidence").and_then(Value::as_array) {
            let ev: Vec<String> = ev.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            obs = obs.with_evidence(ev);
        }
        Ok(ToolResult::text(json!({
            "confidence": obs.confidence,
            "address": obs.address,
            "evidence_count": obs.evidence.len(),
            "description": obs.description,
            "source":"rustre_agent::AgentObservation"
        }).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AgentShannonEntropyTool::definition(), Box::new(AgentShannonEntropyTool)),
        (AgentBumpPriorityTool::definition(), Box::new(AgentBumpPriorityTool)),
        (AgentLlmCountTokensTool::definition(), Box::new(AgentLlmCountTokensTool)),
        (AgentLlmTrimToBudgetTool::definition(), Box::new(AgentLlmTrimToBudgetTool)),
        (AgentLlmExtractCodeBlocksTool::definition(), Box::new(AgentLlmExtractCodeBlocksTool)),
        (AgentLlmBuiltinModelsTool::definition(), Box::new(AgentLlmBuiltinModelsTool)),
        (AgentLlmEstimateCostTool::definition(), Box::new(AgentLlmEstimateCostTool)),
        (AgentCastU64ToF64Tool::definition(), Box::new(AgentCastU64ToF64Tool)),
        (AgentCastUsizeToF64Tool::definition(), Box::new(AgentCastUsizeToF64Tool)),
        (AgentCastI64ToF64Tool::definition(), Box::new(AgentCastI64ToF64Tool)),
        (AgentParseConfidenceTool::definition(), Box::new(AgentParseConfidenceTool)),
        (AgentParseVulnerabilitiesTool::definition(), Box::new(AgentParseVulnerabilitiesTool)),
        (AgentBuiltinWorkflowsTool::definition(), Box::new(AgentBuiltinWorkflowsTool)),
        (AgentLlmMessageSystemTool::definition(), Box::new(AgentLlmMessageSystemTool)),
        (AgentLlmMessageUserTool::definition(), Box::new(AgentLlmMessageUserTool)),
        (AgentPromptsTemplateNewTool::definition(), Box::new(AgentPromptsTemplateNewTool)),
        (AgentPromptsErrorDisplayTool::definition(), Box::new(AgentPromptsErrorDisplayTool)),
        (AgentIdNewWireTool::definition(), Box::new(AgentIdNewWireTool)),
        (AgentMessageRoleAsStrWireTool::definition(), Box::new(AgentMessageRoleAsStrWireTool)),
        (AgentPromptsBuiltinTemplatesCountTool::definition(), Box::new(AgentPromptsBuiltinTemplatesCountTool)),
        (AgentPromptsRegistryCountTool::definition(), Box::new(AgentPromptsRegistryCountTool)),
        (AgentLlmMessageUserWireTool::definition(), Box::new(AgentLlmMessageUserWireTool)),
        (AgentLlmMessageAssistantWireTool::definition(), Box::new(AgentLlmMessageAssistantWireTool)),
        (AgentWorkflowBuiltinListTool::definition(), Box::new(AgentWorkflowBuiltinListTool)),
        (AgentWorkflowTemplatesListTool::definition(), Box::new(AgentWorkflowTemplatesListTool)),
        (AgentCastU64ToF32Tool::definition(), Box::new(AgentCastU64ToF32Tool)),
        (AgentCastF64ToF32Tool::definition(), Box::new(AgentCastF64ToF32Tool)),
        (AgentCastF64ToU64Tool::definition(), Box::new(AgentCastF64ToU64Tool)),
        (AgentCastF64ToU32Tool::definition(), Box::new(AgentCastF64ToU32Tool)),
        (AgentCastU64ToUsizeTool::definition(), Box::new(AgentCastU64ToUsizeTool)),
        (AgentCastU64ToU32Tool::definition(), Box::new(AgentCastU64ToU32Tool)),
        (AgentStandardRePipelineTool::definition(), Box::new(AgentStandardRePipelineTool)),
        (AgentLlmTokenCounterCountTextTool::definition(), Box::new(AgentLlmTokenCounterCountTextTool)),
        (AgentLlmTokenCounterCountMessagesTool::definition(), Box::new(AgentLlmTokenCounterCountMessagesTool)),
        (AgentLlmTokenCounterFitsInContextTool::definition(), Box::new(AgentLlmTokenCounterFitsInContextTool)),
        (AgentLlmContextManagerBuildTool::definition(), Box::new(AgentLlmContextManagerBuildTool)),
        (AgentLlmMessageAssistantTool::definition(), Box::new(AgentLlmMessageAssistantTool)),
        (AgentLlmLlmModelDisplayTool::definition(), Box::new(AgentLlmLlmModelDisplayTool)),
        (AgentLlmLlmRoleDisplayTool::definition(), Box::new(AgentLlmLlmRoleDisplayTool)),
        (AgentLlmMockProviderCompleteTool::definition(), Box::new(AgentLlmMockProviderCompleteTool)),
        (AgentPromptsRenderTool::definition(), Box::new(AgentPromptsRenderTool)),
        (AgentPromptsBuiltinNamesTool::definition(), Box::new(AgentPromptsBuiltinNamesTool)),
        (AgentPromptsRegistryListTool::definition(), Box::new(AgentPromptsRegistryListTool)),
        (AgentPromptsRegistryRenderTool::definition(), Box::new(AgentPromptsRegistryRenderTool)),
        (AgentPromptsContextBuilderTool::definition(), Box::new(AgentPromptsContextBuilderTool)),
        (AgentPromptsFewShotRoundTripTool::definition(), Box::new(AgentPromptsFewShotRoundTripTool)),
        (AgentPromptsTemplateVarSpecTool::definition(), Box::new(AgentPromptsTemplateVarSpecTool)),
        (AgentPromptsSpecTemplateRenderTool::definition(), Box::new(AgentPromptsSpecTemplateRenderTool)),
        (AgentLlmLibMessageFromMessageTool::definition(), Box::new(AgentLlmLibMessageFromMessageTool)),
        (AgentLlmLibConfigBuildTool::definition(), Box::new(AgentLlmLibConfigBuildTool)),
        (AgentLlmLibResponseFirstTextTool::definition(), Box::new(AgentLlmLibResponseFirstTextTool)),
        (AgentLlmLibRoleParseTool::definition(), Box::new(AgentLlmLibRoleParseTool)),
        (AgentLlmLibCompletionOptionsDefaultTool::definition(), Box::new(AgentLlmLibCompletionOptionsDefaultTool)),
        (AgentLlmLibTokenUsageTotalTool::definition(), Box::new(AgentLlmLibTokenUsageTotalTool)),
        (AgentLlmLibContextManagerLenTool::definition(), Box::new(AgentLlmLibContextManagerLenTool)),
        (AgentLlmLibToolDefinitionNewTool::definition(), Box::new(AgentLlmLibToolDefinitionNewTool)),
        (AgentLlmLibListModelVariantsTool::definition(), Box::new(AgentLlmLibListModelVariantsTool)),
        (AgentLlmLibCompletionResponseBuildTool::definition(), Box::new(AgentLlmLibCompletionResponseBuildTool)),
        (AgentPromptsV2RenderPairsTool::definition(), Box::new(AgentPromptsV2RenderPairsTool)),
        (AgentPromptsV2ContextBuilderFullTool::definition(), Box::new(AgentPromptsV2ContextBuilderFullTool)),
        (AgentPromptsV2TemplateRegistryBuiltinsTool::definition(), Box::new(AgentPromptsV2TemplateRegistryBuiltinsTool)),
        (AgentPromptsV2FewShotSimilarityTool::definition(), Box::new(AgentPromptsV2FewShotSimilarityTool)),
        (AgentPromptsV2FewShotCountFilterTool::definition(), Box::new(AgentPromptsV2FewShotCountFilterTool)),
        (AgentPromptsV2PromptChainExecuteTool::definition(), Box::new(AgentPromptsV2PromptChainExecuteTool)),
        (AgentPromptsV2SpecRegistryBuiltinsTool::definition(), Box::new(AgentPromptsV2SpecRegistryBuiltinsTool)),
        (AgentPromptsV2SpecTemplateVarKindsTool::definition(), Box::new(AgentPromptsV2SpecTemplateVarKindsTool)),
        (AgentPromptsV2EngineBuiltinsTool::definition(), Box::new(AgentPromptsV2EngineBuiltinsTool)),
        (AgentPromptsV2EnginePromptVariableTool::definition(), Box::new(AgentPromptsV2EnginePromptVariableTool)),
        (AgentRateLimiterAvailableTool::definition(), Box::new(AgentRateLimiterAvailableTool)),
        (AgentRateLimiterTryAcquireTool::definition(), Box::new(AgentRateLimiterTryAcquireTool)),
        (AgentMetricsSuccessRateTool::definition(), Box::new(AgentMetricsSuccessRateTool)),
        (AgentMetricsAvgDurationMsTool::definition(), Box::new(AgentMetricsAvgDurationMsTool)),
        (AgentMetricsToolSuccessRateTool::definition(), Box::new(AgentMetricsToolSuccessRateTool)),
        (AgentPromptGenRenameTool::definition(), Box::new(AgentPromptGenRenameTool)),
        (AgentPromptGenMalwareTool::definition(), Box::new(AgentPromptGenMalwareTool)),
        (AgentMemoryStoreLenTool::definition(), Box::new(AgentMemoryStoreLenTool)),
        (AgentTaskQueueLenDrainTool::definition(), Box::new(AgentTaskQueueLenDrainTool)),
        (AgentMessageKindFlagsTool::definition(), Box::new(AgentMessageKindFlagsTool)),
        (AgentReasoningNewV2Tool::definition(), Box::new(AgentReasoningNewV2Tool)),
        (AgentReasoningAddStepV2Tool::definition(), Box::new(AgentReasoningAddStepV2Tool)),
        (AgentPlanNewV2Tool::definition(), Box::new(AgentPlanNewV2Tool)),
        (AgentSessionNewV2Tool::definition(), Box::new(AgentSessionNewV2Tool)),
        (AgentConversationAddMessageV2Tool::definition(), Box::new(AgentConversationAddMessageV2Tool)),
        (AgentMemoryStoreLenV2Tool::definition(), Box::new(AgentMemoryStoreLenV2Tool)),
        (AgentMemoryEntryWithTagsV2Tool::definition(), Box::new(AgentMemoryEntryWithTagsV2Tool)),
        (AgentMetricsNewV2Tool::definition(), Box::new(AgentMetricsNewV2Tool)),
        (AgentPluginRegistryEmptyV2Tool::definition(), Box::new(AgentPluginRegistryEmptyV2Tool)),
        (AgentPromptGeneratorRenameV2Tool::definition(), Box::new(AgentPromptGeneratorRenameV2Tool)),
        (AgentRateLimiterResetV2Tool::definition(), Box::new(AgentRateLimiterResetV2Tool)),
        (AgentSelfImprovementAvgRatingV2Tool::definition(), Box::new(AgentSelfImprovementAvgRatingV2Tool)),
        (AgentTaskQueuePeekPopTool::definition(), Box::new(AgentTaskQueuePeekPopTool)),
        (AgentMemoryStoreGetTool::definition(), Box::new(AgentMemoryStoreGetTool)),
        (AgentMetricsSummaryTool::definition(), Box::new(AgentMetricsSummaryTool)),
        (AgentRateLimiterAcquireTool::definition(), Box::new(AgentRateLimiterAcquireTool)),
        (AgentPromptGenDisasmTool::definition(), Box::new(AgentPromptGenDisasmTool)),
        (AgentPromptGenVulnTool::definition(), Box::new(AgentPromptGenVulnTool)),
        (AgentPromptGenYaraTool::definition(), Box::new(AgentPromptGenYaraTool)),
        (AgentResponseExtractJsonTool::definition(), Box::new(AgentResponseExtractJsonTool)),
        (AgentResponseParseRenamesTool::definition(), Box::new(AgentResponseParseRenamesTool)),
        (AgentSelfImprovementSummaryTool::definition(), Box::new(AgentSelfImprovementSummaryTool)),
        (AgentReasoningBuildTool::definition(), Box::new(AgentReasoningBuildTool)),
        (AgentObservationBuildTool::definition(), Box::new(AgentObservationBuildTool)),
    ]
}
