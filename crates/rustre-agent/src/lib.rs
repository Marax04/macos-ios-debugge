//! `rustre-agent`
//!
//! Core AI agent framework for reverse engineering automation.
//! Provides the Agent trait, orchestration primitives, and all supporting types.

pub mod agent_tools_full;
pub mod casts;
pub use crate::casts::{
    f64_to_f32, f64_to_u32, f64_to_u64, i64_to_f64, u64_to_f32, u64_to_u32, u64_to_usize,
    usize_to_u32,
};

#[cfg(test)]
mod casts_use {
    use crate::casts::{
        f64_to_f32, f64_to_u32, f64_to_u64, i64_to_f64, u64_to_f32, u64_to_u32, u64_to_usize,
        usize_to_u32,
    };

    #[test]
    fn exercise_casts() {
        let _ = i64_to_f64(-1);
        let _ = u64_to_f32(1);
        let _ = f64_to_f32(1.0);
        // f32_from_f64_bits is exercised via f64_to_f32 above.
        let _ = f64_to_u64(1.0);
        let _ = f64_to_u32(1.0);
        let _ = u64_to_usize(1);
        let _ = usize_to_u32(1);
        let _ = u64_to_u32(1);
    }
}
pub mod re_agent;
pub mod reasoning_engine;
pub mod task_planner;
pub mod agent_task_queue;
pub mod agent_memory_store;
pub mod agent_action_executor;
pub mod tool_registry;
pub mod agent_loop;
pub mod agent_memory;
pub mod context_manager;
pub mod memory_store;
pub mod tool_executor;

use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error type ─────────────────────────────────────────────────────────────

/// Errors that can occur in an agent pipeline.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("LLM backend error: {0}")]
    LlmError(String),

    #[error("operation timed out after {ms}ms")]
    TimeoutError { ms: u64 },

    #[error("failed to parse agent response: {0}")]
    ParseError(String),

    #[error("capability {0:?} is not supported by this agent")]
    CapabilityNotSupported(AgentCapability),

    #[error("agent not initialized")]
    NotInitialized,

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("context window exceeded: {tokens} tokens > {limit}")]
    ContextWindowExceeded { tokens: u32, limit: u32 },

    #[error("agent '{0}' not found in orchestrator")]
    AgentNotFound(String),

    #[error("pipeline error: {0}")]
    PipelineError(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<serde_json::Error> for AgentError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

// ─── Capabilities & Roles ────────────────────────────────────────────────────

/// High-level capabilities that an agent may advertise.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentCapability {
    Disassembly,
    Decompilation,
    TypeRecovery,
    SymbolRename,
    PatternMatching,
    ScriptExecution,
    NetworkAnalysis,
    MalwareAnalysis,
    VulnerabilityDetection,
}

/// Roles used in multi-turn conversation history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

impl MessageRole {
    /// Returns the lowercase string representation expected by most LLM APIs.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

// ─── Message ─────────────────────────────────────────────────────────────────

/// A single message in an agent's conversation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub role: MessageRole,
    pub content: String,
    /// Unix timestamp in milliseconds.
    pub timestamp: u64,
}

impl AgentMessage {
    /// Create a new message with the current system time.
    #[must_use]
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            role,
            content: content.into(),
            timestamp,
        }
    }
}

// ─── Patch ───────────────────────────────────────────────────────────────────

/// A binary patch to be applied at a given address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    /// Target virtual address.
    pub address: u64,
    /// Original bytes (used for verification / rollback).
    pub original: Vec<u8>,
    /// Replacement bytes.
    pub patched: Vec<u8>,
    /// Human-readable description.
    pub description: String,
}

// ─── Actions ─────────────────────────────────────────────────────────────────

/// Actions that an agent can request the platform to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentAction {
    RenameSymbol { addr: u64, name: String },
    AddComment { addr: u64, comment: String },
    ApplyType { addr: u64, ty: String },
    CreateBookmark { addr: u64, name: String },
    RunScript { code: String, engine: String },
    ApplyPatch(Patch),
}

// ─── Artifacts ───────────────────────────────────────────────────────────────

/// Classification of agent-produced artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactType {
    Report,
    Script,
    PatchedBinary,
    TypeDefinitions,
    Signatures,
    Graph,
}

/// A file-like artifact produced by an agent run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub ty: ArtifactType,
    pub data: Vec<u8>,
}

impl Artifact {
    /// Create a new text-based artifact (UTF-8 encoded).
    #[must_use]
    pub fn text(name: impl Into<String>, ty: ArtifactType, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ty,
            data: content.into().into_bytes(),
        }
    }

    /// Decode the artifact data as UTF-8 text.
    /// # Errors
    /// Returns `std::str::Utf8Error` if the artifact bytes are not valid UTF-8.
    pub fn as_text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }
}

// ─── Input / Output ──────────────────────────────────────────────────────────

/// Input supplied to an agent for processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInput {
    /// Free-form task description.
    pub task: String,
    /// Structured context values (disassembly, decompiled code, etc.).
    pub context: HashMap<String, serde_json::Value>,
    /// Optional raw binary data (e.g. the bytes of a function).
    pub binary_data: Option<Vec<u8>>,
    /// Previous conversation turns.
    pub history: Vec<AgentMessage>,
}

impl AgentInput {
    /// Construct a minimal input with only a task description.
    #[must_use]
    pub fn simple(task: impl Into<String>) -> Self {
        Self {
            task: task.into(),
            context: HashMap::new(),
            binary_data: None,
            history: Vec::new(),
        }
    }

    /// Add a context key-value pair.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.context.insert(key.into(), value);
        self
    }
}

/// Output produced by an agent after processing an input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOutput {
    /// Human-readable summary of findings.
    pub result: String,
    /// Platform actions to apply.
    pub actions: Vec<AgentAction>,
    /// Produced artifacts.
    pub artifacts: Vec<Artifact>,
    /// Confidence in the result [0.0, 1.0].
    pub confidence: f32,
    /// Suggested follow-up steps.
    pub next_steps: Vec<String>,
}

impl AgentOutput {
    /// Construct a simple output with a result string and confidence.
    #[must_use]
    pub fn simple(result: impl Into<String>, confidence: f32) -> Self {
        Self {
            result: result.into(),
            actions: Vec::new(),
            artifacts: Vec::new(),
            // NaN-safe clamp: `clamp` propagates NaN, which would then lose
            // every comparison this confidence takes part in.
            confidence: if confidence >= 1.0 {
                1.0
            } else if confidence > 0.0 {
                confidence
            } else {
                0.0
            },
            next_steps: Vec::new(),
        }
    }
}

// ─── Config & Context ────────────────────────────────────────────────────────

/// Configuration for an agent, primarily LLM backend settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub model: String,
    pub api_key: String,
    pub base_url: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub timeout_ms: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            model: "gpt-4o".to_string(),
            api_key: String::new(),
            base_url: "https://api.openai.com".to_string(),
            max_tokens: 4096,
            temperature: 0.2,
            timeout_ms: 60_000,
        }
    }
}

/// Ambient context about the binary being analysed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentContext {
    pub binary_path: Option<PathBuf>,
    pub architecture: String,
    pub os: String,
    pub analysis: HashMap<String, serde_json::Value>,
}

impl AgentContext {
    /// Create a new context for a specific binary.
    #[must_use]
    pub fn new(
        binary_path: Option<PathBuf>,
        architecture: impl Into<String>,
        os: impl Into<String>,
    ) -> Self {
        Self {
            binary_path,
            architecture: architecture.into(),
            os: os.into(),
            analysis: HashMap::new(),
        }
    }
}

// ─── Agent trait ─────────────────────────────────────────────────────────────

/// Core trait that every AI agent must implement.
#[async_trait]
pub trait Agent: Send + Sync {
    /// Short machine-readable name.
    fn name(&self) -> &str;
    /// Human-readable description of what the agent does.
    fn description(&self) -> &str;
    /// List of capabilities this agent provides.
    fn capabilities(&self) -> Vec<AgentCapability>;
    /// Process a single input and produce an output.
    async fn process(
        &self,
        input: AgentInput,
        ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError>;
    /// One-time initialisation with user-supplied configuration.
    async fn initialize(&mut self, config: &AgentConfig) -> Result<(), AgentError>;
}

// ─── Orchestrator ────────────────────────────────────────────────────────────

/// A registered agent together with its current configuration.
struct RegisteredAgent {
    agent: std::sync::Arc<dyn Agent>,
    config: AgentConfig,
}

/// Orchestrates multiple agents, routing sub-tasks to the most capable agent.
pub struct AgentOrchestrator {
    agents: RwLock<Vec<RegisteredAgent>>,
}

impl Default for AgentOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentOrchestrator {
    /// Create a new, empty orchestrator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            agents: RwLock::new(Vec::new()),
        }
    }

    /// Register and initialise an agent.
    /// # Errors
    /// Returns `AgentError` if agent initialization fails.
    pub async fn register(
        &self,
        mut agent: Box<dyn Agent>,
        config: AgentConfig,
    ) -> Result<(), AgentError> {
        agent.initialize(&config).await?;
        let agent: std::sync::Arc<dyn Agent> = std::sync::Arc::from(agent);
        self.agents.write().push(RegisteredAgent { agent, config });
        Ok(())
    }

    /// Find the first registered agent that supports `capability`.
    pub fn find_by_capability(&self, capability: &AgentCapability) -> Option<String> {
        self.agents
            .read()
            .iter()
            .find(|ra| ra.agent.capabilities().contains(capability))
            .map(|ra| ra.agent.name().to_string())
    }

    /// Return the names of all registered agents.
    #[must_use]
    pub fn agent_names(&self) -> Vec<String> {
        self.agents
            .read()
            .iter()
            .map(|ra| ra.agent.name().to_string())
            .collect()
    }

    /// Return a clone of the configuration for the named agent, if registered.
    #[must_use]
    pub fn get_config(&self, agent_name: &str) -> Option<AgentConfig> {
        self.agents
            .read()
            .iter()
            .find(|ra| ra.agent.name() == agent_name)
            .map(|ra| ra.config.clone())
    }

    /// Execute a task on the agent with the given name.
    ///
    /// # Errors
    /// Returns [`AgentError::AgentNotFound`] if no agent with that name is registered.
    pub async fn execute(
        &self,
        agent_name: &str,
        input: AgentInput,
        ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError> {
        // We need to call async process, but RwLock is sync.
        // Collect the name index then release lock before awaiting.
        let index = {
            self.agents
                .read()
                .iter()
                .position(|ra| ra.agent.name() == agent_name)
        };

        let idx = index.ok_or_else(|| AgentError::AgentNotFound(agent_name.to_string()))?;

        // Clone the Arc out of the lock so we can release the lock before the
        // async `process` call. The Arc keeps the agent alive across `.await`.
        let agent = {
            let guard = self.agents.read();
            std::sync::Arc::clone(&guard[idx].agent)
        };
        let output = agent.process(input, ctx).await?;

        Ok(output)
    }

    /// Route a task to the first agent that supports all requested capabilities.
    /// # Errors
    /// Returns `AgentError` if no agent supports the capabilities or processing fails.
    pub async fn route(
        &self,
        capabilities: &[AgentCapability],
        input: AgentInput,
        ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError> {
        let name = {
            self.agents
                .read()
                .iter()
                .find(|ra| {
                    let caps = ra.agent.capabilities();
                    capabilities.iter().all(|c| caps.contains(c))
                })
                .map(|ra| ra.agent.name().to_string())
        };

        let agent_name = name.ok_or_else(|| {
            AgentError::PipelineError(format!("no agent supports capabilities {capabilities:?}"))
        })?;

        self.execute(&agent_name, input, ctx).await
    }

    /// Return the number of registered agents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.agents.read().len()
    }

    /// Return true if no agents are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register all built-in RE workflow agents ([`DisasmAgent`] and
    /// [`VulnAgent`]) returned by [`builtin_workflows()`].
    ///
    /// This is the primary entry-point for wiring the standard agent catalogue
    /// into the orchestrator before running any workflow.
    ///
    /// # Errors
    /// Returns the first [`AgentError`] encountered during agent initialisation.
    pub async fn register_builtin_workflows(&self) -> Result<(), AgentError> {
        for (agent, config) in builtin_workflows() {
            self.register(agent, config).await?;
        }
        Ok(())
    }
}

// ─── Utility: no-op agent (useful for testing / placeholders) ─────────────

/// A no-op agent that returns an empty successful output.
/// Useful as a placeholder or in unit tests.
pub struct NoOpAgent {
    name: String,
    capabilities: Vec<AgentCapability>,
}

impl NoOpAgent {
    #[must_use]
    pub fn new(name: impl Into<String>, capabilities: Vec<AgentCapability>) -> Self {
        Self {
            name: name.into(),
            capabilities,
        }
    }
}

#[async_trait]
impl Agent for NoOpAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &'static str {
        "No-op agent — always returns an empty successful output."
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.capabilities.clone()
    }

    async fn process(
        &self,
        input: AgentInput,
        _ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError> {
        Ok(AgentOutput::simple(
            format!("NoOpAgent processed: {}", input.task),
            1.0,
        ))
    }

    async fn initialize(&mut self, _config: &AgentConfig) -> Result<(), AgentError> {
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper ──────────────────────────────────────────────────────────────

    fn make_context() -> AgentContext {
        AgentContext::new(None, "x86_64", "linux")
    }

    fn make_config() -> AgentConfig {
        AgentConfig {
            model: "test-model".to_string(),
            api_key: "sk-test".to_string(),
            base_url: "http://localhost:11434".to_string(),
            max_tokens: 512,
            temperature: 0.0,
            timeout_ms: 5_000,
        }
    }

    // ── AgentInput ──────────────────────────────────────────────────────────

    #[test]
    fn test_agent_input_simple() {
        let input = AgentInput::simple("analyse function");
        assert_eq!(input.task, "analyse function");
        assert!(input.context.is_empty());
        assert!(input.binary_data.is_none());
        assert!(input.history.is_empty());
    }

    #[test]
    fn test_agent_input_with_context() {
        let input = AgentInput::simple("task")
            .with_context("arch", serde_json::json!("x86_64"))
            .with_context("bits", serde_json::json!(64));
        assert_eq!(input.context.len(), 2);
        assert_eq!(input.context["arch"], serde_json::json!("x86_64"));
    }

    // ── AgentOutput ─────────────────────────────────────────────────────────

    #[test]
    fn test_agent_output_simple() {
        let out = AgentOutput::simple("done", 0.95);
        assert_eq!(out.result, "done");
        assert!((out.confidence - 0.95_f32).abs() < f32::EPSILON);
        assert!(out.actions.is_empty());
        assert!(out.artifacts.is_empty());
    }

    #[test]
    fn test_confidence_clamping() {
        let out = AgentOutput::simple("x", 2.5);
        assert!((out.confidence - 1.0_f32).abs() < f32::EPSILON);
        let out2 = AgentOutput::simple("x", -1.0);
        assert!((out2.confidence).abs() < f32::EPSILON);
    }

    // ── Artifact ────────────────────────────────────────────────────────────

    #[test]
    fn test_artifact_text_roundtrip() {
        let art = Artifact::text("report.txt", ArtifactType::Report, "hello");
        assert_eq!(art.name, "report.txt");
        assert_eq!(art.ty, ArtifactType::Report);
        assert_eq!(art.as_text().unwrap(), "hello");
    }

    // ── MessageRole ─────────────────────────────────────────────────────────

    #[test]
    fn test_message_role_as_str() {
        assert_eq!(MessageRole::System.as_str(), "system");
        assert_eq!(MessageRole::User.as_str(), "user");
        assert_eq!(MessageRole::Assistant.as_str(), "assistant");
        assert_eq!(MessageRole::Tool.as_str(), "tool");
    }

    // ── AgentMessage ────────────────────────────────────────────────────────

    #[test]
    fn test_agent_message_new() {
        let msg = AgentMessage::new(MessageRole::User, "hello");
        assert_eq!(msg.role, MessageRole::User);
        assert_eq!(msg.content, "hello");
        assert!(msg.timestamp > 0);
    }

    // ── AgentConfig default ─────────────────────────────────────────────────

    #[test]
    fn test_config_default() {
        let cfg = AgentConfig::default();
        assert_eq!(cfg.model, "gpt-4o");
        assert_eq!(cfg.max_tokens, 4096);
    }

    // ── AgentContext ────────────────────────────────────────────────────────

    #[test]
    fn test_context_construction() {
        let ctx = AgentContext::new(Some(PathBuf::from("/bin/ls")), "arm64", "linux");
        assert_eq!(ctx.architecture, "arm64");
        assert_eq!(ctx.os, "linux");
        assert!(ctx.binary_path.is_some());
    }

    // ── AgentCapability ─────────────────────────────────────────────────────

    #[test]
    fn test_capability_clone_eq() {
        let c = AgentCapability::VulnerabilityDetection;
        assert_eq!(c, AgentCapability::VulnerabilityDetection);
        let c2 = c.clone();
        assert_eq!(c, c2);
    }

    // ── Patch ───────────────────────────────────────────────────────────────

    #[test]
    fn test_patch_fields() {
        let p = Patch {
            address: 0x1000,
            original: vec![0x90],
            patched: vec![0xCC],
            description: "breakpoint".to_string(),
        };
        assert_eq!(p.address, 0x1000);
        assert_eq!(p.patched, vec![0xCC]);
    }

    // ── AgentAction serialisation ────────────────────────────────────────────

    #[test]
    fn test_action_serialization() {
        let action = AgentAction::RenameSymbol {
            addr: 0xDEAD,
            name: "malloc_wrapper".to_string(),
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: AgentAction = serde_json::from_str(&json).unwrap();
        if let AgentAction::RenameSymbol { addr, name } = back {
            assert_eq!(addr, 0xDEAD);
            assert_eq!(name, "malloc_wrapper");
        } else {
            panic!("wrong variant");
        }
    }

    // ── NoOpAgent ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_no_op_agent_process() {
        let agent = NoOpAgent::new("noop", vec![AgentCapability::Disassembly]);
        let input = AgentInput::simple("test task");
        let ctx = make_context();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(out.result.contains("test task"));
        assert!((out.confidence - 1.0_f32).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_no_op_agent_capabilities() {
        let agent = NoOpAgent::new(
            "multi",
            vec![AgentCapability::Disassembly, AgentCapability::Decompilation],
        );
        assert_eq!(agent.capabilities().len(), 2);
        assert_eq!(agent.name(), "multi");
    }

    // ── AgentOrchestrator ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_orchestrator_register_and_names() {
        let orch = AgentOrchestrator::new();
        let agent = Box::new(NoOpAgent::new(
            "agent-a",
            vec![AgentCapability::Disassembly],
        ));
        orch.register(agent, make_config()).await.unwrap();
        assert_eq!(orch.agent_names(), vec!["agent-a"]);
    }

    #[tokio::test]
    async fn test_orchestrator_find_by_capability() {
        let orch = AgentOrchestrator::new();
        let agent = Box::new(NoOpAgent::new(
            "vuln-agent",
            vec![AgentCapability::VulnerabilityDetection],
        ));
        orch.register(agent, make_config()).await.unwrap();
        let found = orch.find_by_capability(&AgentCapability::VulnerabilityDetection);
        assert_eq!(found.as_deref(), Some("vuln-agent"));
        let not_found = orch.find_by_capability(&AgentCapability::Decompilation);
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_orchestrator_execute() {
        let orch = AgentOrchestrator::new();
        let agent = Box::new(NoOpAgent::new(
            "exec-agent",
            vec![AgentCapability::Disassembly],
        ));
        orch.register(agent, make_config()).await.unwrap();
        let out = orch
            .execute(
                "exec-agent",
                AgentInput::simple("do disasm"),
                &make_context(),
            )
            .await
            .unwrap();
        assert!(out.result.contains("do disasm"));
    }

    #[tokio::test]
    async fn test_orchestrator_execute_not_found() {
        let orch = AgentOrchestrator::new();
        let err = orch
            .execute("ghost", AgentInput::simple("x"), &make_context())
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::AgentNotFound(_)));
    }

    #[tokio::test]
    async fn test_orchestrator_route() {
        let orch = AgentOrchestrator::new();
        let agent = Box::new(NoOpAgent::new(
            "full-agent",
            vec![
                AgentCapability::Disassembly,
                AgentCapability::Decompilation,
                AgentCapability::SymbolRename,
            ],
        ));
        orch.register(agent, make_config()).await.unwrap();
        let out = orch
            .route(
                &[AgentCapability::Disassembly, AgentCapability::SymbolRename],
                AgentInput::simple("route test"),
                &make_context(),
            )
            .await
            .unwrap();
        assert!(out.result.contains("route test"));
    }

    #[tokio::test]
    async fn test_orchestrator_route_no_match() {
        let orch = AgentOrchestrator::new();
        let agent = Box::new(NoOpAgent::new(
            "limited",
            vec![AgentCapability::Disassembly],
        ));
        orch.register(agent, make_config()).await.unwrap();
        let err = orch
            .route(
                &[AgentCapability::MalwareAnalysis],
                AgentInput::simple("malware"),
                &make_context(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::PipelineError(_)));
    }

    #[tokio::test]
    async fn test_orchestrator_is_empty_len() {
        let orch = AgentOrchestrator::new();
        assert!(orch.is_empty());
        let agent = Box::new(NoOpAgent::new("a", vec![]));
        orch.register(agent, make_config()).await.unwrap();
        assert!(!orch.is_empty());
        assert_eq!(orch.len(), 1);
    }

    // ── Error variants ───────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = AgentError::TimeoutError { ms: 5000 };
        assert!(e.to_string().contains("5000"));
        let e2 = AgentError::CapabilityNotSupported(AgentCapability::Decompilation);
        assert!(e2.to_string().contains("Decompilation"));
    }

    #[test]
    fn test_agent_error_from_serde() {
        let bad_json = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let e: AgentError = bad_json.into();
        assert!(matches!(e, AgentError::SerializationError(_)));
    }
}

// ─── Spec-required types ──────────────────────────────────────────────────────

use parking_lot::RwLock as ParkingRwLock;
use std::sync::Arc;

/// Unique agent identifier (spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId {
    pub inner: u64,
}

impl AgentId {
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self { inner: id }
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Agent({})", self.inner)
    }
}

/// Kind of an agent message (spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageKind {
    Query,
    Response,
    Event,
    Error,
    Shutdown,
}

impl std::fmt::Display for MessageKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Message exchanged between agents (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecAgentMessage {
    pub id: u64,
    pub from: AgentId,
    pub to: AgentId,
    pub kind: MessageKind,
    pub payload: serde_json::Value,
}

impl SpecAgentMessage {
    #[must_use]
    pub fn new(from: AgentId, to: AgentId, kind: MessageKind, payload: serde_json::Value) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            id: COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            from,
            to,
            kind,
            payload,
        }
    }

    #[must_use]
    pub fn is_query(&self) -> bool {
        self.kind == MessageKind::Query
    }

    #[must_use]
    pub fn is_response(&self) -> bool {
        self.kind == MessageKind::Response
    }
}

/// Agent lifecycle status (spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Idle,
    Running,
    Waiting,
    Stopped,
    AgentError(String),
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Running => write!(f, "Running"),
            Self::Waiting => write!(f, "Waiting"),
            Self::Stopped => write!(f, "Stopped"),
            Self::AgentError(s) => write!(f, "Error({s})"),
        }
    }
}

/// Agent capability enum (spec).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpecAgentCapability {
    Analyze,
    Decompile,
    Debug,
    Search,
    Generate,
    ThreatIntel,
    Generic(String),
}

impl std::fmt::Display for SpecAgentCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generic(s) => write!(f, "Generic({s})"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// Agent info descriptor (spec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: AgentId,
    pub name: String,
    pub capabilities: Vec<SpecAgentCapability>,
    pub status: AgentStatus,
}

/// Error type for spec Agent trait.
#[derive(Debug, thiserror::Error)]
pub enum SpecAgentError {
    #[error("agent not found: {0}")]
    NotFound(u64),
    #[error("agent timed out")]
    Timeout,
    #[error("handle error: {0}")]
    HandleError(String),
    #[error("agent already running")]
    AlreadyRunning,
}

/// Core agent trait (spec).
#[async_trait::async_trait]
pub trait SpecAgent: Send + Sync {
    fn info(&self) -> &AgentInfo;
    async fn handle(&self, msg: SpecAgentMessage) -> Result<SpecAgentMessage, SpecAgentError>;
    async fn start(&mut self) -> Result<(), SpecAgentError>;
    async fn stop(&mut self) -> Result<(), SpecAgentError>;
}

/// Thread-safe registry of spec agents.
pub struct AgentRegistry {
    pub agents: ParkingRwLock<HashMap<u64, Arc<dyn SpecAgent>>>,
}

impl AgentRegistry {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            agents: ParkingRwLock::new(HashMap::new()),
        })
    }

    pub fn register(&self, agent: Arc<dyn SpecAgent>) {
        let id = agent.info().id.inner;
        self.agents.write().insert(id, agent);
    }

    #[must_use]
    pub fn find(&self, id: AgentId) -> Option<Arc<dyn SpecAgent>> {
        self.agents.read().get(&id.inner).cloned()
    }

    #[must_use]
    pub fn list_ids(&self) -> Vec<AgentId> {
        self.agents
            .read()
            .keys()
            .copied()
            .map(AgentId::new)
            .collect()
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.agents.read().len()
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self {
            agents: ParkingRwLock::new(HashMap::new()),
        }
    }
}

/// A mock agent that queues responses (spec).
pub struct MockAgent {
    pub info: AgentInfo,
    pub responses: parking_lot::Mutex<Vec<SpecAgentMessage>>,
}

impl MockAgent {
    #[must_use]
    pub const fn new(info: AgentInfo) -> Self {
        Self {
            info,
            responses: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn queue_response(&self, msg: SpecAgentMessage) {
        self.responses.lock().push(msg);
    }
}

#[async_trait::async_trait]
impl SpecAgent for MockAgent {
    fn info(&self) -> &AgentInfo {
        &self.info
    }

    async fn handle(&self, msg: SpecAgentMessage) -> Result<SpecAgentMessage, SpecAgentError> {
        let resp = {
            let mut lock = self.responses.lock();
            if lock.is_empty() {
                return Err(SpecAgentError::HandleError(
                    "no responses queued".to_string(),
                ));
            }
            lock.remove(0)
        };
        let _ = msg;
        Ok(resp)
    }

    async fn start(&mut self) -> Result<(), SpecAgentError> {
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), SpecAgentError> {
        Ok(())
    }
}

#[cfg(test)]
mod spec_tests {
    use super::*;

    fn make_info(id: u64) -> AgentInfo {
        AgentInfo {
            id: AgentId::new(id),
            name: format!("agent-{id}"),
            capabilities: vec![SpecAgentCapability::Analyze],
            status: AgentStatus::Idle,
        }
    }

    fn make_msg(from: u64, to: u64) -> SpecAgentMessage {
        SpecAgentMessage::new(
            AgentId::new(from),
            AgentId::new(to),
            MessageKind::Query,
            serde_json::json!({"task": "analyze"}),
        )
    }

    #[test]
    fn test_agent_id_display() {
        let id = AgentId::new(42);
        assert_eq!(id.to_string(), "Agent(42)");
    }

    #[test]
    fn test_agent_id_new() {
        let id = AgentId::new(1);
        assert_eq!(id.inner, 1);
    }

    #[test]
    fn test_message_kind_display() {
        assert_eq!(MessageKind::Query.to_string(), "Query");
        assert_eq!(MessageKind::Response.to_string(), "Response");
        assert_eq!(MessageKind::Event.to_string(), "Event");
        assert_eq!(MessageKind::Error.to_string(), "Error");
        assert_eq!(MessageKind::Shutdown.to_string(), "Shutdown");
    }

    #[test]
    fn test_spec_agent_message_new() {
        let msg = make_msg(1, 2);
        assert!(msg.is_query());
        assert!(!msg.is_response());
        assert_eq!(msg.from.inner, 1);
        assert_eq!(msg.to.inner, 2);
    }

    #[test]
    fn test_spec_agent_message_is_response() {
        let msg = SpecAgentMessage::new(
            AgentId::new(1),
            AgentId::new(2),
            MessageKind::Response,
            serde_json::json!({}),
        );
        assert!(msg.is_response());
        assert!(!msg.is_query());
    }

    #[test]
    fn test_agent_status_display() {
        assert_eq!(AgentStatus::Idle.to_string(), "Idle");
        assert_eq!(AgentStatus::Running.to_string(), "Running");
        assert_eq!(AgentStatus::Waiting.to_string(), "Waiting");
        assert_eq!(AgentStatus::Stopped.to_string(), "Stopped");
        assert_eq!(
            AgentStatus::AgentError("crash".to_string()).to_string(),
            "Error(crash)"
        );
    }

    #[test]
    fn test_spec_agent_capability_display() {
        assert_eq!(SpecAgentCapability::Analyze.to_string(), "Analyze");
        assert_eq!(
            SpecAgentCapability::Generic("custom".to_string()).to_string(),
            "Generic(custom)"
        );
    }

    #[test]
    fn test_agent_registry_new() {
        let reg = AgentRegistry::new();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_agent_registry_register_and_find() {
        let reg = AgentRegistry::new();
        let info = make_info(10);
        let agent = Arc::new(MockAgent::new(info));
        reg.register(agent);
        assert_eq!(reg.count(), 1);
        let found = reg.find(AgentId::new(10));
        assert!(found.is_some());
    }

    #[test]
    fn test_agent_registry_find_missing() {
        let reg = AgentRegistry::new();
        assert!(reg.find(AgentId::new(999)).is_none());
    }

    #[test]
    fn test_agent_registry_list_ids() {
        let reg = AgentRegistry::new();
        reg.register(Arc::new(MockAgent::new(make_info(1))));
        reg.register(Arc::new(MockAgent::new(make_info(2))));
        let ids = reg.list_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_mock_agent_info() {
        let info = make_info(5);
        let agent = MockAgent::new(info);
        assert_eq!(agent.info().id.inner, 5);
        assert_eq!(agent.info().name, "agent-5");
    }

    #[tokio::test]
    async fn test_mock_agent_handle_queued() {
        let info = make_info(1);
        let agent = MockAgent::new(info.clone());
        let resp = SpecAgentMessage::new(
            AgentId::new(1),
            AgentId::new(2),
            MessageKind::Response,
            serde_json::json!({"result": "ok"}),
        );
        agent.queue_response(resp);
        let query = make_msg(2, 1);
        let result = agent.handle(query).await.unwrap();
        assert!(result.is_response());
    }

    #[tokio::test]
    async fn test_mock_agent_handle_empty_error() {
        let info = make_info(1);
        let agent = MockAgent::new(info);
        let query = make_msg(2, 1);
        let result = agent.handle(query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_agent_start_stop() {
        let info = make_info(1);
        let mut agent = MockAgent::new(info);
        assert!(agent.start().await.is_ok());
        assert!(agent.stop().await.is_ok());
    }

    #[test]
    fn test_spec_agent_error_display() {
        let e = SpecAgentError::NotFound(42);
        assert!(e.to_string().contains("42"));
        let e2 = SpecAgentError::Timeout;
        assert!(e2.to_string().contains("timed out"));
        let e3 = SpecAgentError::HandleError("bad".to_string());
        assert!(e3.to_string().contains("bad"));
        let e4 = SpecAgentError::AlreadyRunning;
        assert!(e4.to_string().contains("running"));
    }

    #[test]
    fn test_agent_info_fields() {
        let info = make_info(7);
        assert_eq!(info.id.inner, 7);
        assert!(!info.capabilities.is_empty());
        assert_eq!(info.status, AgentStatus::Idle);
    }

    #[test]
    fn test_spec_agent_message_id_increments() {
        let m1 = make_msg(1, 2);
        let m2 = make_msg(1, 2);
        assert_ne!(m1.id, m2.id);
    }

    #[test]
    fn test_spec_capability_all_variants() {
        let caps = [SpecAgentCapability::Analyze,
            SpecAgentCapability::Decompile,
            SpecAgentCapability::Debug,
            SpecAgentCapability::Search,
            SpecAgentCapability::Generate,
            SpecAgentCapability::ThreatIntel,
            SpecAgentCapability::Generic("custom".to_string())];
        assert_eq!(caps.len(), 7);
    }
}

// ─── Extended Capability enum ─────────────────────────────────────────────────

/// Extended agent capability set covering all RE analysis functions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtendedCapability {
    Disassemble,
    Decompile,
    Analyze,
    Explain,
    Rename,
    Document,
    FindVulns,
    ExplainSuspicious,
    GenerateSignature,
    CorrelateThreats,
}

impl std::fmt::Display for ExtendedCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── AgentTask ───────────────────────────────────────────────────────────────

/// Priority level for a task in the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaskPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// A discrete unit of work for the agent to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: u64,
    pub description: String,
    pub capability: ExtendedCapability,
    pub priority: TaskPriority,
    pub payload: serde_json::Value,
    pub created_at: u64,
    pub deadline_ms: Option<u64>,
}

impl AgentTask {
    /// Create a new task.
    #[must_use]
    pub fn new(
        id: u64,
        description: impl Into<String>,
        capability: ExtendedCapability,
        priority: TaskPriority,
        payload: serde_json::Value,
    ) -> Self {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id,
            description: description.into(),
            capability,
            priority,
            payload,
            created_at,
            deadline_ms: None,
        }
    }

    /// Attach a deadline in absolute milliseconds since epoch.
    #[must_use]
    pub const fn with_deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    /// Returns `true` if this task has expired its deadline.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let Some(dl) = self.deadline_ms else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        now > dl
    }
}

// ─── AgentTaskQueue ──────────────────────────────────────────────────────────

/// Priority queue of pending agent tasks.
pub struct AgentTaskQueue {
    tasks: parking_lot::Mutex<Vec<AgentTask>>,
}

impl AgentTaskQueue {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tasks: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Push a task into the queue.
    pub fn push(&self, task: AgentTask) {
        let mut guard = self.tasks.lock();
        guard.push(task);
        guard.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Pop the highest-priority non-expired task.
    pub fn pop(&self) -> Option<AgentTask> {
        let mut guard = self.tasks.lock();
        guard.retain(|t| !t.is_expired());
        if guard.is_empty() {
            None
        } else {
            Some(guard.remove(0))
        }
    }

    /// Peek at the highest-priority task without removing it.
    pub fn peek(&self) -> Option<AgentTask> {
        let guard = self.tasks.lock();
        guard.first().cloned()
    }

    /// Number of pending tasks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tasks.lock().len()
    }

    /// Returns `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drain all tasks.
    pub fn drain(&self) -> Vec<AgentTask> {
        let mut guard = self.tasks.lock();
        std::mem::take(&mut *guard)
    }
}

impl Default for AgentTaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AgentMemory ─────────────────────────────────────────────────────────────

/// A single entry in agent long-term memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub key: String,
    pub value: serde_json::Value,
    pub timestamp: u64,
    pub tags: Vec<String>,
}

impl MemoryEntry {
    #[must_use]
    pub fn new(key: impl Into<String>, value: serde_json::Value) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            key: key.into(),
            value,
            timestamp,
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Long-term memory store for the agent, backed by an in-memory map.
/// In production this would persist to `SQLite` + `MySQL`.
pub struct AgentMemory {
    entries: ParkingRwLock<std::collections::HashMap<String, MemoryEntry>>,
    capacity: usize,
}

impl AgentMemory {
    /// Create a new memory store with a given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: ParkingRwLock::new(std::collections::HashMap::new()),
            capacity,
        }
    }

    /// Store or update a memory entry.
    pub fn store(&self, entry: MemoryEntry) {
        let mut guard = self.entries.write();
        if guard.len() >= self.capacity {
            // Evict oldest entry
            // `entries` is a HashMap and timestamps tie easily (coarse clock,
            // bursts of stores), so without a tie-break on the key the evicted
            // memory entry differs between runs on identical input.
            if let Some(oldest_key) = guard
                .values()
                .min_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.key.cmp(&b.key)))
                .map(|e| e.key.clone())
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(entry.key.clone(), entry);
    }

    /// Retrieve a memory entry by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<MemoryEntry> {
        self.entries.read().get(key).cloned()
    }

    /// Find entries with a matching tag.
    #[must_use]
    pub fn find_by_tag(&self, tag: &str) -> Vec<MemoryEntry> {
        self.entries
            .read()
            .values()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .cloned()
            .collect()
    }

    /// Remove an entry by key.
    pub fn remove(&self, key: &str) -> bool {
        self.entries.write().remove(key).is_some()
    }

    /// Total number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns `true` if the memory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── AgentObservation ────────────────────────────────────────────────────────

/// Kind of observation an agent can make about a binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationKind {
    FunctionBehavior,
    StringEvidence,
    SuspiciousPattern,
    CryptoUsage,
    NetworkActivity,
    FilesystemActivity,
    RegistryActivity,
    Anomaly,
    KnownSignature,
}

/// A single agent observation about the binary under analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentObservation {
    pub kind: ObservationKind,
    pub address: Option<u64>,
    pub description: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub timestamp: u64,
}

impl AgentObservation {
    #[must_use]
    pub fn new(kind: ObservationKind, description: impl Into<String>, confidence: f32) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            kind,
            address: None,
            description: description.into(),
            confidence: confidence.clamp(0.0, 1.0),
            evidence: Vec::new(),
            timestamp,
        }
    }

    #[must_use]
    pub const fn at_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    #[must_use]
    pub fn with_evidence(mut self, ev: Vec<String>) -> Self {
        self.evidence = ev;
        self
    }
}

// ─── AgentReasoning ──────────────────────────────────────────────────────────

/// A step in the agent's chain-of-thought reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    pub step_number: u32,
    pub thought: String,
    pub conclusion: Option<String>,
}

/// Chain-of-thought reasoning produced by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReasoning {
    pub task_id: u64,
    pub steps: Vec<ReasoningStep>,
    pub final_answer: String,
}

impl AgentReasoning {
    #[must_use]
    pub const fn new(task_id: u64) -> Self {
        Self {
            task_id,
            steps: Vec::new(),
            final_answer: String::new(),
        }
    }

    pub fn add_step(&mut self, thought: impl Into<String>, conclusion: Option<String>) {
        let n = crate::casts::usize_to_u32(self.steps.len()) + 1;
        self.steps.push(ReasoningStep {
            step_number: n,
            thought: thought.into(),
            conclusion,
        });
    }

    pub fn set_answer(&mut self, answer: impl Into<String>) {
        self.final_answer = answer.into();
    }

    #[must_use]
    pub const fn step_count(&self) -> usize {
        self.steps.len()
    }
}

// ─── AgentPlan ───────────────────────────────────────────────────────────────

/// A planned step in a multi-step analysis plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub index: u32,
    pub capability: ExtendedCapability,
    pub description: String,
    pub estimated_ms: u64,
    pub depends_on: Vec<u32>,
}

/// A multi-step analysis plan produced by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPlan {
    pub goal: String,
    pub steps: Vec<PlanStep>,
    pub estimated_total_ms: u64,
}

impl AgentPlan {
    #[must_use]
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            goal: goal.into(),
            steps: Vec::new(),
            estimated_total_ms: 0,
        }
    }

    pub fn add_step(&mut self, step: PlanStep) {
        self.estimated_total_ms += step.estimated_ms;
        self.steps.push(step);
    }

    #[must_use]
    pub const fn step_count(&self) -> usize {
        self.steps.len()
    }
}

// ─── AgentToolCall / AgentToolResult ─────────────────────────────────────────

/// A call to an RE analysis tool by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToolCall {
    pub call_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub issued_at: u64,
}

impl AgentToolCall {
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Self {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            call_id: call_id.into(),
            tool_name: tool_name.into(),
            arguments,
            issued_at,
        }
    }
}

/// Result returned from an RE tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToolResult {
    pub call_id: String,
    pub tool_name: String,
    pub output: serde_json::Value,
    pub success: bool,
    pub error: Option<String>,
    pub duration_ms: u64,
}

impl AgentToolResult {
    #[must_use]
    pub fn success(
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        output: serde_json::Value,
        duration_ms: u64,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            tool_name: tool_name.into(),
            output,
            success: true,
            error: None,
            duration_ms,
        }
    }

    #[must_use]
    pub fn failure(
        call_id: impl Into<String>,
        tool_name: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            tool_name: tool_name.into(),
            output: serde_json::Value::Null,
            success: false,
            error: Some(error.into()),
            duration_ms: 0,
        }
    }
}

// ─── AgentConversation ───────────────────────────────────────────────────────

/// A full dialogue history between user and agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConversation {
    pub session_id: String,
    pub messages: Vec<AgentMessage>,
    pub tool_calls: Vec<AgentToolCall>,
    pub tool_results: Vec<AgentToolResult>,
}

impl AgentConversation {
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            messages: Vec::new(),
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
        }
    }

    pub fn add_message(&mut self, role: MessageRole, content: impl Into<String>) {
        self.messages.push(AgentMessage::new(role, content));
    }

    pub fn add_tool_call(&mut self, call: AgentToolCall) {
        self.tool_calls.push(call);
    }

    pub fn add_tool_result(&mut self, result: AgentToolResult) {
        self.tool_results.push(result);
    }

    #[must_use]
    pub const fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Get all user messages.
    #[must_use]
    pub fn user_messages(&self) -> Vec<&AgentMessage> {
        self.messages
            .iter()
            .filter(|m| m.role == MessageRole::User)
            .collect()
    }

    /// Get all assistant messages.
    #[must_use]
    pub fn assistant_messages(&self) -> Vec<&AgentMessage> {
        self.messages
            .iter()
            .filter(|m| m.role == MessageRole::Assistant)
            .collect()
    }
}

// ─── AgentSession ────────────────────────────────────────────────────────────

/// Status of an agent session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Active,
    Paused,
    Completed,
    Failed(String),
}

/// A complete analysis session managed by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub session_id: String,
    pub binary_path: Option<std::path::PathBuf>,
    pub status: SessionStatus,
    pub conversation: AgentConversation,
    pub observations: Vec<AgentObservation>,
    pub reasoning_chains: Vec<AgentReasoning>,
    pub plans: Vec<AgentPlan>,
    pub created_at: u64,
    pub updated_at: u64,
    pub tags: Vec<String>,
}

impl AgentSession {
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let id = session_id.into();
        let conv = AgentConversation::new(id.clone());
        Self {
            session_id: id,
            binary_path: None,
            status: SessionStatus::Active,
            conversation: conv,
            observations: Vec::new(),
            reasoning_chains: Vec::new(),
            plans: Vec::new(),
            created_at: now,
            updated_at: now,
            tags: Vec::new(),
        }
    }

    pub fn add_observation(&mut self, obs: AgentObservation) {
        self.observations.push(obs);
        self.touch();
    }

    pub fn add_reasoning(&mut self, reasoning: AgentReasoning) {
        self.reasoning_chains.push(reasoning);
        self.touch();
    }

    pub fn add_plan(&mut self, plan: AgentPlan) {
        self.plans.push(plan);
        self.touch();
    }

    pub fn complete(&mut self) {
        self.status = SessionStatus::Completed;
        self.touch();
    }

    pub fn fail(&mut self, reason: impl Into<String>) {
        self.status = SessionStatus::Failed(reason.into());
        self.touch();
    }

    fn touch(&mut self) {
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == SessionStatus::Active
    }
}

// ─── AgentMetrics ────────────────────────────────────────────────────────────

/// Performance and accuracy metrics for an agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentMetrics {
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    pub total_duration_ms: u64,
    pub total_tokens_used: u64,
    pub accuracy_score: f64,
    pub tool_calls_made: u64,
    pub tool_calls_succeeded: u64,
    pub sessions_run: u64,
}

impl AgentMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn record_success(&mut self, duration_ms: u64, tokens: u64) {
        self.tasks_completed += 1;
        self.total_duration_ms += duration_ms;
        self.total_tokens_used += tokens;
    }

    pub const fn record_failure(&mut self) {
        self.tasks_failed += 1;
    }

    pub const fn record_tool_call(&mut self, success: bool) {
        self.tool_calls_made += 1;
        if success {
            self.tool_calls_succeeded += 1;
        }
    }

    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.tasks_completed + self.tasks_failed;
        if total == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.tasks_completed) / crate::casts::u64_to_f64(total)
    }

    #[must_use]
    pub fn avg_duration_ms(&self) -> f64 {
        if self.tasks_completed == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.total_duration_ms) / crate::casts::u64_to_f64(self.tasks_completed)
    }

    #[must_use]
    pub fn tool_success_rate(&self) -> f64 {
        if self.tool_calls_made == 0 {
            return 0.0;
        }
        crate::casts::u64_to_f64(self.tool_calls_succeeded) / crate::casts::u64_to_f64(self.tool_calls_made)
    }
}

// ─── AgentRateLimiter ─────────────────────────────────────────────────────────

/// Token-bucket rate limiter for API calls.
#[derive(Debug)]
pub struct AgentRateLimiter {
    capacity: u32,
    /// Combined state: (tokens, `last_refill_instant`) under a single lock to
    /// prevent TOCTOU races where two threads can observe the same stale
    /// `last_refill` and both apply the same refill amount.
    state: parking_lot::Mutex<(u32, std::time::Instant)>,
    refill_per_second: u32,
}

impl AgentRateLimiter {
    #[must_use]
    pub fn new(capacity: u32, refill_per_second: u32) -> Self {
        Self {
            capacity,
            state: parking_lot::Mutex::new((capacity, std::time::Instant::now())),
            refill_per_second,
        }
    }

    /// Try to consume `count` tokens. Returns `true` if allowed.
    pub fn try_acquire(&self, count: u32) -> bool {
        let now = std::time::Instant::now();
        let mut guard = self.state.lock();
        let (ref mut tokens, ref mut last_refill) = *guard;
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        let refill = crate::casts::f64_to_u32(elapsed * f64::from(self.refill_per_second));
        *tokens = (*tokens + refill).min(self.capacity);
        *last_refill = now;
        let result = if *tokens >= count {
            *tokens -= count;
            true
        } else {
            false
        };
        drop(guard);
        result
    }

    /// Available tokens right now.
    #[must_use]
    pub fn available(&self) -> u32 {
        self.state.lock().0
    }

    /// Reset tokens to full capacity.
    pub fn reset(&self) {
        self.state.lock().0 = self.capacity;
    }
}

// ─── AgentPromptGenerator ────────────────────────────────────────────────────

/// Generates structured prompts for LLM backends.
pub struct AgentPromptGenerator {
    system_prefix: String,
    max_context_chars: usize,
}

impl AgentPromptGenerator {
    #[must_use]
    pub fn new(system_prefix: impl Into<String>, max_context_chars: usize) -> Self {
        Self {
            system_prefix: system_prefix.into(),
            max_context_chars,
        }
    }

    /// Truncate `s` to at most `max_chars` bytes while respecting UTF-8 char
    /// boundaries. Slicing a `&str` by raw byte index panics when the index
    /// lands in the middle of a multibyte codepoint; this helper avoids that.
    fn safe_truncate<'a>(&self, s: &'a str) -> &'a str {
        let limit = self.max_context_chars;
        if s.len() <= limit {
            return s;
        }
        // Walk char boundaries to find the largest byte index <= limit.
        let safe_end = s
            .char_indices()
            .take_while(|&(i, _)| i < limit)
            .last()
            .map_or(0, |(i, c)| i + c.len_utf8());
        &s[..safe_end]
    }

    /// Generate a disassembly explanation prompt.
    #[must_use]
    pub fn disassembly_prompt(&self, disasm: &str, arch: &str) -> String {
        let truncated = self.safe_truncate(disasm);
        format!(
            "{}\n\nArchitecture: {arch}\n\nDisassembly:\n```\n{truncated}\n```\n\nExplain what this function does.",
            self.system_prefix
        )
    }

    /// Generate a vulnerability analysis prompt.
    #[must_use]
    pub fn vuln_analysis_prompt(&self, code: &str) -> String {
        let truncated = self.safe_truncate(code);
        format!(
            "{}\n\nAnalyze this code for security vulnerabilities:\n```\n{truncated}\n```",
            self.system_prefix
        )
    }

    /// Generate a rename suggestion prompt.
    #[must_use]
    pub fn rename_prompt(&self, code: &str) -> String {
        let truncated = self.safe_truncate(code);
        format!(
            "{}\n\nSuggest meaningful names for functions and variables:\n```\n{truncated}\n```",
            self.system_prefix
        )
    }

    /// Generate a YARA rule generation prompt.
    #[must_use]
    pub fn yara_prompt(&self, strings: &[String], imports: &[String]) -> String {
        format!(
            "{}\n\nGenerate YARA rules based on:\nStrings: {}\nImports: {}",
            self.system_prefix,
            strings.join(", "),
            imports.join(", ")
        )
    }

    /// Generate a malware analysis prompt.
    #[must_use]
    pub fn malware_prompt(&self, behavior: &str, iocs: &[String]) -> String {
        format!(
            "{}\n\nAnalyze this malware behavior:\n{behavior}\n\nKnown IOCs: {}",
            self.system_prefix,
            iocs.join(", ")
        )
    }
}

// ─── AgentResponseParser ─────────────────────────────────────────────────────

/// Parses structured outputs from LLM responses.
pub struct AgentResponseParser;

impl AgentResponseParser {
    /// Extract a JSON object from an LLM response that may contain freeform text.
    /// # Errors
    /// Returns `AgentError::ParseError` if no valid JSON can be located.
    pub fn extract_json(response: &str) -> Result<serde_json::Value, AgentError> {
        // Try direct parse first
        if let Ok(v) = serde_json::from_str(response) {
            return Ok(v);
        }
        // Try to find JSON block within markdown code fences
        if let Some(start) = response.find("```json") {
            let rest = &response[start + 7..];
            if let Some(end) = rest.find("```") {
                let json_str = &rest[..end].trim();
                return serde_json::from_str(json_str)
                    .map_err(|e| AgentError::ParseError(e.to_string()));
            }
        }
        // Try to find bare JSON object
        if let Some(start) = response.find('{')
            && let Some(end) = response.rfind('}') {
                let json_str = &response[start..=end];
                if let Ok(v) = serde_json::from_str(json_str) {
                    return Ok(v);
                }
            }
        Err(AgentError::ParseError(
            "no JSON found in response".to_string(),
        ))
    }

    /// Extract a list of rename suggestions from a JSON response.
    /// # Errors
    /// Returns `AgentError::ParseError` if the JSON cannot be parsed as an object.
    pub fn parse_renames(
        response: &str,
    ) -> Result<std::collections::HashMap<String, String>, AgentError> {
        let v = Self::extract_json(response)?;
        let obj = v
            .as_object()
            .ok_or_else(|| AgentError::ParseError("expected JSON object".into()))?;
        let mut map = std::collections::HashMap::new();
        for (k, val) in obj {
            if let Some(s) = val.as_str() {
                map.insert(k.clone(), s.to_string());
            }
        }
        Ok(map)
    }

    /// Extract vulnerability findings from a structured response.
    #[must_use] 
    pub fn parse_vulnerabilities(response: &str) -> Vec<String> {
        response
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with('-') || trimmed.starts_with('*') || trimmed.starts_with('•')
                {
                    Some(trimmed.trim_start_matches(['-', '*', '•', ' ']).to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract confidence score from response (0.0..1.0).
    #[must_use]
    pub fn parse_confidence(response: &str) -> f32 {
        // Look for patterns like "confidence: 0.85" or "85%"
        for word in response.split_whitespace() {
            let w = word.trim_end_matches('%').trim_end_matches(',');
            if let Ok(pct) = w.parse::<f32>() {
                if pct > 1.0 && pct <= 100.0 {
                    return (pct / 100.0).clamp(0.0, 1.0);
                }
                if (0.0..=1.0).contains(&pct) {
                    return pct;
                }
            }
        }
        0.5
    }
}

// ─── AgentSelfImprovement ────────────────────────────────────────────────────

/// Tracks agent feedback for continuous improvement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub task_id: u64,
    pub response: String,
    pub rating: i8,
    pub comment: String,
    pub timestamp: u64,
}

/// Self-improvement system that learns from user feedback.
pub struct AgentSelfImprovement {
    feedback: parking_lot::Mutex<Vec<FeedbackEntry>>,
}

impl AgentSelfImprovement {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            feedback: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Record feedback for a task response.
    pub fn record_feedback(
        &self,
        task_id: u64,
        response: impl Into<String>,
        rating: i8,
        comment: impl Into<String>,
    ) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.feedback.lock().push(FeedbackEntry {
            task_id,
            response: response.into(),
            rating: rating.clamp(-5, 5),
            comment: comment.into(),
            timestamp,
        });
    }

    /// Average rating across all feedback entries.
    #[must_use]
    pub fn average_rating(&self) -> f64 {
        let guard = self.feedback.lock();
        if guard.is_empty() {
            return 0.0;
        }
        let sum: i64 = guard.iter().map(|e| i64::from(e.rating)).sum();
        crate::casts::i64_to_f64(sum) / crate::casts::usize_to_f64(guard.len())
    }

    /// Total feedback count.
    #[must_use]
    pub fn feedback_count(&self) -> usize {
        self.feedback.lock().len()
    }

    /// Get all feedback with positive ratings.
    #[must_use]
    pub fn positive_feedback(&self) -> Vec<FeedbackEntry> {
        self.feedback
            .lock()
            .iter()
            .filter(|e| e.rating > 0)
            .cloned()
            .collect()
    }

    /// Get all feedback with negative ratings.
    #[must_use]
    pub fn negative_feedback(&self) -> Vec<FeedbackEntry> {
        self.feedback
            .lock()
            .iter()
            .filter(|e| e.rating < 0)
            .cloned()
            .collect()
    }
}

impl Default for AgentSelfImprovement {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AgentPlugin ─────────────────────────────────────────────────────────────

/// Trait for extensible agent behavior plugins.
pub trait AgentPlugin: Send + Sync {
    fn plugin_name(&self) -> &str;
    fn plugin_version(&self) -> &str;
    fn supports_capability(&self, cap: &ExtendedCapability) -> bool;
    /// # Errors
    /// Returns an `AgentError` if the plugin's execution fails.
    fn execute(&self, task: &AgentTask, ctx: &AgentContext) -> Result<AgentOutput, AgentError>;
}

/// Registry of loaded agent plugins.
pub struct AgentPluginRegistry {
    plugins: ParkingRwLock<Vec<Arc<dyn AgentPlugin>>>,
}

impl AgentPluginRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            plugins: ParkingRwLock::new(Vec::new()),
        }
    }

    pub fn register(&self, plugin: Arc<dyn AgentPlugin>) {
        self.plugins.write().push(plugin);
    }

    #[must_use]
    pub fn find_for_capability(&self, cap: &ExtendedCapability) -> Option<Arc<dyn AgentPlugin>> {
        self.plugins
            .read()
            .iter()
            .find(|p| p.supports_capability(cap))
            .cloned()
    }

    #[must_use]
    pub fn plugin_count(&self) -> usize {
        self.plugins.read().len()
    }

    #[must_use]
    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins
            .read()
            .iter()
            .map(|p| p.plugin_name().to_string())
            .collect()
    }
}

impl Default for AgentPluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DisasmAgent ──────────────────────────────────────────────────────────────

/// A concrete disassembly agent.
///
/// In `process()` it builds an [`AgentToolCall`] for an MCP `disassemble`
/// tool, then synthesises a disassembly report from the context that was
/// passed in with the input.  No live disassembly engine is required — the
/// tool-call pattern records *what* would be invoked so that an MCP host can
/// execute it.
pub struct DisasmAgent {
    config: Option<AgentConfig>,
}

impl DisasmAgent {
    /// Create a new `DisasmAgent`.
    #[must_use]
    pub const fn new() -> Self {
        Self { config: None }
    }
}

impl Default for DisasmAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Agent for DisasmAgent {
    fn name(&self) -> &'static str {
        "disasm-agent"
    }

    fn description(&self) -> &'static str {
        "Disassembly agent — emits an MCP tool-call for disassembly and \
         returns a structured disassembly report."
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        vec![AgentCapability::Disassembly]
    }

    async fn process(
        &self,
        input: AgentInput,
        ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError> {
        // Derive the binary path from context or from the task string.
        let binary_path = ctx
            .binary_path
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| {
                // Fallback: treat the task string itself as a path hint.
                let t = input.task.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(t.to_string())
                }
            })
            .unwrap_or_else(|| "<unknown>".to_string());

        let arch = if ctx.architecture.is_empty() {
            "x86_64"
        } else {
            &ctx.architecture
        };

        // Build an MCP-style tool-call descriptor (not executed here —
        // returned for the host to dispatch).
        let call = AgentToolCall::new(
            "disasm-1",
            "mcp__ghidra__disassemble_function",
            serde_json::json!({
                "binary_path": binary_path,
                "architecture": arch,
                "task": input.task,
            }),
        );

        // Pull any pre-supplied disassembly from the input context.
        let disasm_snippet = input
            .context
            .get("disassembly")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let result = if disasm_snippet.is_empty() {
            format!(
                "[disasm-agent] MCP tool call issued: {} → binary='{}' arch='{}'.\n\
                 Awaiting host execution of mcp__ghidra__disassemble_function.",
                call.call_id, binary_path, arch
            )
        } else {
            format!(
                "[disasm-agent] Disassembly for '{binary_path}' (arch={arch}):\n{disasm_snippet}"
            )
        };

        let artifact = Artifact::text(
            "disasm-tool-call.json",
            ArtifactType::Report,
            serde_json::to_string_pretty(&call.arguments).unwrap_or_else(|_| "{}".to_string()),
        );

        Ok(AgentOutput {
            result,
            actions: Vec::new(),
            artifacts: vec![artifact],
            confidence: 0.85,
            next_steps: vec![
                "Run mcp__ghidra__disassemble_function with the provided arguments.".to_string(),
                "Pass the disassembly output back as context['disassembly'] for explanation."
                    .to_string(),
            ],
        })
    }

    async fn initialize(&mut self, config: &AgentConfig) -> Result<(), AgentError> {
        self.config = Some(config.clone());
        Ok(())
    }
}

// ─── VulnAgent ────────────────────────────────────────────────────────────────

/// A concrete vulnerability-detection agent.
///
/// `process()` pattern-matches the task string and any `decompiled_code`
/// context value against a catalogue of common vulnerability patterns
/// (buffer overflows, format-string bugs, use-after-free, integer overflows,
/// insecure API calls).  Each match produces an [`AgentAction::AddComment`]
/// at a placeholder address so callers can apply the findings to a binary.
pub struct VulnAgent {
    config: Option<AgentConfig>,
}

impl VulnAgent {
    /// Create a new `VulnAgent`.
    #[must_use]
    pub const fn new() -> Self {
        Self { config: None }
    }
}

impl Default for VulnAgent {
    fn default() -> Self {
        Self::new()
    }
}

/// A single vulnerability pattern.
struct VulnPattern {
    /// Substring to look for (case-insensitive).
    needle: &'static str,
    /// Short CWE-style label.
    label: &'static str,
    /// Confidence for this pattern.
    confidence: f32,
}

const VULN_PATTERNS: &[VulnPattern] = &[
    VulnPattern {
        needle: "gets(",
        label: "CWE-120: unbounded gets() — buffer overflow risk",
        confidence: 0.95,
    },
    VulnPattern {
        needle: "strcpy(",
        label: "CWE-120: unbounded strcpy() — buffer overflow risk",
        confidence: 0.90,
    },
    VulnPattern {
        needle: "strcat(",
        label: "CWE-120: unbounded strcat() — buffer overflow risk",
        confidence: 0.90,
    },
    VulnPattern {
        needle: "sprintf(",
        label: "CWE-120: unbounded sprintf() — buffer overflow risk",
        confidence: 0.85,
    },
    VulnPattern {
        needle: "scanf(",
        label: "CWE-120: unbounded scanf() — buffer overflow risk",
        confidence: 0.80,
    },
    VulnPattern {
        needle: "printf(",
        label: "CWE-134: user-controlled printf format string",
        confidence: 0.70,
    },
    VulnPattern {
        needle: "free(",
        label: "CWE-416: potential use-after-free near free()",
        confidence: 0.60,
    },
    VulnPattern {
        needle: "malloc(",
        label: "CWE-476: unchecked malloc() return value",
        confidence: 0.55,
    },
    VulnPattern {
        needle: "overflow",
        label: "CWE-190: possible integer overflow",
        confidence: 0.65,
    },
    VulnPattern {
        needle: "system(",
        label: "CWE-78: OS command injection via system()",
        confidence: 0.90,
    },
    VulnPattern {
        needle: "exec(",
        label: "CWE-78: OS command injection via exec*()",
        confidence: 0.85,
    },
    VulnPattern {
        needle: "popen(",
        label: "CWE-78: OS command injection via popen()",
        confidence: 0.85,
    },
    VulnPattern {
        needle: "memcpy(",
        label: "CWE-120: memcpy() without bounds check",
        confidence: 0.65,
    },
    VulnPattern {
        needle: "memmove(",
        label: "CWE-120: memmove() without bounds check",
        confidence: 0.60,
    },
    VulnPattern {
        needle: "alloca(",
        label: "CWE-770: stack allocation via alloca() — stack exhaustion risk",
        confidence: 0.70,
    },
];

#[async_trait]
impl Agent for VulnAgent {
    fn name(&self) -> &'static str {
        "vuln-agent"
    }

    fn description(&self) -> &'static str {
        "Vulnerability-detection agent — pattern-matches decompiled code and \
         task input against a catalogue of common CWE patterns."
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        vec![
            AgentCapability::VulnerabilityDetection,
            AgentCapability::PatternMatching,
        ]
    }

    async fn process(
        &self,
        input: AgentInput,
        _ctx: &AgentContext,
    ) -> Result<AgentOutput, AgentError> {
        // Collect the text corpus to scan.
        let code_ctx = input
            .context
            .get("decompiled_code")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let corpus = format!("{}\n{}", input.task, code_ctx).to_lowercase();

        let mut findings: Vec<String> = Vec::new();
        let mut actions: Vec<AgentAction> = Vec::new();
        let mut max_confidence: f32 = 0.0;

        for pat in VULN_PATTERNS {
            if corpus.contains(pat.needle) {
                findings.push(pat.label.to_string());
                // Emit an AddComment action at address 0 (placeholder —
                // a real integration would resolve the actual address).
                actions.push(AgentAction::AddComment {
                    addr: 0,
                    comment: format!("[vuln-agent] {}", pat.label),
                });
                if pat.confidence > max_confidence {
                    max_confidence = pat.confidence;
                }
            }
        }

        let (result, confidence) = if findings.is_empty() {
            (
                "[vuln-agent] No common vulnerability patterns detected in the provided input."
                    .to_string(),
                0.5,
            )
        } else {
            let summary = format!(
                "[vuln-agent] {} potential vulnerability pattern(s) detected:\n{}",
                findings.len(),
                findings
                    .iter()
                    .map(|f| format!("  - {f}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            (summary, max_confidence)
        };

        let report_content = findings.join("\n");
        let artifact = Artifact::text("vuln-report.txt", ArtifactType::Report, report_content);

        Ok(AgentOutput {
            result,
            actions,
            artifacts: vec![artifact],
            confidence,
            next_steps: if findings.is_empty() {
                vec![
                    "Consider providing decompiled_code in the input context for deeper analysis."
                        .to_string(),
                ]
            } else {
                vec![
                    "Review each flagged call site in the binary.".to_string(),
                    "Use disasm-agent to obtain precise addresses for the findings.".to_string(),
                ]
            },
        })
    }

    async fn initialize(&mut self, config: &AgentConfig) -> Result<(), AgentError> {
        self.config = Some(config.clone());
        Ok(())
    }
}

// ─── builtin_workflows ────────────────────────────────────────────────────────

/// Return a list of (agent, config) pairs for all built-in RE workflow agents.
///
/// Built-in agents:
/// * `"disasm-agent"` — [`DisasmAgent`] (capability: [`AgentCapability::Disassembly`])
/// * `"vuln-agent"`   — [`VulnAgent`]   (capabilities: [`AgentCapability::VulnerabilityDetection`],
///   [`AgentCapability::PatternMatching`])
///
/// Pass the returned pairs to [`AgentOrchestrator::register`] to make them
/// available for routing.
#[must_use]
pub fn builtin_workflows() -> Vec<(Box<dyn Agent>, AgentConfig)> {
    let config = AgentConfig::default();
    vec![
        (
            Box::new(DisasmAgent::new()) as Box<dyn Agent>,
            config.clone(),
        ),
        (Box::new(VulnAgent::new()) as Box<dyn Agent>, config),
    ]
}

// ─── Extended tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── ExtendedCapability ───────────────────────────────────────────────────
    #[test]
    fn test_extended_capability_display() {
        assert_eq!(ExtendedCapability::Disassemble.to_string(), "Disassemble");
        assert_eq!(ExtendedCapability::FindVulns.to_string(), "FindVulns");
        assert_eq!(
            ExtendedCapability::CorrelateThreats.to_string(),
            "CorrelateThreats"
        );
    }

    // ── AgentTask ────────────────────────────────────────────────────────────
    #[test]
    fn test_agent_task_new() {
        let t = AgentTask::new(
            1,
            "analyze main",
            ExtendedCapability::Analyze,
            TaskPriority::High,
            serde_json::json!({}),
        );
        assert_eq!(t.id, 1);
        assert_eq!(t.priority, TaskPriority::High);
        assert!(!t.is_expired());
    }

    #[test]
    fn test_agent_task_with_deadline_not_expired() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
            + 60_000;
        let t = AgentTask::new(
            1,
            "task",
            ExtendedCapability::Analyze,
            TaskPriority::Normal,
            serde_json::json!({}),
        )
        .with_deadline(future);
        assert!(!t.is_expired());
    }

    #[test]
    fn test_agent_task_expired() {
        let past = 1000u64; // far in the past
        let t = AgentTask::new(
            1,
            "old",
            ExtendedCapability::Analyze,
            TaskPriority::Low,
            serde_json::json!({}),
        )
        .with_deadline(past);
        assert!(t.is_expired());
    }

    #[test]
    fn test_task_priority_ordering() {
        assert!(TaskPriority::Critical > TaskPriority::High);
        assert!(TaskPriority::High > TaskPriority::Normal);
        assert!(TaskPriority::Normal > TaskPriority::Low);
    }

    // ── AgentTaskQueue ───────────────────────────────────────────────────────
    #[test]
    fn test_task_queue_push_pop() {
        let q = AgentTaskQueue::new();
        q.push(AgentTask::new(
            1,
            "low",
            ExtendedCapability::Analyze,
            TaskPriority::Low,
            serde_json::json!({}),
        ));
        q.push(AgentTask::new(
            2,
            "high",
            ExtendedCapability::Analyze,
            TaskPriority::High,
            serde_json::json!({}),
        ));
        assert_eq!(q.len(), 2);
        let top = q.pop().unwrap();
        assert_eq!(top.priority, TaskPriority::High);
    }

    #[test]
    fn test_task_queue_empty_pop() {
        let q = AgentTaskQueue::new();
        assert!(q.pop().is_none());
        assert!(q.is_empty());
    }

    #[test]
    fn test_task_queue_drain() {
        let q = AgentTaskQueue::new();
        for i in 0..5 {
            q.push(AgentTask::new(
                i,
                "t",
                ExtendedCapability::Analyze,
                TaskPriority::Normal,
                serde_json::json!({}),
            ));
        }
        let drained = q.drain();
        assert_eq!(drained.len(), 5);
        assert!(q.is_empty());
    }

    #[test]
    fn test_task_queue_peek() {
        let q = AgentTaskQueue::new();
        q.push(AgentTask::new(
            1,
            "t",
            ExtendedCapability::Analyze,
            TaskPriority::Critical,
            serde_json::json!({}),
        ));
        let peeked = q.peek().unwrap();
        assert_eq!(peeked.priority, TaskPriority::Critical);
        assert_eq!(q.len(), 1); // peek doesn't remove
    }

    // ── AgentMemory ──────────────────────────────────────────────────────────
    #[test]
    fn test_agent_memory_store_get() {
        let mem = AgentMemory::new(100);
        mem.store(MemoryEntry::new("key1", serde_json::json!("value1")));
        let entry = mem.get("key1").unwrap();
        assert_eq!(entry.value, serde_json::json!("value1"));
    }

    #[test]
    fn test_agent_memory_get_missing() {
        let mem = AgentMemory::new(100);
        assert!(mem.get("nonexistent").is_none());
    }

    #[test]
    fn test_agent_memory_remove() {
        let mem = AgentMemory::new(100);
        mem.store(MemoryEntry::new("k", serde_json::json!(1)));
        assert!(mem.remove("k"));
        assert!(!mem.remove("k"));
    }

    #[test]
    fn test_agent_memory_find_by_tag() {
        let mem = AgentMemory::new(100);
        let entry =
            MemoryEntry::new("k", serde_json::json!(1)).with_tags(vec!["malware".to_string()]);
        mem.store(entry);
        let found = mem.find_by_tag("malware");
        assert_eq!(found.len(), 1);
        let not_found = mem.find_by_tag("benign");
        assert_eq!(not_found.len(), 0);
    }

    #[test]
    fn test_agent_memory_capacity_eviction() {
        let mem = AgentMemory::new(2);
        for i in 0u64..3 {
            std::thread::sleep(std::time::Duration::from_millis(1)); // ensure different timestamps
            mem.store(MemoryEntry::new(format!("k{i}"), serde_json::json!(i)));
        }
        assert_eq!(mem.len(), 2); // evicted one
    }

    // ── AgentObservation ─────────────────────────────────────────────────────
    #[test]
    fn test_observation_new() {
        let obs = AgentObservation::new(ObservationKind::SuspiciousPattern, "found loop", 0.9);
        assert!((obs.confidence - 0.9).abs() < 1e-9);
        assert!(obs.address.is_none());
    }

    #[test]
    fn test_observation_at_address() {
        let obs = AgentObservation::new(ObservationKind::CryptoUsage, "AES detected", 0.8)
            .at_address(0x1000);
        assert_eq!(obs.address, Some(0x1000));
    }

    #[test]
    fn test_observation_clamps_confidence() {
        let obs = AgentObservation::new(ObservationKind::Anomaly, "test", 1.5);
        assert!((obs.confidence - 1.0).abs() < 1e-9);
        let obs2 = AgentObservation::new(ObservationKind::Anomaly, "test", -0.5);
        assert!(obs2.confidence.abs() < 1e-9);
    }

    // ── AgentReasoning ───────────────────────────────────────────────────────
    #[test]
    fn test_reasoning_add_steps() {
        let mut r = AgentReasoning::new(42);
        r.add_step("This looks like encryption", Some("AES-128".to_string()));
        r.add_step("Key schedule detected", None);
        assert_eq!(r.step_count(), 2);
        assert_eq!(r.steps[0].step_number, 1);
        assert_eq!(r.steps[1].step_number, 2);
    }

    #[test]
    fn test_reasoning_set_answer() {
        let mut r = AgentReasoning::new(1);
        r.set_answer("This is AES-128 encryption");
        assert_eq!(r.final_answer, "This is AES-128 encryption");
    }

    // ── AgentPlan ────────────────────────────────────────────────────────────
    #[test]
    fn test_agent_plan_add_step() {
        let mut plan = AgentPlan::new("analyze binary");
        plan.add_step(PlanStep {
            index: 0,
            capability: ExtendedCapability::Disassemble,
            description: "Disassemble all functions".to_string(),
            estimated_ms: 1000,
            depends_on: vec![],
        });
        assert_eq!(plan.step_count(), 1);
        assert_eq!(plan.estimated_total_ms, 1000);
    }

    // ── AgentToolCall / Result ────────────────────────────────────────────────
    #[test]
    fn test_tool_call_new() {
        let call = AgentToolCall::new("c1", "disassemble", serde_json::json!({"addr": 0x1000}));
        assert_eq!(call.call_id, "c1");
        assert_eq!(call.tool_name, "disassemble");
    }

    #[test]
    fn test_tool_result_success() {
        let r = AgentToolResult::success(
            "c1",
            "disasm",
            serde_json::json!({"output": "push rbp"}),
            50,
        );
        assert!(r.success);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_tool_result_failure() {
        let r = AgentToolResult::failure("c2", "decompile", "timeout");
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    // ── AgentConversation ────────────────────────────────────────────────────
    #[test]
    fn test_conversation_add_messages() {
        let mut conv = AgentConversation::new("sess-1");
        conv.add_message(MessageRole::User, "analyze this function");
        conv.add_message(MessageRole::Assistant, "this is a sorting algorithm");
        assert_eq!(conv.message_count(), 2);
        assert_eq!(conv.user_messages().len(), 1);
        assert_eq!(conv.assistant_messages().len(), 1);
    }

    // ── AgentSession ─────────────────────────────────────────────────────────
    #[test]
    fn test_session_new() {
        let s = AgentSession::new("s1");
        assert_eq!(s.session_id, "s1");
        assert!(s.is_active());
        assert!(s.observations.is_empty());
    }

    #[test]
    fn test_session_complete() {
        let mut s = AgentSession::new("s2");
        s.complete();
        assert_eq!(s.status, SessionStatus::Completed);
        assert!(!s.is_active());
    }

    #[test]
    fn test_session_fail() {
        let mut s = AgentSession::new("s3");
        s.fail("network error");
        assert!(matches!(s.status, SessionStatus::Failed(_)));
    }

    // ── AgentMetrics ──────────────────────────────────────────────────────────
    #[test]
    fn test_metrics_success_rate() {
        let mut m = AgentMetrics::new();
        m.record_success(100, 500);
        m.record_success(200, 800);
        m.record_failure();
        assert!((m.success_rate() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_metrics_avg_duration() {
        let mut m = AgentMetrics::new();
        m.record_success(100, 0);
        m.record_success(300, 0);
        assert!((m.avg_duration_ms() - 200.0).abs() < 1e-10);
    }

    #[test]
    fn test_metrics_tool_success_rate() {
        let mut m = AgentMetrics::new();
        m.record_tool_call(true);
        m.record_tool_call(true);
        m.record_tool_call(false);
        assert!((m.tool_success_rate() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_metrics_zero_success_rate() {
        let m = AgentMetrics::new();
        assert!(m.success_rate().abs() < 1e-9);
        assert!(m.avg_duration_ms().abs() < 1e-9);
        assert!(m.tool_success_rate().abs() < 1e-9);
    }

    // ── AgentRateLimiter ──────────────────────────────────────────────────────
    #[test]
    fn test_rate_limiter_basic() {
        let rl = AgentRateLimiter::new(10, 1);
        assert!(rl.try_acquire(5));
        assert_eq!(rl.available(), 5);
        assert!(rl.try_acquire(5));
        assert!(!rl.try_acquire(1)); // exhausted
    }

    #[test]
    fn test_rate_limiter_reset() {
        let rl = AgentRateLimiter::new(10, 1);
        rl.try_acquire(10);
        rl.reset();
        assert_eq!(rl.available(), 10);
    }

    // ── AgentPromptGenerator ──────────────────────────────────────────────────
    #[test]
    fn test_prompt_generator_disassembly() {
        let prompt_gen = AgentPromptGenerator::new("You are an RE expert.", 1000);
        let p = prompt_gen.disassembly_prompt("push rbp\nmov rbp, rsp", "x86_64");
        assert!(p.contains("x86_64"));
        assert!(p.contains("push rbp"));
    }

    #[test]
    fn test_prompt_generator_vuln() {
        let prompt_gen = AgentPromptGenerator::new("sys", 1000);
        let p = prompt_gen.vuln_analysis_prompt("gets(buf);");
        assert!(p.contains("gets(buf)"));
    }

    #[test]
    fn test_prompt_generator_yara() {
        let prompt_gen = AgentPromptGenerator::new("sys", 1000);
        let p = prompt_gen.yara_prompt(&["malware.exe".to_string()], &["WinExec".to_string()]);
        assert!(p.contains("malware.exe"));
        assert!(p.contains("WinExec"));
    }

    // ── AgentResponseParser ───────────────────────────────────────────────────
    #[test]
    fn test_parse_json_direct() {
        let json = r#"{"key": "value"}"#;
        let v = AgentResponseParser::extract_json(json).unwrap();
        assert_eq!(v["key"], "value");
    }

    #[test]
    fn test_parse_json_from_code_fence() {
        let response = "Here is the result:\n```json\n{\"a\": 1}\n```\n";
        let v = AgentResponseParser::extract_json(response).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn test_parse_json_from_mixed_text() {
        let response = "The answer is {\"x\": true} as shown above.";
        let v = AgentResponseParser::extract_json(response).unwrap();
        assert_eq!(v["x"], true);
    }

    #[test]
    fn test_parse_renames() {
        let json = r#"{"v1": "buffer_size", "v2": "file_handle"}"#;
        let renames = AgentResponseParser::parse_renames(json).unwrap();
        assert_eq!(renames["v1"], "buffer_size");
        assert_eq!(renames["v2"], "file_handle");
    }

    #[test]
    fn test_parse_vulnerabilities() {
        let response = "Found issues:\n- Buffer overflow at 0x1000\n* Use-after-free at 0x2000\n";
        let findings = AgentResponseParser::parse_vulnerabilities(response);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_parse_confidence_percent() {
        let c = AgentResponseParser::parse_confidence("confidence: 87%");
        assert!((c - 0.87).abs() < 0.01);
    }

    // ── AgentSelfImprovement ──────────────────────────────────────────────────
    #[test]
    fn test_self_improvement_feedback() {
        let si = AgentSelfImprovement::new();
        si.record_feedback(1, "response", 3, "great");
        si.record_feedback(2, "response", -2, "wrong");
        assert_eq!(si.feedback_count(), 2);
        let avg = si.average_rating();
        assert!((avg - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_self_improvement_positive_negative() {
        let si = AgentSelfImprovement::new();
        si.record_feedback(1, "r1", 2, "");
        si.record_feedback(2, "r2", -1, "");
        si.record_feedback(3, "r3", 3, "");
        assert_eq!(si.positive_feedback().len(), 2);
        assert_eq!(si.negative_feedback().len(), 1);
    }

    // ── AgentPluginRegistry ───────────────────────────────────────────────────
    #[test]
    fn test_plugin_registry_empty() {
        let reg = AgentPluginRegistry::new();
        assert_eq!(reg.plugin_count(), 0);
        assert!(
            reg.find_for_capability(&ExtendedCapability::Analyze)
                .is_none()
        );
    }
}

// ─── DisasmAgent / VulnAgent tests ───────────────────────────────────────────

#[cfg(test)]
mod concrete_agent_tests {
    use super::*;

    fn make_context() -> AgentContext {
        AgentContext::new(Some(PathBuf::from("/bin/target")), "x86_64", "linux")
    }

    fn make_config() -> AgentConfig {
        AgentConfig {
            model: "test-model".to_string(),
            api_key: "sk-test".to_string(),
            base_url: "http://localhost".to_string(),
            max_tokens: 512,
            temperature: 0.0,
            timeout_ms: 5_000,
        }
    }

    // ── DisasmAgent ──────────────────────────────────────────────────────────

    #[test]
    fn test_disasm_agent_name() {
        let agent = DisasmAgent::new();
        assert_eq!(agent.name(), "disasm-agent");
    }

    #[test]
    fn test_disasm_agent_capabilities() {
        let agent = DisasmAgent::new();
        assert!(agent.capabilities().contains(&AgentCapability::Disassembly));
    }

    #[tokio::test]
    async fn test_disasm_agent_process_no_context() {
        let agent = DisasmAgent::new();
        let input = AgentInput::simple("disassemble main function");
        let ctx = make_context();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(out.result.contains("disasm-agent"));
        assert!(!out.artifacts.is_empty());
        assert!((out.confidence - 0.85).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_disasm_agent_process_with_disassembly_context() {
        let agent = DisasmAgent::new();
        let input = AgentInput::simple("explain function").with_context(
            "disassembly",
            serde_json::json!("push rbp\nmov rbp, rsp\nret"),
        );
        let ctx = make_context();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(out.result.contains("push rbp"));
    }

    #[tokio::test]
    async fn test_disasm_agent_initialize() {
        let mut agent = DisasmAgent::new();
        let cfg = make_config();
        agent.initialize(&cfg).await.unwrap();
        assert!(agent.config.is_some());
    }

    #[tokio::test]
    async fn test_disasm_agent_next_steps_non_empty() {
        let agent = DisasmAgent::new();
        let input = AgentInput::simple("disasm");
        let ctx = make_context();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(!out.next_steps.is_empty());
    }

    // ── VulnAgent ────────────────────────────────────────────────────────────

    #[test]
    fn test_vuln_agent_name() {
        let agent = VulnAgent::new();
        assert_eq!(agent.name(), "vuln-agent");
    }

    #[test]
    fn test_vuln_agent_capabilities() {
        let agent = VulnAgent::new();
        let caps = agent.capabilities();
        assert!(caps.contains(&AgentCapability::VulnerabilityDetection));
        assert!(caps.contains(&AgentCapability::PatternMatching));
    }

    #[tokio::test]
    async fn test_vuln_agent_no_findings() {
        let agent = VulnAgent::new();
        let input = AgentInput::simple("check function foo");
        let ctx = AgentContext::default();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(out.result.contains("No common vulnerability"));
        assert!(out.actions.is_empty());
    }

    #[tokio::test]
    async fn test_vuln_agent_detects_gets() {
        let agent = VulnAgent::new();
        let input = AgentInput::simple("analyze").with_context(
            "decompiled_code",
            serde_json::json!("char buf[64]; gets(buf);"),
        );
        let ctx = AgentContext::default();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(!out.actions.is_empty());
        assert!(out.result.contains("CWE-120"));
        assert!(out.confidence > 0.5);
    }

    #[tokio::test]
    async fn test_vuln_agent_detects_system() {
        let agent = VulnAgent::new();
        let input = AgentInput::simple("system(user_input)");
        let ctx = AgentContext::default();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(out.result.contains("CWE-78"));
    }

    #[tokio::test]
    async fn test_vuln_agent_multiple_patterns() {
        let agent = VulnAgent::new();
        let input = AgentInput::simple("analyze").with_context(
            "decompiled_code",
            serde_json::json!("gets(buf); strcpy(dst, src); system(cmd);"),
        );
        let ctx = AgentContext::default();
        let out = agent.process(input, &ctx).await.unwrap();
        // Should detect at least gets, strcpy, and system.
        assert!(out.actions.len() >= 3);
    }

    #[tokio::test]
    async fn test_vuln_agent_initialize() {
        let mut agent = VulnAgent::new();
        let cfg = make_config();
        agent.initialize(&cfg).await.unwrap();
        assert!(agent.config.is_some());
    }

    #[tokio::test]
    async fn test_vuln_agent_artifact_present() {
        let agent = VulnAgent::new();
        let input = AgentInput::simple("check")
            .with_context("decompiled_code", serde_json::json!("malloc(n)"));
        let ctx = AgentContext::default();
        let out = agent.process(input, &ctx).await.unwrap();
        assert!(!out.artifacts.is_empty());
    }

    // ── builtin_workflows ────────────────────────────────────────────────────

    #[test]
    fn test_builtin_workflows_count() {
        let workflows = builtin_workflows();
        assert_eq!(workflows.len(), 2);
    }

    #[test]
    fn test_builtin_workflows_names() {
        let workflows = builtin_workflows();
        let names: Vec<&str> = workflows.iter().map(|(a, _)| a.name()).collect();
        assert!(names.contains(&"disasm-agent"));
        assert!(names.contains(&"vuln-agent"));
    }

    #[tokio::test]
    async fn test_builtin_workflows_register_in_orchestrator() {
        let orch = AgentOrchestrator::new();
        for (agent, config) in builtin_workflows() {
            orch.register(agent, config).await.unwrap();
        }
        assert_eq!(orch.len(), 2);
        assert!(
            orch.find_by_capability(&AgentCapability::Disassembly)
                .is_some()
        );
        assert!(
            orch.find_by_capability(&AgentCapability::VulnerabilityDetection)
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_register_builtin_workflows_helper() {
        let orch = AgentOrchestrator::new();
        orch.register_builtin_workflows().await.unwrap();
        assert_eq!(orch.len(), 2);
        assert!(
            orch.find_by_capability(&AgentCapability::Disassembly)
                .is_some()
        );
        assert!(
            orch.find_by_capability(&AgentCapability::VulnerabilityDetection)
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_orchestrator_route_to_disasm_agent() {
        let orch = AgentOrchestrator::new();
        for (agent, config) in builtin_workflows() {
            orch.register(agent, config).await.unwrap();
        }
        let out = orch
            .route(
                &[AgentCapability::Disassembly],
                AgentInput::simple("disassemble _start"),
                &make_context(),
            )
            .await
            .unwrap();
        assert!(out.result.contains("disasm-agent"));
    }

    #[tokio::test]
    async fn test_orchestrator_route_to_vuln_agent() {
        let orch = AgentOrchestrator::new();
        for (agent, config) in builtin_workflows() {
            orch.register(agent, config).await.unwrap();
        }
        let out = orch
            .route(
                &[AgentCapability::VulnerabilityDetection],
                AgentInput::simple("gets(buf)"),
                &AgentContext::default(),
            )
            .await
            .unwrap();
        assert!(out.result.contains("vuln-agent"));
    }
}
