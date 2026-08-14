//! MCP capabilities advertisement and high-level negotiation.
//!
//! Provides [`McpCapabilities`], [`ToolCapability`], [`ResourceCapability`],
//! [`PromptCapability`], [`SamplingCapability`], and [`CapabilityNegotiation`]
//! for implementing the MCP spec §1 capabilities handshake.
//!
//! # Distinction from `mcp_capability_negotiator`
//!
//! This module models the **MCP protocol-level capability advertisement**:
//! servers declare tools, resources, prompts, and sampling settings via
//! strongly-typed structs and produce the `initialize` response JSON.
//! [`CapabilityNegotiation`] is a high-level helper that matches requested
//! tools against what the server offers.
//!
//! [`crate::mcp_capability_negotiator`] implements the **low-level handshake
//! algorithm**: it accepts generic [`crate::mcp_capability_negotiator::Capabilities`]
//! objects (feature flags keyed by name), enforces version compatibility via a
//! configurable [`crate::mcp_capability_negotiator::NegotiationPolicy`], and
//! tracks peer capability matrices.  Note that both modules independently
//! define a `CapabilityVersion` type and a `NegotiationResult` type; they are
//! intentionally different (this module's types are MCP-spec-shaped; the other
//! module's types carry `Copy + Ord` for algorithmic use).

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── CapabilityVersion ─────────────────────────────────────────────────────────

/// Semantic version triple.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl CapabilityVersion {
    /// Create a version triple.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse from a `"major.minor.patch"` string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts[2].parse().ok()?;
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Return `true` if `self` is compatible with `other` (same major version).
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// Return `true` if `self >= other`.
    #[must_use]
    pub fn at_least(&self, other: &Self) -> bool {
        (self.major, self.minor, self.patch) >= (other.major, other.minor, other.patch)
    }
}

impl fmt::Display for CapabilityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for CapabilityVersion {
    fn default() -> Self {
        Self::new(1, 0, 0)
    }
}

// ── ToolCapability ────────────────────────────────────────────────────────────

/// Advertisement of a tool capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapability {
    /// Tool identifier.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Tool version.
    pub version: CapabilityVersion,
    /// Whether this tool supports streaming responses.
    pub streaming: bool,
    /// Whether this tool supports cancellation.
    pub cancellable: bool,
    /// Input schema (subset).
    pub input_schema: Option<serde_json::Value>,
    /// Tags for capability discovery.
    pub tags: Vec<String>,
    /// Whether this tool requires authentication.
    pub requires_auth: bool,
}

impl ToolCapability {
    /// Create a minimal tool capability.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            version: CapabilityVersion::default(),
            streaming: false,
            cancellable: false,
            input_schema: None,
            tags: Vec::new(),
            requires_auth: false,
        }
    }

    /// Enable streaming.
    #[must_use]
    pub fn with_streaming(mut self) -> Self {
        self.streaming = true;
        self
    }

    /// Enable cancellation.
    #[must_use]
    pub fn with_cancellation(mut self) -> Self {
        self.cancellable = true;
        self
    }

    /// Attach an input schema.
    #[must_use]
    pub fn with_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema = Some(schema);
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Return `true` if this capability matches a tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

// ── ResourceCapability ────────────────────────────────────────────────────────

/// Advertisement of a resource capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCapability {
    /// Resource URI template.
    pub uri_template: String,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// MIME type of the resource content.
    pub mime_type: String,
    /// Whether the resource is subscribable (server pushes updates).
    pub subscribable: bool,
    /// Whether the resource is paginatable.
    pub paginatable: bool,
    /// Maximum payload size in bytes (0 = unlimited).
    pub max_size_bytes: u64,
}

impl ResourceCapability {
    /// Create a minimal resource capability.
    #[must_use]
    pub fn new(
        uri_template: impl Into<String>,
        name: impl Into<String>,
        mime_type: impl Into<String>,
    ) -> Self {
        Self {
            uri_template: uri_template.into(),
            name: name.into(),
            description: String::new(),
            mime_type: mime_type.into(),
            subscribable: false,
            paginatable: false,
            max_size_bytes: 0,
        }
    }

    /// Return `true` if the MIME type is text-based.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.mime_type.starts_with("text/") || self.mime_type == "application/json"
    }

    /// Return `true` if `uri` matches this capability's URI template.
    #[must_use]
    pub fn matches_uri(&self, uri: &str) -> bool {
        // Simple prefix/suffix match for templates like "rustre://binary/{id}/info".
        let template = &self.uri_template;
        if !template.contains('{') {
            return uri == template;
        }
        let prefix = template.split('{').next().unwrap_or("");
        uri.starts_with(prefix)
    }
}

// ── PromptCapability ──────────────────────────────────────────────────────────

/// A single prompt template capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// Advertisement of a prompt capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptCapability {
    /// Prompt name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Expected arguments.
    pub arguments: Vec<PromptArgument>,
    /// Tags.
    pub tags: Vec<String>,
    /// Estimated output token count.
    pub estimated_tokens: Option<u32>,
}

impl PromptCapability {
    /// Create a minimal prompt capability.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            arguments: Vec::new(),
            tags: Vec::new(),
            estimated_tokens: None,
        }
    }

    /// Add a required argument.
    #[must_use]
    pub fn with_arg(mut self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.arguments.push(PromptArgument {
            name: name.into(),
            description: description.into(),
            required: true,
        });
        self
    }

    /// Add an optional argument.
    #[must_use]
    pub fn with_optional_arg(
        mut self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.arguments.push(PromptArgument {
            name: name.into(),
            description: description.into(),
            required: false,
        });
        self
    }

    /// Return `true` if all required arguments are present.
    #[must_use]
    pub fn validate_args(&self, args: &HashMap<String, String>) -> bool {
        self.arguments
            .iter()
            .filter(|a| a.required)
            .all(|a| args.contains_key(&a.name))
    }
}

// ── SamplingCapability ────────────────────────────────────────────────────────

/// Sampling configuration for LLM-assisted tool results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingCapability {
    /// Whether sampling (LLM inference) is supported.
    pub enabled: bool,
    /// Maximum context window tokens.
    pub max_tokens: u32,
    /// Supported model families.
    pub supported_models: Vec<String>,
    /// Whether streaming sampling is supported.
    pub streaming: bool,
    /// Default temperature.
    pub default_temperature: f32,
    /// Maximum stop sequences.
    pub max_stop_sequences: u32,
    /// Whether system prompts are allowed.
    pub system_prompt_allowed: bool,
}

impl Default for SamplingCapability {
    fn default() -> Self {
        Self {
            enabled: true,
            max_tokens: 4096,
            supported_models: vec!["claude-3-5-sonnet".into(), "claude-3-haiku".into()],
            streaming: true,
            default_temperature: 0.7,
            max_stop_sequences: 4,
            system_prompt_allowed: true,
        }
    }
}

impl SamplingCapability {
    /// Create with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if the given model is supported.
    #[must_use]
    pub fn supports_model(&self, model: &str) -> bool {
        self.supported_models
            .iter()
            .any(|m| m == model || model.starts_with(m.as_str()))
    }

    /// Create a disabled sampling capability.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

// ── McpCapabilities ───────────────────────────────────────────────────────────

/// Complete capability set advertised by an MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCapabilities {
    /// Server name.
    pub server_name: String,
    /// Server version.
    pub server_version: CapabilityVersion,
    /// MCP protocol version.
    pub protocol_version: CapabilityVersion,
    /// Whether tools are enabled.
    pub tools_enabled: bool,
    /// Whether resources are enabled.
    pub resources_enabled: bool,
    /// Whether prompts are enabled.
    pub prompts_enabled: bool,
    /// Whether sampling is enabled.
    pub sampling_enabled: bool,
    /// Whether logging is enabled.
    pub logging_enabled: bool,
    /// Tool capabilities.
    pub tools: Vec<ToolCapability>,
    /// Resource capabilities.
    pub resources: Vec<ResourceCapability>,
    /// Prompt capabilities.
    pub prompts: Vec<PromptCapability>,
    /// Sampling configuration.
    pub sampling: SamplingCapability,
    /// Arbitrary server metadata.
    pub metadata: HashMap<String, String>,
}

impl McpCapabilities {
    /// Create a complete capability set.
    #[must_use]
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            server_version: CapabilityVersion::default(),
            protocol_version: CapabilityVersion::new(2024, 11, 5),
            tools_enabled: true,
            resources_enabled: true,
            prompts_enabled: true,
            sampling_enabled: true,
            logging_enabled: true,
            tools: Vec::new(),
            resources: Vec::new(),
            prompts: Vec::new(),
            sampling: SamplingCapability::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a tool capability.
    pub fn add_tool(&mut self, tool: ToolCapability) {
        self.tools.push(tool);
    }

    /// Add a resource capability.
    pub fn add_resource(&mut self, resource: ResourceCapability) {
        self.resources.push(resource);
    }

    /// Add a prompt capability.
    pub fn add_prompt(&mut self, prompt: PromptCapability) {
        self.prompts.push(prompt);
    }

    /// Set metadata.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Look up a tool by name.
    #[must_use]
    pub fn find_tool(&self, name: &str) -> Option<&ToolCapability> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Look up a resource by URI.
    #[must_use]
    pub fn find_resource(&self, uri: &str) -> Option<&ResourceCapability> {
        self.resources.iter().find(|r| r.matches_uri(uri))
    }

    /// Look up a prompt by name.
    #[must_use]
    pub fn find_prompt(&self, name: &str) -> Option<&PromptCapability> {
        self.prompts.iter().find(|p| p.name == name)
    }

    /// Serialise to the MCP `initialize` response JSON.
    #[must_use]
    pub fn to_initialize_response(&self) -> serde_json::Value {
        serde_json::json!({
            "protocolVersion": self.protocol_version.to_string(),
            "serverInfo": {
                "name": self.server_name,
                "version": self.server_version.to_string(),
            },
            "capabilities": {
                "tools":     { "enabled": self.tools_enabled },
                "resources": { "enabled": self.resources_enabled, "subscribe": true },
                "prompts":   { "enabled": self.prompts_enabled },
                "sampling":  { "enabled": self.sampling_enabled },
                "logging":   { "enabled": self.logging_enabled },
            }
        })
    }

    /// Return all tool names.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.iter().map(|t| t.name.as_str()).collect()
    }

    /// Return all resource URI templates.
    #[must_use]
    pub fn resource_uris(&self) -> Vec<&str> {
        self.resources
            .iter()
            .map(|r| r.uri_template.as_str())
            .collect()
    }

    /// Return all prompt names.
    #[must_use]
    pub fn prompt_names(&self) -> Vec<&str> {
        self.prompts.iter().map(|p| p.name.as_str()).collect()
    }

    /// Total number of capabilities.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.tools.len() + self.resources.len() + self.prompts.len()
    }
}

// ── CapabilityNegotiation ─────────────────────────────────────────────────────

/// Result of a capability negotiation between client and server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationResult {
    /// Whether negotiation succeeded.
    pub success: bool,
    /// Agreed protocol version.
    pub agreed_protocol_version: Option<CapabilityVersion>,
    /// Tools that were accepted.
    pub accepted_tools: Vec<String>,
    /// Tools that were rejected.
    pub rejected_tools: Vec<String>,
    /// Resources that were accepted.
    pub accepted_resources: Vec<String>,
    /// Prompts that were accepted.
    pub accepted_prompts: Vec<String>,
    /// Negotiation warnings.
    pub warnings: Vec<String>,
    /// Negotiation errors.
    pub errors: Vec<String>,
}

impl NegotiationResult {
    /// Create a successful result.
    #[must_use]
    pub fn success(version: CapabilityVersion) -> Self {
        Self {
            success: true,
            agreed_protocol_version: Some(version),
            accepted_tools: Vec::new(),
            rejected_tools: Vec::new(),
            accepted_resources: Vec::new(),
            accepted_prompts: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Create a failed result.
    #[must_use]
    pub fn failure(reason: impl Into<String>) -> Self {
        Self {
            success: false,
            agreed_protocol_version: None,
            accepted_tools: Vec::new(),
            rejected_tools: Vec::new(),
            accepted_resources: Vec::new(),
            accepted_prompts: Vec::new(),
            warnings: Vec::new(),
            errors: vec![reason.into()],
        }
    }

    /// Add a warning.
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// Client capability advertisement for negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// Client name.
    pub client_name: String,
    /// Client version.
    pub client_version: CapabilityVersion,
    /// Protocol versions the client supports (ordered by preference).
    pub supported_protocol_versions: Vec<CapabilityVersion>,
    /// Tool names the client requests.
    pub requested_tools: Vec<String>,
    /// Resource URI templates the client requests.
    pub requested_resources: Vec<String>,
    /// Prompt names the client requests.
    pub requested_prompts: Vec<String>,
    /// Whether the client supports sampling.
    pub supports_sampling: bool,
    /// Whether the client supports roots listing.
    pub roots: bool,
}

impl ClientCapabilities {
    /// Create a basic client capability set.
    #[must_use]
    pub fn new(client_name: impl Into<String>) -> Self {
        Self {
            client_name: client_name.into(),
            client_version: CapabilityVersion::default(),
            supported_protocol_versions: vec![CapabilityVersion::new(2024, 11, 5)],
            requested_tools: Vec::new(),
            requested_resources: Vec::new(),
            requested_prompts: Vec::new(),
            supports_sampling: true,
            roots: false,
        }
    }

    /// Request all available tools.
    #[must_use]
    pub fn with_all_tools(mut self) -> Self {
        self.requested_tools = vec!["*".to_string()];
        self
    }
}

/// MCP capability negotiation engine.
#[derive(Debug, Default)]
pub struct CapabilityNegotiation {
    /// History of negotiations.
    pub history: Vec<NegotiationResult>,
}

impl CapabilityNegotiation {
    /// Create a new negotiation engine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Perform capability negotiation between a client and server.
    pub fn negotiate(
        &mut self,
        client: &ClientCapabilities,
        server: &McpCapabilities,
    ) -> NegotiationResult {
        // Find a common protocol version.
        let agreed_version = client
            .supported_protocol_versions
            .iter()
            .find(|cv| cv.is_compatible_with(&server.protocol_version))
            .cloned();

        let agreed_version = match agreed_version {
            Some(v) => v,
            None => {
                let result = NegotiationResult::failure(format!(
                    "no common protocol version: client supports {:?}, server requires {}",
                    client.supported_protocol_versions, server.protocol_version,
                ));
                self.history.push(result.clone());
                return result;
            }
        };

        let mut result = NegotiationResult::success(agreed_version);

        // Negotiate tools.
        let wants_all = client.requested_tools.iter().any(|t| t == "*");
        for tool in &server.tools {
            if wants_all || client.requested_tools.contains(&tool.name) {
                result.accepted_tools.push(tool.name.clone());
            }
        }
        for req in &client.requested_tools {
            if req != "*" && !server.tools.iter().any(|t| &t.name == req) {
                result.rejected_tools.push(req.clone());
                result.warn(format!("requested tool '{req}' not available"));
            }
        }

        // Negotiate resources.
        for res in &server.resources {
            result.accepted_resources.push(res.uri_template.clone());
        }

        // Negotiate prompts.
        for prompt in &server.prompts {
            result.accepted_prompts.push(prompt.name.clone());
        }

        // Sampling.
        if client.supports_sampling && !server.sampling_enabled {
            result.warn("client wants sampling but server has it disabled".to_string());
        }

        self.history.push(result.clone());
        result
    }

    /// Number of negotiations performed.
    #[must_use]
    pub fn negotiation_count(&self) -> usize {
        self.history.len()
    }

    /// Last successful protocol version.
    #[must_use]
    pub fn last_agreed_version(&self) -> Option<&CapabilityVersion> {
        self.history
            .iter()
            .rev()
            .filter(|r| r.success)
            .filter_map(|r| r.agreed_protocol_version.as_ref())
            .next()
    }
}

// ── CapabilityRegistry ────────────────────────────────────────────────────────

/// Thread-safe registry of `McpCapabilities` from multiple MCP servers.
#[derive(Debug, Default)]
pub struct CapabilityRegistry {
    servers: HashMap<String, McpCapabilities>,
}

impl CapabilityRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a server's capabilities.
    pub fn register(&mut self, capabilities: McpCapabilities) {
        self.servers
            .insert(capabilities.server_name.clone(), capabilities);
    }

    /// Remove a server.
    pub fn remove(&mut self, server_name: &str) -> bool {
        self.servers.remove(server_name).is_some()
    }

    /// Find a tool by name across all registered servers.
    #[must_use]
    pub fn find_tool(&self, tool_name: &str) -> Vec<(&str, &ToolCapability)> {
        self.servers
            .iter()
            .filter_map(|(name, cap)| cap.find_tool(tool_name).map(|t| (name.as_str(), t)))
            .collect()
    }

    /// Find all tools matching a tag across all servers.
    #[must_use]
    pub fn tools_by_tag(&self, tag: &str) -> Vec<(&str, &ToolCapability)> {
        self.servers
            .iter()
            .flat_map(|(name, cap)| {
                cap.tools
                    .iter()
                    .filter(|t| t.has_tag(tag))
                    .map(move |t| (name.as_str(), t))
            })
            .collect()
    }

    /// Return the names of all registered servers.
    #[must_use]
    pub fn server_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.servers.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Number of registered servers.
    #[must_use]
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Total tool count across all servers.
    #[must_use]
    pub fn total_tool_count(&self) -> usize {
        self.servers.values().map(|c| c.tools.len()).sum()
    }
}

// ── CapabilityDiff ────────────────────────────────────────────────────────────

/// Difference between two `McpCapabilities` instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDiff {
    /// Tools added (in `new` but not in `old`).
    pub tools_added: Vec<String>,
    /// Tools removed (in `old` but not in `new`).
    pub tools_removed: Vec<String>,
    /// Resources added.
    pub resources_added: Vec<String>,
    /// Resources removed.
    pub resources_removed: Vec<String>,
    /// Whether the protocol version changed.
    pub protocol_version_changed: bool,
}

impl CapabilityDiff {
    /// Compute the diff between `old` and `new` capabilities.
    #[must_use]
    pub fn compute(old: &McpCapabilities, new: &McpCapabilities) -> Self {
        let old_tools: std::collections::HashSet<&str> =
            old.tools.iter().map(|t| t.name.as_str()).collect();
        let new_tools: std::collections::HashSet<&str> =
            new.tools.iter().map(|t| t.name.as_str()).collect();

        let tools_added = new_tools
            .difference(&old_tools)
            .map(|s| s.to_string())
            .collect();
        let tools_removed = old_tools
            .difference(&new_tools)
            .map(|s| s.to_string())
            .collect();

        let old_res: std::collections::HashSet<&str> = old
            .resources
            .iter()
            .map(|r| r.uri_template.as_str())
            .collect();
        let new_res: std::collections::HashSet<&str> = new
            .resources
            .iter()
            .map(|r| r.uri_template.as_str())
            .collect();

        let resources_added = new_res
            .difference(&old_res)
            .map(|s| s.to_string())
            .collect();
        let resources_removed = old_res
            .difference(&new_res)
            .map(|s| s.to_string())
            .collect();

        Self {
            tools_added,
            tools_removed,
            resources_added,
            resources_removed,
            protocol_version_changed: old.protocol_version != new.protocol_version,
        }
    }

    /// Return `true` if there are no differences.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools_added.is_empty()
            && self.tools_removed.is_empty()
            && self.resources_added.is_empty()
            && self.resources_removed.is_empty()
            && !self.protocol_version_changed
    }

    /// Return the total number of changes.
    #[must_use]
    pub fn change_count(&self) -> usize {
        self.tools_added.len()
            + self.tools_removed.len()
            + self.resources_added.len()
            + self.resources_removed.len()
            + if self.protocol_version_changed { 1 } else { 0 }
    }
}

// ── CapabilityValidator ───────────────────────────────────────────────────────

/// Validates `McpCapabilities` against a policy.
#[derive(Debug, Default)]
pub struct CapabilityValidator {
    /// Tools that are required.
    pub required_tools: Vec<String>,
    /// Tools that are forbidden.
    pub forbidden_tools: Vec<String>,
    /// Minimum protocol version.
    pub min_protocol_version: Option<CapabilityVersion>,
}

/// Result of a capability validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl CapabilityValidator {
    /// Create a new validator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require a tool.
    pub fn require_tool(&mut self, name: impl Into<String>) {
        self.required_tools.push(name.into());
    }

    /// Forbid a tool.
    pub fn forbid_tool(&mut self, name: impl Into<String>) {
        self.forbidden_tools.push(name.into());
    }

    /// Validate capabilities against the policy.
    #[must_use]
    pub fn validate(&self, cap: &McpCapabilities) -> ValidationResult {
        let mut errors: Vec<String> = Vec::with_capacity(self.required_tools.len() + self.forbidden_tools.len());
        let mut warnings: Vec<String> = Vec::new();

        for req in &self.required_tools {
            if cap.find_tool(req).is_none() {
                errors.push(format!("required tool '{req}' is missing"));
            }
        }
        for forbidden in &self.forbidden_tools {
            if cap.find_tool(forbidden).is_some() {
                errors.push(format!("forbidden tool '{forbidden}' is present"));
            }
        }
        if let Some(min) = &self.min_protocol_version
            && !cap.protocol_version.at_least(min) {
                errors.push(format!(
                    "protocol version {} is below minimum {}",
                    cap.protocol_version, min
                ));
            }
        if cap.tools.is_empty() && cap.tools_enabled {
            warnings.push("tools are enabled but none are defined".into());
        }

        ValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }
}

// ── CapabilitySnapshot ────────────────────────────────────────────────────────

/// A point-in-time snapshot of a server's capabilities for change tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// Timestamp of the snapshot.
    pub timestamp: u64,
    /// Server name.
    pub server_name: String,
    /// Protocol version.
    pub protocol_version: CapabilityVersion,
    /// Tool names at snapshot time.
    pub tool_names: Vec<String>,
    /// Resource URIs at snapshot time.
    pub resource_uris: Vec<String>,
    /// Whether tools were enabled.
    pub tools_enabled: bool,
}

impl CapabilitySnapshot {
    /// Take a snapshot from `McpCapabilities`.
    #[must_use]
    pub fn take(cap: &McpCapabilities) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            timestamp: now,
            server_name: cap.server_name.clone(),
            protocol_version: cap.protocol_version.clone(),
            tool_names: cap.tool_names().iter().map(|s| s.to_string()).collect(),
            resource_uris: cap.resource_uris().iter().map(|s| s.to_string()).collect(),
            tools_enabled: cap.tools_enabled,
        }
    }

    /// Return `true` if the snapshot has the given tool.
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.tool_names.iter().any(|t| t == name)
    }

    /// Return the number of tools in the snapshot.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tool_names.len()
    }
}

// ── CapabilitySessionManager ──────────────────────────────────────────────────

/// Manages capability negotiation sessions across multiple client connections.
#[derive(Debug, Default)]
pub struct CapabilitySessionManager {
    sessions: HashMap<String, (ClientCapabilities, NegotiationResult)>,
}

impl CapabilitySessionManager {
    /// Create a new manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a successful negotiation result.
    pub fn register_session(
        &mut self,
        session_id: impl Into<String>,
        client: ClientCapabilities,
        result: NegotiationResult,
    ) {
        self.sessions.insert(session_id.into(), (client, result));
    }

    /// Remove a session.
    pub fn close_session(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Return the number of active sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Return all session IDs.
    #[must_use]
    pub fn session_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.sessions.keys().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }

    /// Return sessions that accepted a specific tool.
    #[must_use]
    pub fn sessions_with_tool(&self, tool_name: &str) -> Vec<&str> {
        self.sessions
            .iter()
            .filter(|(_, (_, result))| result.accepted_tools.contains(&tool_name.to_string()))
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Return `true` if any session was successful.
    #[must_use]
    pub fn has_successful_sessions(&self) -> bool {
        self.sessions.values().any(|(_, r)| r.success)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server() -> McpCapabilities {
        let mut cap = McpCapabilities::new("rustre-mcp-server");
        cap.add_tool(ToolCapability::new(
            "analyze.function",
            "Analyse a function",
        ));
        cap.add_tool(
            ToolCapability::new("disasm.at", "Disassemble at address")
                .with_streaming()
                .with_tag("analysis"),
        );
        cap.add_resource(ResourceCapability::new(
            "rustre://project/current",
            "Current Project",
            "application/json",
        ));
        cap.add_prompt(
            PromptCapability::new("explain_function", "Explain a function")
                .with_arg("addr", "Function address")
                .with_optional_arg("lang", "Output language"),
        );
        cap
    }

    fn make_client() -> ClientCapabilities {
        ClientCapabilities::new("claude-code").with_all_tools()
    }

    // ── CapabilityVersion ────────────────────────────────────────────────────

    #[test]
    fn test_version_display() {
        let v = CapabilityVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_version_parse() {
        let v = CapabilityVersion::parse("2024.11.5").unwrap();
        assert_eq!(v.major, 2024);
        assert_eq!(v.minor, 11);
        assert_eq!(v.patch, 5);
    }

    #[test]
    fn test_version_parse_invalid() {
        assert!(CapabilityVersion::parse("1.2").is_none());
        assert!(CapabilityVersion::parse("a.b.c").is_none());
    }

    #[test]
    fn test_version_compatible() {
        let v1 = CapabilityVersion::new(1, 0, 0);
        let v2 = CapabilityVersion::new(1, 5, 3);
        assert!(v1.is_compatible_with(&v2));
    }

    #[test]
    fn test_version_incompatible() {
        let v1 = CapabilityVersion::new(1, 0, 0);
        let v2 = CapabilityVersion::new(2, 0, 0);
        assert!(!v1.is_compatible_with(&v2));
    }

    #[test]
    fn test_version_at_least() {
        let v1 = CapabilityVersion::new(1, 5, 0);
        let v2 = CapabilityVersion::new(1, 0, 0);
        assert!(v1.at_least(&v2));
        assert!(!v2.at_least(&v1));
    }

    // ── ToolCapability ───────────────────────────────────────────────────────

    #[test]
    fn test_tool_capability_new() {
        let t = ToolCapability::new("analyze.function", "Analyse");
        assert_eq!(t.name, "analyze.function");
        assert!(!t.streaming);
        assert!(!t.cancellable);
    }

    #[test]
    fn test_tool_capability_streaming() {
        let t = ToolCapability::new("t", "d").with_streaming();
        assert!(t.streaming);
    }

    #[test]
    fn test_tool_capability_tag() {
        let t = ToolCapability::new("t", "d").with_tag("analysis");
        assert!(t.has_tag("analysis"));
        assert!(!t.has_tag("debug"));
    }

    #[test]
    fn test_tool_capability_schema() {
        let schema = serde_json::json!({"type": "object"});
        let t = ToolCapability::new("t", "d").with_schema(schema.clone());
        assert_eq!(t.input_schema.unwrap(), schema);
    }

    // ── ResourceCapability ───────────────────────────────────────────────────

    #[test]
    fn test_resource_is_text() {
        let r = ResourceCapability::new("rustre://p", "P", "application/json");
        assert!(r.is_text());
    }

    #[test]
    fn test_resource_is_binary() {
        let r = ResourceCapability::new("rustre://p", "P", "application/octet-stream");
        assert!(!r.is_text());
    }

    #[test]
    fn test_resource_matches_uri() {
        let r = ResourceCapability::new("rustre://binary/{id}/info", "Info", "application/json");
        assert!(r.matches_uri("rustre://binary/bv-1234/info"));
        assert!(!r.matches_uri("rustre://project/current"));
    }

    #[test]
    fn test_resource_matches_exact() {
        let r = ResourceCapability::new("rustre://project/current", "P", "application/json");
        assert!(r.matches_uri("rustre://project/current"));
        assert!(!r.matches_uri("rustre://project/other"));
    }

    // ── PromptCapability ─────────────────────────────────────────────────────

    #[test]
    fn test_prompt_capability_new() {
        let p = PromptCapability::new("explain", "Explain something");
        assert_eq!(p.name, "explain");
        assert!(p.arguments.is_empty());
    }

    #[test]
    fn test_prompt_with_args() {
        let p = PromptCapability::new("p", "d")
            .with_arg("required_arg", "A required arg")
            .with_optional_arg("opt", "Optional");
        assert_eq!(p.arguments.len(), 2);
        assert!(p.arguments[0].required);
        assert!(!p.arguments[1].required);
    }

    #[test]
    fn test_prompt_validate_args() {
        let p = PromptCapability::new("p", "d").with_arg("addr", "Address");
        let mut args = HashMap::new();
        args.insert("addr".to_string(), "0x1400".to_string());
        assert!(p.validate_args(&args));
        args.clear();
        assert!(!p.validate_args(&args));
    }

    // ── SamplingCapability ───────────────────────────────────────────────────

    #[test]
    fn test_sampling_defaults() {
        let s = SamplingCapability::new();
        assert!(s.enabled);
        assert!(s.streaming);
    }

    #[test]
    fn test_sampling_supports_model() {
        let s = SamplingCapability::new();
        assert!(s.supports_model("claude-3-5-sonnet"));
        assert!(!s.supports_model("gpt-4"));
    }

    #[test]
    fn test_sampling_disabled() {
        let s = SamplingCapability::disabled();
        assert!(!s.enabled);
    }

    // ── McpCapabilities ──────────────────────────────────────────────────────

    #[test]
    fn test_mcp_capabilities_add_tool() {
        let mut cap = McpCapabilities::new("test");
        cap.add_tool(ToolCapability::new("t1", "d1"));
        assert_eq!(cap.tools.len(), 1);
    }

    #[test]
    fn test_mcp_capabilities_find_tool() {
        let cap = make_server();
        assert!(cap.find_tool("analyze.function").is_some());
        assert!(cap.find_tool("missing").is_none());
    }

    #[test]
    fn test_mcp_capabilities_find_resource() {
        let cap = make_server();
        assert!(cap.find_resource("rustre://project/current").is_some());
        assert!(cap.find_resource("unknown://x").is_none());
    }

    #[test]
    fn test_mcp_capabilities_find_prompt() {
        let cap = make_server();
        assert!(cap.find_prompt("explain_function").is_some());
        assert!(cap.find_prompt("missing").is_none());
    }

    #[test]
    fn test_mcp_capabilities_tool_names() {
        let cap = make_server();
        let names = cap.tool_names();
        assert!(names.contains(&"analyze.function"));
        assert!(names.contains(&"disasm.at"));
    }

    #[test]
    fn test_mcp_capabilities_total_count() {
        let cap = make_server();
        // total_count = tools + resources + prompts = 2 + 1 + 1 = 4
        assert_eq!(cap.total_count(), 4);
        assert_eq!(
            cap.total_count(),
            cap.tools.len() + cap.resources.len() + cap.prompts.len()
        );
    }

    #[test]
    fn test_mcp_capabilities_initialize_response() {
        let cap = make_server();
        let resp = cap.to_initialize_response();
        assert!(
            resp["serverInfo"]["name"]
                .as_str()
                .unwrap()
                .contains("rustre")
        );
        assert!(resp["capabilities"]["tools"]["enabled"].as_bool().unwrap());
    }

    #[test]
    fn test_mcp_capabilities_metadata() {
        let mut cap = McpCapabilities::new("test");
        cap.set_meta("env", "production");
        assert_eq!(
            cap.metadata.get("env").map(String::as_str),
            Some("production")
        );
    }

    // ── CapabilityNegotiation ────────────────────────────────────────────────

    #[test]
    fn test_negotiation_success() {
        let server = make_server();
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        assert!(result.success);
        assert!(result.agreed_protocol_version.is_some());
    }

    #[test]
    fn test_negotiation_accepted_tools() {
        let server = make_server();
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        assert!(
            result
                .accepted_tools
                .contains(&"analyze.function".to_string())
        );
    }

    #[test]
    fn test_negotiation_specific_tool_request() {
        let server = make_server();
        let mut client = ClientCapabilities::new("test");
        client.requested_tools.push("analyze.function".to_string());
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        assert!(
            result
                .accepted_tools
                .contains(&"analyze.function".to_string())
        );
    }

    #[test]
    fn test_negotiation_rejected_tool() {
        let server = make_server();
        let mut client = ClientCapabilities::new("test");
        client.requested_tools.push("nonexistent.tool".to_string());
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        assert!(
            result
                .rejected_tools
                .contains(&"nonexistent.tool".to_string())
        );
    }

    #[test]
    fn test_negotiation_version_mismatch() {
        let mut server = make_server();
        server.protocol_version = CapabilityVersion::new(99, 0, 0);
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        assert!(!result.success);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_negotiation_history() {
        let server = make_server();
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        neg.negotiate(&client, &server);
        neg.negotiate(&client, &server);
        assert_eq!(neg.negotiation_count(), 2);
    }

    #[test]
    fn test_negotiation_last_agreed_version() {
        let server = make_server();
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        neg.negotiate(&client, &server);
        assert!(neg.last_agreed_version().is_some());
    }

    #[test]
    fn test_negotiation_resources_accepted() {
        let server = make_server();
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        assert!(!result.accepted_resources.is_empty());
    }

    #[test]
    fn test_negotiation_prompts_accepted() {
        let server = make_server();
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        assert!(
            result
                .accepted_prompts
                .contains(&"explain_function".to_string())
        );
    }

    // ── CapabilityRegistry ───────────────────────────────────────────────────

    #[test]
    fn test_registry_register_and_find() {
        let mut reg = CapabilityRegistry::new();
        reg.register(make_server());
        let tools = reg.find_tool("analyze.function");
        assert!(!tools.is_empty());
        assert!(tools[0].0.contains("rustre"));
    }

    #[test]
    fn test_registry_remove() {
        let mut reg = CapabilityRegistry::new();
        reg.register(make_server());
        assert!(reg.remove("rustre-mcp-server"));
        assert_eq!(reg.server_count(), 0);
    }

    #[test]
    fn test_registry_tools_by_tag() {
        let mut reg = CapabilityRegistry::new();
        reg.register(make_server());
        let tagged = reg.tools_by_tag("analysis");
        assert!(!tagged.is_empty());
    }

    #[test]
    fn test_registry_server_names() {
        let mut reg = CapabilityRegistry::new();
        reg.register(make_server());
        let names = reg.server_names();
        assert!(names.contains(&"rustre-mcp-server"));
    }

    #[test]
    fn test_registry_total_tool_count() {
        let mut reg = CapabilityRegistry::new();
        reg.register(make_server());
        assert!(reg.total_tool_count() >= 2);
    }

    // ── CapabilityDiff ───────────────────────────────────────────────────────

    #[test]
    fn test_diff_no_changes() {
        let server = make_server();
        let diff = CapabilityDiff::compute(&server, &server);
        assert!(diff.is_empty());
        assert_eq!(diff.change_count(), 0);
    }

    #[test]
    fn test_diff_tool_added() {
        let old = make_server();
        let mut new_cap = make_server();
        new_cap.add_tool(ToolCapability::new("new_tool", "New"));
        let diff = CapabilityDiff::compute(&old, &new_cap);
        assert!(diff.tools_added.contains(&"new_tool".to_string()));
    }

    #[test]
    fn test_diff_tool_removed() {
        let old = make_server();
        let mut new_cap = make_server();
        new_cap.tools.clear();
        let diff = CapabilityDiff::compute(&old, &new_cap);
        assert!(!diff.tools_removed.is_empty());
    }

    #[test]
    fn test_diff_change_count() {
        let old = make_server();
        let mut new_cap = make_server();
        new_cap.add_tool(ToolCapability::new("extra", "Extra tool"));
        let diff = CapabilityDiff::compute(&old, &new_cap);
        assert!(diff.change_count() > 0);
    }

    // ── CapabilityValidator ──────────────────────────────────────────────────

    #[test]
    fn test_validator_required_tool_present() {
        let mut v = CapabilityValidator::new();
        v.require_tool("analyze.function");
        let result = v.validate(&make_server());
        assert!(result.valid);
    }

    #[test]
    fn test_validator_required_tool_missing() {
        let mut v = CapabilityValidator::new();
        v.require_tool("nonexistent.tool");
        let result = v.validate(&make_server());
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validator_forbidden_tool() {
        let mut v = CapabilityValidator::new();
        v.forbid_tool("analyze.function");
        let result = v.validate(&make_server());
        assert!(!result.valid);
    }

    #[test]
    fn test_validator_min_version_ok() {
        let mut v = CapabilityValidator::new();
        v.min_protocol_version = Some(CapabilityVersion::new(2024, 1, 0));
        let result = v.validate(&make_server());
        assert!(result.valid);
    }

    #[test]
    fn test_validator_min_version_fail() {
        let mut v = CapabilityValidator::new();
        v.min_protocol_version = Some(CapabilityVersion::new(9999, 0, 0));
        let result = v.validate(&make_server());
        assert!(!result.valid);
    }

    // ── CapabilitySnapshot ───────────────────────────────────────────────────

    #[test]
    fn test_snapshot_take() {
        let server = make_server();
        let snap = CapabilitySnapshot::take(&server);
        assert_eq!(snap.server_name, "rustre-mcp-server");
        assert!(snap.tools_enabled);
    }

    #[test]
    fn test_snapshot_has_tool() {
        let server = make_server();
        let snap = CapabilitySnapshot::take(&server);
        assert!(snap.has_tool("analyze.function"));
        assert!(!snap.has_tool("nonexistent"));
    }

    #[test]
    fn test_snapshot_tool_count() {
        let server = make_server();
        let snap = CapabilitySnapshot::take(&server);
        assert_eq!(snap.tool_count(), server.tools.len());
    }

    // ── CapabilitySessionManager ─────────────────────────────────────────────

    #[test]
    fn test_session_manager_register() {
        let mut mgr = CapabilitySessionManager::new();
        let client = make_client();
        let result = NegotiationResult::success(CapabilityVersion::new(2024, 11, 5));
        mgr.register_session("sess-1", client, result);
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_session_manager_close() {
        let mut mgr = CapabilitySessionManager::new();
        let client = make_client();
        let result = NegotiationResult::success(CapabilityVersion::new(2024, 11, 5));
        mgr.register_session("s1", client, result);
        assert!(mgr.close_session("s1"));
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_session_manager_sessions_with_tool() {
        let server = make_server();
        let client = make_client();
        let mut neg = CapabilityNegotiation::new();
        let result = neg.negotiate(&client, &server);
        let mut mgr = CapabilitySessionManager::new();
        mgr.register_session("s1", client, result);
        let sessions = mgr.sessions_with_tool("analyze.function");
        assert!(sessions.contains(&"s1"));
    }

    #[test]
    fn test_session_manager_has_successful() {
        let mut mgr = CapabilitySessionManager::new();
        let result = NegotiationResult::success(CapabilityVersion::new(2024, 11, 5));
        mgr.register_session("s", ClientCapabilities::new("test"), result);
        assert!(mgr.has_successful_sessions());
    }

    #[test]
    fn test_session_manager_ids_sorted() {
        let mut mgr = CapabilitySessionManager::new();
        let r = NegotiationResult::success(CapabilityVersion::new(2024, 11, 5));
        mgr.register_session("beta", ClientCapabilities::new("b"), r.clone());
        mgr.register_session("alpha", ClientCapabilities::new("a"), r);
        let ids = mgr.session_ids();
        assert_eq!(ids[0], "alpha");
    }
}
