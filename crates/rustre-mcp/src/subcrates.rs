//! Sub-crate registry/dispatcher for the `rustre-mcp` hub.
//!
//! Wires every workspace sub-crate that contributes MCP functionality into a
//! single discoverable surface. Each sub-crate's primary type is re-exported
//! and instantiated by [`SubcrateRegistry::all`], so callers can spin up the
//! full MCP stack (federation + server + tool catalog) from one place.

pub use rustre_mcp_federation::{FederationConfig, FederationManager};
pub use rustre_mcp_server::McpServer;
pub use rustre_mcp_tools::ToolRegistry as McpToolRegistry;

/// Aggregated handle to every wired sub-crate of the `rustre-mcp` hub.
pub struct SubcrateRegistry {
    /// Multi-upstream federation manager (`rustre-mcp-federation`).
    pub federation: FederationManager,
    /// JSON-RPC MCP server skeleton (`rustre-mcp-server`).
    pub server: McpServer,
    /// Built-in tool catalog and registry (`rustre-mcp-tools`).
    pub tools: McpToolRegistry,
}

impl SubcrateRegistry {
    /// Construct a default registry that instantiates every wired sub-crate.
    #[must_use]
    pub fn all() -> Self {
        Self {
            federation: FederationManager::new(FederationConfig::new()),
            server: McpServer::new("rustre-mcp", env!("CARGO_PKG_VERSION")),
            tools: McpToolRegistry::new(),
        }
    }

    /// Names of every sub-crate wired into the hub.
    #[must_use]
    pub fn subcrate_names() -> &'static [&'static str] {
        &[
            "rustre-mcp-federation",
            "rustre-mcp-server",
            "rustre-mcp-tools",
        ]
    }
}

impl Default for SubcrateRegistry {
    fn default() -> Self {
        Self::all()
    }
}
