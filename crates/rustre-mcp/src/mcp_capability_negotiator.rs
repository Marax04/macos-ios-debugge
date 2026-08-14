//! Low-level MCP capability negotiation algorithm.
//!
//! Provides [`McpCapabilityNegotiator`], [`Capabilities`], [`NegotiationResult`],
//! and supporting types for the MCP handshake protocol where a client and server
//! exchange their capability sets and agree on a common feature baseline.
//!
//! # Distinction from `mcp_capabilities`
//!
//! This module implements the **generic handshake algorithm**: capabilities are
//! modelled as named feature flags with semantic version numbers.  The
//! [`McpCapabilityNegotiator`] enforces version compatibility under a
//! configurable [`NegotiationPolicy`] (Strict / Lenient / Accept) and produces
//! a [`NegotiationResult`] recording agreed, local-only, and remote-only feature
//! sets.  It also provides a [`CapabilityMatrix`] for tracking multiple peers.
//!
//! [`crate::mcp_capabilities`] models the **MCP protocol-level advertisement**:
//! servers enumerate concrete tools, resources, and prompts; the
//! [`crate::mcp_capabilities::CapabilityNegotiation`] helper matches tool names.
//! Both modules define their own `CapabilityVersion` and `NegotiationResult`
//! types — the types in *this* module are `Copy + Ord` for algorithmic use,
//! while the types in `mcp_capabilities` are MCP-spec-shaped (no `Copy`,
//! no `Ord`).

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Feature flags ────────────────────────────────────────────────────────────

/// A single capability advertised by a client or server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Short machine-readable name, e.g. `"streaming"`.
    pub name: String,
    /// Semantic version of this capability (major.minor.patch).
    pub version: CapabilityVersion,
    /// Whether this capability is optional (can be absent without failure).
    pub optional: bool,
    /// Additional properties for this capability.
    pub properties: HashMap<String, String>,
}

impl Capability {
    /// Create a required capability with the given name and version.
    #[must_use]
    pub fn required(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: CapabilityVersion::parse(&version.into()).unwrap_or_default(),
            optional: false,
            properties: HashMap::new(),
        }
    }

    /// Create an optional capability.
    #[must_use]
    pub fn optional(name: impl Into<String>, version: impl Into<String>) -> Self {
        let mut c = Self::required(name, version);
        c.optional = true;
        c
    }

    /// Attach a property.
    #[must_use]
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

// ─── CapabilityVersion ────────────────────────────────────────────────────────

/// Semantic version number (major.minor.patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapabilityVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl CapabilityVersion {
    /// Construct a version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Parse a `"major.minor.patch"` string.
    ///
    /// # Errors
    /// Returns [`NegotiationError::InvalidVersion`] when parsing fails.
    pub fn parse(s: &str) -> Result<Self, NegotiationError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(NegotiationError::InvalidVersion(s.to_string()));
        }
        let parse = |p: &str| {
            p.parse::<u32>()
                .map_err(|_| NegotiationError::InvalidVersion(s.to_string()))
        };
        Ok(Self::new(parse(parts[0])?, parse(parts[1])?, parse(parts[2])?))
    }

    /// Returns `true` if `self` is backwards-compatible with `required`.
    ///
    /// Compatibility means `self.major == required.major && self >= required`.
    #[must_use]
    pub fn is_compatible_with(&self, required: &Self) -> bool {
        self.major == required.major && *self >= *required
    }
}

impl Default for CapabilityVersion {
    fn default() -> Self {
        Self::new(1, 0, 0)
    }
}

impl fmt::Display for CapabilityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ─── Capabilities ─────────────────────────────────────────────────────────────

/// A full capability advertisement, consisting of a set of named capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// The advertised capabilities, keyed by name.
    pub capabilities: HashMap<String, Capability>,
    /// Protocol version the sender supports.
    pub protocol_version: CapabilityVersion,
    /// Identity of the sender (e.g. `"RustRE-MCP/1.0"`).
    pub agent_id: String,
}

impl Capabilities {
    /// Create an empty set.
    #[must_use]
    pub fn new(agent_id: impl Into<String>, protocol_version: CapabilityVersion) -> Self {
        Self {
            capabilities: HashMap::new(),
            protocol_version,
            agent_id: agent_id.into(),
        }
    }

    /// Add a capability.
    pub fn add(&mut self, cap: Capability) {
        self.capabilities.insert(cap.name.clone(), cap);
    }

    /// Builder-style capability addition.
    #[must_use]
    pub fn with(mut self, cap: Capability) -> Self {
        self.add(cap);
        self
    }

    /// Return `true` if the named capability is present.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.capabilities.contains_key(name)
    }

    /// Return the version of a named capability, if present.
    #[must_use]
    pub fn version_of(&self, name: &str) -> Option<CapabilityVersion> {
        self.capabilities.get(name).map(|c| c.version)
    }

    /// Return names of all capabilities.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.capabilities.keys().map(String::as_str).collect()
    }

    /// Number of declared capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Produce a RustRE server default capability set.
    #[must_use]
    pub fn rustre_defaults() -> Self {
        Self::new("RustRE-MCP", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"))
            .with(Capability::required("resources", "1.0.0"))
            .with(Capability::optional("streaming", "1.0.0"))
            .with(Capability::optional("batch", "1.0.0"))
            .with(Capability::optional("notifications", "1.0.0"))
            .with(Capability::optional("sampling", "1.0.0"))
    }
}

// ─── NegotiationError ─────────────────────────────────────────────────────────

/// Errors that can occur during capability negotiation.
#[derive(Debug, Error, Clone)]
pub enum NegotiationError {
    #[error("invalid version string: {0}")]
    InvalidVersion(String),

    #[error("incompatible protocol versions: client={client}, server={server}")]
    IncompatibleProtocol {
        client: CapabilityVersion,
        server: CapabilityVersion,
    },

    #[error("required capability missing on peer: {0}")]
    MissingRequiredCapability(String),

    #[error("version conflict for capability '{name}': required {required}, offered {offered}")]
    VersionConflict {
        name: String,
        required: CapabilityVersion,
        offered: CapabilityVersion,
    },

    #[error("negotiation rejected: {0}")]
    Rejected(String),
}

// ─── NegotiationResult ────────────────────────────────────────────────────────

/// Outcome of a capability negotiation handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationResult {
    /// The agreed-upon protocol version.
    pub protocol_version: CapabilityVersion,
    /// Capabilities agreed by both parties, keyed by name.
    pub agreed: HashMap<String, Capability>,
    /// Capabilities offered by the remote but not present locally (optional ones).
    pub remote_only: HashSet<String>,
    /// Capabilities present locally but not offered by the remote (optional ones).
    pub local_only: HashSet<String>,
    /// Whether negotiation was fully successful (all required caps matched).
    pub success: bool,
    /// Human-readable summary.
    pub summary: String,
}

impl NegotiationResult {
    /// Returns `true` if the named capability is in the agreed set.
    #[must_use]
    pub fn has_agreed(&self, name: &str) -> bool {
        self.agreed.contains_key(name)
    }

    /// Total agreed capabilities.
    #[must_use]
    pub fn agreed_count(&self) -> usize {
        self.agreed.len()
    }
}

impl fmt::Display for NegotiationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NegotiationResult {{ protocol={}, agreed={}, success={} }}",
            self.protocol_version,
            self.agreed.len(),
            self.success
        )
    }
}

// ─── NegotiationPolicy ────────────────────────────────────────────────────────

/// Policy controlling how strictly the negotiator enforces version compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NegotiationPolicy {
    /// Require exact major version match and peer >= our version.
    Strict,
    /// Accept any remote version that is >= our local version, ignoring major
    /// differences.  A remote advertising version 1.0 connecting to a local
    /// 2.0 endpoint will **fail** under Lenient (1.0 < 2.0), while a remote
    /// advertising 3.0 will succeed.  If you need to accept older clients
    /// unconditionally use [`NegotiationPolicy::Accept`].
    Lenient,
    /// Accept all versions without checking.
    Accept,
}

// ─── McpCapabilityNegotiator ──────────────────────────────────────────────────

/// Negotiates capabilities between a local and a remote endpoint.
///
/// Call [`McpCapabilityNegotiator::negotiate`] with the remote's [`Capabilities`]
/// to obtain a [`NegotiationResult`] describing what both parties agreed upon.
#[derive(Debug, Clone)]
pub struct McpCapabilityNegotiator {
    /// Our local capabilities.
    local: Capabilities,
    /// The policy used for version compatibility checks.
    pub policy: NegotiationPolicy,
}

impl McpCapabilityNegotiator {
    /// Create a negotiator advertising `local` capabilities.
    #[must_use]
    pub fn new(local: Capabilities) -> Self {
        Self {
            local,
            policy: NegotiationPolicy::Strict,
        }
    }

    /// Set the negotiation policy.
    #[must_use]
    pub fn with_policy(mut self, policy: NegotiationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Retrieve the local capability set.
    #[must_use]
    pub fn local(&self) -> &Capabilities {
        &self.local
    }

    /// Negotiate against a remote [`Capabilities`] advertisement.
    ///
    /// Algorithm:
    /// 1. Check protocol version compatibility.
    /// 2. For each capability in `local`:
    ///    - If required: must be present on remote with a compatible version.
    ///    - If optional: record in `local_only` if absent on remote.
    /// 3. Record any extra remote capabilities in `remote_only`.
    ///
    /// # Errors
    /// Returns [`NegotiationError`] if a required capability is missing or
    /// versions are incompatible.
    pub fn negotiate(
        &self,
        remote: &Capabilities,
    ) -> Result<NegotiationResult, NegotiationError> {
        // Step 1 — Protocol version check.
        let proto_ok = match self.policy {
            NegotiationPolicy::Strict => {
                remote
                    .protocol_version
                    .is_compatible_with(&self.local.protocol_version)
            }
            NegotiationPolicy::Lenient => {
                remote.protocol_version >= self.local.protocol_version
            }
            NegotiationPolicy::Accept => true,
        };

        if !proto_ok {
            return Err(NegotiationError::IncompatibleProtocol {
                client: remote.protocol_version,
                server: self.local.protocol_version,
            });
        }

        // Use the minimum of the two protocol versions as the agreed one.
        let agreed_proto = self
            .local
            .protocol_version
            .min(remote.protocol_version);

        let mut agreed = HashMap::new();
        let mut local_only = HashSet::new();
        let mut errors: Vec<NegotiationError> = Vec::new();

        // Step 2 — Check each local capability against the remote set.
        for (name, local_cap) in &self.local.capabilities {
            if let Some(remote_cap) = remote.capabilities.get(name) {
                // Capability present on both sides — check version.
                let version_ok = match self.policy {
                    NegotiationPolicy::Accept => true,
                    NegotiationPolicy::Lenient => {
                        remote_cap.version >= local_cap.version
                    }
                    NegotiationPolicy::Strict => {
                        remote_cap.version.is_compatible_with(&local_cap.version)
                    }
                };

                if version_ok {
                    // Use the minimum version as the agreed capability.
                    let mut agreed_cap = local_cap.clone();
                    agreed_cap.version = local_cap.version.min(remote_cap.version);
                    agreed.insert(name.clone(), agreed_cap);
                } else {
                    let err = NegotiationError::VersionConflict {
                        name: name.clone(),
                        required: local_cap.version,
                        offered: remote_cap.version,
                    };
                    if local_cap.optional {
                        // Version conflict on optional — just skip it.
                        local_only.insert(name.clone());
                    } else {
                        errors.push(err);
                    }
                }
            } else {
                // Remote does not have this capability.
                if local_cap.optional {
                    local_only.insert(name.clone());
                } else {
                    errors.push(NegotiationError::MissingRequiredCapability(name.clone()));
                }
            }
        }

        // If any required caps failed, return the first error.
        if let Some(err) = errors.into_iter().next() {
            return Err(err);
        }

        // Step 3 — Collect remote-only capabilities.
        let remote_only: HashSet<String> = remote
            .capabilities
            .keys()
            .filter(|n| !self.local.capabilities.contains_key(*n))
            .cloned()
            .collect();

        let summary = format!(
            "Negotiated {} capabilities (proto={}, local_only={}, remote_only={})",
            agreed.len(),
            agreed_proto,
            local_only.len(),
            remote_only.len()
        );

        Ok(NegotiationResult {
            protocol_version: agreed_proto,
            agreed,
            remote_only,
            local_only,
            success: true,
            summary,
        })
    }

    /// Check whether the remote supports a specific named capability at any version.
    #[must_use]
    pub fn remote_has(remote: &Capabilities, name: &str) -> bool {
        remote.has(name)
    }

    /// Produce a capability advertisement for a typical MCP client.
    #[must_use]
    pub fn client_default() -> Capabilities {
        Capabilities::new("MCP-Client", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"))
            .with(Capability::optional("streaming", "1.0.0"))
            .with(Capability::optional("batch", "1.0.0"))
    }
}

// ─── CapabilityMatrix ─────────────────────────────────────────────────────────

/// A matrix recording which capabilities are available for each registered peer.
#[derive(Debug, Clone, Default)]
pub struct CapabilityMatrix {
    /// peer_id → NegotiationResult
    peers: HashMap<String, NegotiationResult>,
}

impl CapabilityMatrix {
    /// Create an empty matrix.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the negotiation result for a peer.
    pub fn record(&mut self, peer_id: impl Into<String>, result: NegotiationResult) {
        self.peers.insert(peer_id.into(), result);
    }

    /// Look up the negotiation result for a peer.
    #[must_use]
    pub fn get(&self, peer_id: &str) -> Option<&NegotiationResult> {
        self.peers.get(peer_id)
    }

    /// Return all peer IDs.
    #[must_use]
    pub fn peer_ids(&self) -> Vec<&str> {
        self.peers.keys().map(String::as_str).collect()
    }

    /// Number of peers in the matrix.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Return all peers that have agreed on the given capability.
    #[must_use]
    pub fn peers_with_capability(&self, cap: &str) -> Vec<&str> {
        self.peers
            .iter()
            .filter(|(_, r)| r.has_agreed(cap))
            .map(|(id, _)| id.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_caps() -> Capabilities {
        Capabilities::new("server", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"))
            .with(Capability::required("resources", "1.0.0"))
            .with(Capability::optional("streaming", "1.0.0"))
    }

    fn remote_full() -> Capabilities {
        Capabilities::new("client", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"))
            .with(Capability::required("resources", "1.0.0"))
            .with(Capability::optional("streaming", "1.0.0"))
            .with(Capability::optional("extra", "2.0.0"))
    }

    #[test]
    fn test_full_negotiation_success() {
        let neg = McpCapabilityNegotiator::new(local_caps());
        let result = neg.negotiate(&remote_full()).unwrap();
        assert!(result.success);
        assert!(result.has_agreed("tools"));
        assert!(result.has_agreed("resources"));
        assert!(result.has_agreed("streaming"));
        assert!(result.remote_only.contains("extra"));
        assert!(result.local_only.is_empty());
    }

    #[test]
    fn test_missing_required_capability() {
        let local = Capabilities::new("s", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"))
            .with(Capability::required("must_have", "1.0.0"));
        let remote = Capabilities::new("c", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"));
        let neg = McpCapabilityNegotiator::new(local);
        let err = neg.negotiate(&remote).unwrap_err();
        assert!(matches!(err, NegotiationError::MissingRequiredCapability(_)));
    }

    #[test]
    fn test_optional_missing_is_ok() {
        let local = Capabilities::new("s", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"))
            .with(Capability::optional("streaming", "1.0.0"));
        let remote = Capabilities::new("c", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0"));
        let neg = McpCapabilityNegotiator::new(local);
        let result = neg.negotiate(&remote).unwrap();
        assert!(result.success);
        assert!(!result.has_agreed("streaming"));
        assert!(result.local_only.contains("streaming"));
    }

    #[test]
    fn test_version_conflict_required() {
        let local = Capabilities::new("s", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "2.0.0")); // want 2.x
        let remote = Capabilities::new("c", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.0.0")); // only has 1.x
        let neg = McpCapabilityNegotiator::new(local);
        let err = neg.negotiate(&remote).unwrap_err();
        assert!(matches!(err, NegotiationError::VersionConflict { .. }));
    }

    #[test]
    fn test_incompatible_protocol() {
        let local = Capabilities::new("s", CapabilityVersion::new(2, 0, 0));
        let remote = Capabilities::new("c", CapabilityVersion::new(1, 0, 0));
        let neg = McpCapabilityNegotiator::new(local);
        let err = neg.negotiate(&remote).unwrap_err();
        assert!(matches!(err, NegotiationError::IncompatibleProtocol { .. }));
    }

    #[test]
    fn test_lenient_policy_accepts_older() {
        let local = Capabilities::new("s", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("tools", "1.5.0"));
        let remote = Capabilities::new("c", CapabilityVersion::new(1, 2, 0))
            .with(Capability::required("tools", "1.5.0"));
        let neg = McpCapabilityNegotiator::new(local).with_policy(NegotiationPolicy::Lenient);
        let result = neg.negotiate(&remote).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_capability_matrix() {
        let neg = McpCapabilityNegotiator::new(local_caps());
        let result = neg.negotiate(&remote_full()).unwrap();
        let mut matrix = CapabilityMatrix::new();
        matrix.record("peer-1", result);
        assert_eq!(matrix.len(), 1);
        let peers = matrix.peers_with_capability("tools");
        assert!(peers.contains(&"peer-1"));
    }

    #[test]
    fn test_capability_version_parse() {
        let v = CapabilityVersion::parse("2.3.4").unwrap();
        assert_eq!(v, CapabilityVersion::new(2, 3, 4));
    }

    #[test]
    fn test_capability_version_compatibility() {
        let v1 = CapabilityVersion::new(1, 5, 0);
        let v2 = CapabilityVersion::new(1, 3, 0);
        assert!(v1.is_compatible_with(&v2)); // 1.5 >= 1.3 same major
        assert!(!v2.is_compatible_with(&v1)); // 1.3 < 1.5

        let v3 = CapabilityVersion::new(2, 0, 0);
        assert!(!v1.is_compatible_with(&v3)); // different major
    }

    #[test]
    fn test_rustre_defaults() {
        let caps = Capabilities::rustre_defaults();
        assert!(caps.has("tools"));
        assert!(caps.has("resources"));
        assert!(caps.has("streaming"));
    }

    #[test]
    fn test_accept_policy_ignores_versions() {
        let local = Capabilities::new("s", CapabilityVersion::new(3, 0, 0))
            .with(Capability::required("x", "3.0.0"));
        let remote = Capabilities::new("c", CapabilityVersion::new(1, 0, 0))
            .with(Capability::required("x", "1.0.0"));
        let neg = McpCapabilityNegotiator::new(local).with_policy(NegotiationPolicy::Accept);
        let result = neg.negotiate(&remote).unwrap();
        assert!(result.success);
        assert!(result.has_agreed("x"));
    }
}
