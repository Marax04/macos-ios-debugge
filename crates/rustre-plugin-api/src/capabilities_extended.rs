//! `capabilities_extended` — Extended plugin capabilities system.
//!
//! Provides `CapabilityRegistry`, `RequiredCapability`, `OptionalCapability`,
//! `CapabilityNegotiation`, `CapabilityToken`, `CapabilityDelegation`.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the extended capability system.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("capability not registered: '{0}'")]
    NotRegistered(String),
    #[error("capability already registered: '{0}'")]
    AlreadyRegistered(String),
    #[error("capability denied: '{0}'")]
    Denied(String),
    #[error("token expired")]
    TokenExpired,
    #[error("token invalid: {0}")]
    TokenInvalid(String),
    #[error("delegation chain too deep ({0})")]
    DelegationDepth(usize),
    #[error("negotiation failed: {0}")]
    NegotiationFailed(String),
    #[error("plugin not found: '{0}'")]
    PluginNotFound(String),
}

// ─── CapabilityId ─────────────────────────────────────────────────────────────

/// Unique identifier for a capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityId(pub String);

impl CapabilityId {
    /// Create from a string.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }

    /// Return the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

impl From<&str> for CapabilityId {
    fn from(s: &str) -> Self { Self::new(s) }
}

// ─── CapabilitySpec ───────────────────────────────────────────────────────────

/// Specification of a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySpec {
    /// Unique capability ID.
    pub id: CapabilityId,
    /// Human-readable name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Semantic version.
    pub version: String,
    /// Whether this capability can be delegated.
    pub delegatable: bool,
    /// Whether granting this capability allows reading sensitive data.
    pub sensitive: bool,
    /// Minimum trust level required to grant this capability.
    pub min_trust_level: TrustLevel,
}

impl CapabilitySpec {
    /// Create a new capability spec.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            id: CapabilityId::new(id),
            name: name.into(),
            description: description.into(),
            version: version.into(),
            delegatable: true,
            sensitive: false,
            min_trust_level: TrustLevel::Basic,
        }
    }

    /// Builder: make non-delegatable.
    #[must_use]
    pub const fn non_delegatable(mut self) -> Self { self.delegatable = false; self }

    /// Builder: mark as sensitive.
    #[must_use]
    pub const fn sensitive(mut self) -> Self { self.sensitive = true; self }

    /// Builder: set minimum trust level.
    #[must_use]
    pub const fn require_trust(mut self, level: TrustLevel) -> Self {
        self.min_trust_level = level; self
    }
}

// ─── TrustLevel ───────────────────────────────────────────────────────────────

/// Trust level required or possessed by a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    Sandbox,
    Basic,
    Elevated,
    System,
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self { Self::Sandbox => "sandbox", Self::Basic => "basic",
            Self::Elevated => "elevated", Self::System => "system" };
        f.write_str(s)
    }
}

// ─── RequiredCapability ───────────────────────────────────────────────────────

/// A capability that a plugin requires in order to function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredCapability {
    pub id: CapabilityId,
    pub reason: String,
}

impl RequiredCapability {
    #[must_use]
    pub fn new(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { id: CapabilityId::new(id), reason: reason.into() }
    }
}

// ─── OptionalCapability ───────────────────────────────────────────────────────

/// A capability that a plugin can use if granted but can operate without.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionalCapability {
    pub id: CapabilityId,
    pub reason: String,
    /// What additional functionality is enabled if this is granted.
    pub enables: String,
}

impl OptionalCapability {
    #[must_use]
    pub fn new(id: impl Into<String>, reason: impl Into<String>, enables: impl Into<String>) -> Self {
        Self { id: CapabilityId::new(id), reason: reason.into(), enables: enables.into() }
    }
}

// ─── CapabilityToken ──────────────────────────────────────────────────────────

/// An unforgeable proof that a capability has been granted to a specific plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Token ID (unique).
    pub token_id: u64,
    /// Capability this token grants.
    pub capability_id: CapabilityId,
    /// Plugin ID this token is issued to.
    pub grantee: String,
    /// Plugin ID that issued this token.
    pub issuer: String,
    /// Expiry timestamp (Unix seconds, 0 = no expiry).
    pub expires_at: u64,
    /// Delegation depth (0 = direct grant, N = delegated N times).
    pub delegation_depth: usize,
    /// Revoked flag.
    pub revoked: bool,
    /// Metadata.
    pub metadata: HashMap<String, String>,
}

impl CapabilityToken {
    /// Create a new token.
    #[must_use]
    pub fn new(
        token_id: u64,
        capability_id: CapabilityId,
        grantee: impl Into<String>,
        issuer: impl Into<String>,
        ttl_secs: u64,
    ) -> Self {
        let expires_at = if ttl_secs == 0 { 0 } else {
            SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) + ttl_secs
        };
        Self {
            token_id, capability_id, grantee: grantee.into(), issuer: issuer.into(),
            expires_at, delegation_depth: 0, revoked: false, metadata: HashMap::new(),
        }
    }

    /// Return `true` if the token is valid (not expired and not revoked).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.revoked { return false; }
        if self.expires_at == 0 { return true; }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        now < self.expires_at
    }

    /// Revoke this token.
    pub const fn revoke(&mut self) { self.revoked = true; }

    /// Add metadata.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

impl fmt::Display for CapabilityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token[{}] cap={} grantee={} valid={}", self.token_id, self.capability_id, self.grantee, self.is_valid())
    }
}

// ─── CapabilityDelegation ────────────────────────────────────────────────────

/// Describes the delegation of a sub-capability from one plugin to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDelegation {
    /// Token being delegated.
    pub source_token_id: u64,
    /// New token issued to the delegate.
    pub delegated_token_id: u64,
    /// Delegating plugin.
    pub delegator: String,
    /// Receiving plugin.
    pub delegate: String,
    /// Capability being delegated.
    pub capability_id: CapabilityId,
    /// New depth in the delegation chain.
    pub depth: usize,
    /// Timestamp of delegation.
    pub timestamp: u64,
    /// Whether the delegate can further delegate.
    pub re_delegatable: bool,
}

impl CapabilityDelegation {
    /// Create a new delegation record.
    #[must_use]
    pub fn new(
        source_token_id: u64,
        delegated_token_id: u64,
        delegator: impl Into<String>,
        delegate: impl Into<String>,
        capability_id: CapabilityId,
        depth: usize,
    ) -> Self {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Self {
            source_token_id, delegated_token_id,
            delegator: delegator.into(), delegate: delegate.into(),
            capability_id, depth, timestamp: ts, re_delegatable: true,
        }
    }
}

// ─── NegotiationRequest ───────────────────────────────────────────────────────

/// Request sent by a plugin during capability negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationRequest {
    /// Requesting plugin ID.
    pub plugin_id: String,
    /// Required capabilities.
    pub required: Vec<RequiredCapability>,
    /// Optional capabilities.
    pub optional: Vec<OptionalCapability>,
    /// Plugin's trust level.
    pub trust_level: TrustLevel,
}

/// Result of a capability negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationResult {
    pub plugin_id: String,
    /// Granted tokens, keyed by capability ID.
    pub granted: HashMap<String, CapabilityToken>,
    /// Required capabilities that were denied.
    pub denied_required: Vec<CapabilityId>,
    /// Optional capabilities that were not granted.
    pub not_granted_optional: Vec<CapabilityId>,
    /// Whether all required capabilities were granted.
    pub success: bool,
}

impl NegotiationResult {
    /// Return `true` if the plugin can proceed (all required capabilities granted).
    #[must_use]
    pub const fn can_proceed(&self) -> bool { self.success }

    /// Return a token for the given capability, if granted.
    #[must_use]
    pub fn get_token(&self, cap_id: &str) -> Option<&CapabilityToken> {
        self.granted.get(cap_id)
    }

    /// Number of granted capabilities.
    #[must_use]
    pub fn granted_count(&self) -> usize { self.granted.len() }
}

// ─── CapabilityNegotiation ────────────────────────────────────────────────────

/// Handles the handshake between a plugin and the host.
pub struct CapabilityNegotiation {
    /// Maximum delegation depth.
    pub max_delegation_depth: usize,
    /// Default token TTL in seconds.
    pub default_ttl_secs: u64,
}

impl CapabilityNegotiation {
    /// Create a new negotiation handler.
    #[must_use]
    pub const fn new() -> Self {
        Self { max_delegation_depth: 3, default_ttl_secs: 3600 }
    }

    /// Negotiate capabilities for a plugin.
    ///
    /// # Errors
    /// Returns `CapabilityError::NegotiationFailed` if required capabilities cannot be granted.
    pub fn negotiate(
        &self,
        request: &NegotiationRequest,
        registry: &CapabilityRegistry,
        token_counter: &mut u64,
    ) -> Result<NegotiationResult, CapabilityError> {
        let mut granted = HashMap::new();
        let mut denied_required = Vec::new();
        let mut not_granted_optional = Vec::new();

        // Process required capabilities
        for req in &request.required {
            match registry.check_grant(&req.id, &request.plugin_id, request.trust_level) {
                Ok(()) => {
                    *token_counter += 1;
                    let token = CapabilityToken::new(
                        *token_counter,
                        req.id.clone(),
                        &request.plugin_id,
                        "host",
                        self.default_ttl_secs,
                    );
                    granted.insert(req.id.as_str().to_string(), token);
                }
                Err(_) => {
                    denied_required.push(req.id.clone());
                }
            }
        }

        // Process optional capabilities
        for opt in &request.optional {
            match registry.check_grant(&opt.id, &request.plugin_id, request.trust_level) {
                Ok(()) => {
                    *token_counter += 1;
                    let token = CapabilityToken::new(
                        *token_counter,
                        opt.id.clone(),
                        &request.plugin_id,
                        "host",
                        self.default_ttl_secs,
                    );
                    granted.insert(opt.id.as_str().to_string(), token);
                }
                Err(_) => {
                    not_granted_optional.push(opt.id.clone());
                }
            }
        }

        let success = denied_required.is_empty();
        Ok(NegotiationResult {
            plugin_id: request.plugin_id.clone(),
            granted, denied_required, not_granted_optional, success,
        })
    }
}

impl Default for CapabilityNegotiation {
    fn default() -> Self { Self::new() }
}

// ─── CapabilityRegistry ───────────────────────────────────────────────────────

/// Dynamic registry for capability definitions and grant policies.
pub struct CapabilityRegistry {
    specs: HashMap<String, CapabilitySpec>,
    allow_lists: HashMap<String, HashSet<String>>,
    deny_lists: HashMap<String, HashSet<String>>,
    tokens: Arc<Mutex<Vec<CapabilityToken>>>,
    delegations: Arc<Mutex<Vec<CapabilityDelegation>>>,
    token_counter: Arc<Mutex<u64>>,
}

impl CapabilityRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            specs: HashMap::new(),
            allow_lists: HashMap::new(),
            deny_lists: HashMap::new(),
            tokens: Arc::new(Mutex::new(Vec::new())),
            delegations: Arc::new(Mutex::new(Vec::new())),
            token_counter: Arc::new(Mutex::new(0)),
        }
    }

    /// Register a capability specification.
    ///
    /// # Errors
    /// Returns `CapabilityError::AlreadyRegistered` if already present.
    pub fn register(&mut self, spec: CapabilitySpec) -> Result<(), CapabilityError> {
        let key = spec.id.0.clone();
        if self.specs.contains_key(&key) {
            return Err(CapabilityError::AlreadyRegistered(key));
        }
        self.specs.insert(key, spec);
        Ok(())
    }

    /// Register or replace a capability spec.
    pub fn register_or_replace(&mut self, spec: CapabilitySpec) {
        self.specs.insert(spec.id.0.clone(), spec);
    }

    /// Find a capability spec by ID.
    #[must_use]
    pub fn find(&self, id: &CapabilityId) -> Option<&CapabilitySpec> {
        self.specs.get(id.as_str())
    }

    /// Return `true` if the capability is registered.
    #[must_use]
    pub fn is_registered(&self, id: &CapabilityId) -> bool {
        self.specs.contains_key(id.as_str())
    }

    /// Add a plugin to the allow-list for a capability.
    pub fn allow(&mut self, cap_id: &str, plugin_id: impl Into<String>) {
        self.allow_lists.entry(cap_id.to_string()).or_default().insert(plugin_id.into());
    }

    /// Add a plugin to the deny-list for a capability.
    pub fn deny(&mut self, cap_id: &str, plugin_id: impl Into<String>) {
        self.deny_lists.entry(cap_id.to_string()).or_default().insert(plugin_id.into());
    }

    /// Check whether a plugin can be granted a capability.
    ///
    /// # Errors
    /// Returns `CapabilityError::NotRegistered` or `CapabilityError::Denied` on failure.
    pub fn check_grant(
        &self,
        cap_id: &CapabilityId,
        plugin_id: &str,
        trust_level: TrustLevel,
    ) -> Result<(), CapabilityError> {
        let spec = self.find(cap_id)
            .ok_or_else(|| CapabilityError::NotRegistered(cap_id.to_string()))?;

        // Check trust level
        if trust_level < spec.min_trust_level {
            return Err(CapabilityError::Denied(format!(
                "insufficient trust level: have {trust_level}, need {}", spec.min_trust_level
            )));
        }

        // Check deny list
        if let Some(denied) = self.deny_lists.get(cap_id.as_str())
            && denied.contains(plugin_id) {
                return Err(CapabilityError::Denied(format!("plugin '{plugin_id}' is denied '{cap_id}'")));
            }

        // Check allow list (if non-empty, plugin must be listed)
        if let Some(allowed) = self.allow_lists.get(cap_id.as_str())
            && !allowed.is_empty() && !allowed.contains(plugin_id) {
                return Err(CapabilityError::Denied(format!("plugin '{plugin_id}' not in allow-list for '{cap_id}'")));
            }

        Ok(())
    }

    /// Grant a capability token to a plugin.
    ///
    /// # Errors
    /// Returns `CapabilityError` if the grant is not permitted.
    pub fn grant(
        &self,
        cap_id: &CapabilityId,
        plugin_id: &str,
        trust_level: TrustLevel,
        ttl_secs: u64,
    ) -> Result<CapabilityToken, CapabilityError> {
        self.check_grant(cap_id, plugin_id, trust_level)?;
        let mut counter = self.token_counter.lock().unwrap();
        *counter += 1;
        let token = CapabilityToken::new(*counter, cap_id.clone(), plugin_id, "host", ttl_secs);
        self.tokens.lock().unwrap().push(token.clone());
        Ok(token)
    }

    /// Revoke a token by ID.
    pub fn revoke_token(&self, token_id: u64) {
        let mut tokens = self.tokens.lock().unwrap();
        if let Some(t) = tokens.iter_mut().find(|t| t.token_id == token_id) {
            t.revoke();
        }
    }

    /// Delegate a capability from one plugin to another.
    ///
    /// # Errors
    /// Returns `CapabilityError::DelegationDepth` if the chain is too deep,
    /// or `CapabilityError::Denied` if the capability is not delegatable.
    pub fn delegate(
        &self,
        source_token_id: u64,
        delegator: &str,
        delegate: &str,
        max_depth: usize,
        ttl_secs: u64,
    ) -> Result<CapabilityToken, CapabilityError> {
        // Extract all needed fields from the tokens lock into local variables,
        // then release the lock before calling self.find() or any other method
        // that might need to re-acquire a lock, to avoid potential deadlocks.
        let (cap_id, new_depth, is_valid) = {
            let tokens = self.tokens.lock().unwrap();
            let source = tokens.iter()
                .find(|t| t.token_id == source_token_id && t.grantee == delegator)
                .ok_or_else(|| CapabilityError::TokenInvalid(format!("token {source_token_id} not found for {delegator}")))?;
            (source.capability_id.clone(), source.delegation_depth + 1, source.is_valid())
            // lock released here
        };

        if !is_valid {
            return Err(CapabilityError::TokenExpired);
        }
        if new_depth > max_depth {
            return Err(CapabilityError::DelegationDepth(new_depth - 1));
        }
        // self.find() accesses self.specs (not self.tokens), but calling it
        // with the tokens lock dropped is safe and avoids accidental re-entrant locking.
        let delegatable = self.find(&cap_id)
            .ok_or_else(|| CapabilityError::NotRegistered(cap_id.to_string()))?.delegatable;
        if !delegatable {
            return Err(CapabilityError::Denied(format!("'{cap_id}' is not delegatable")));
        }

        let mut counter = self.token_counter.lock().unwrap();
        *counter += 1;
        let new_token_id = *counter;
        drop(counter);

        let mut new_token = CapabilityToken::new(new_token_id, cap_id.clone(), delegate, delegator, ttl_secs);
        new_token.delegation_depth = new_depth;

        let delegation = CapabilityDelegation::new(
            source_token_id, new_token_id, delegator, delegate, cap_id, new_depth,
        );
        self.tokens.lock().unwrap().push(new_token.clone());
        self.delegations.lock().unwrap().push(delegation);
        Ok(new_token)
    }

    /// Return all active (non-revoked, non-expired) tokens for a plugin.
    #[must_use]
    pub fn active_tokens_for(&self, plugin_id: &str) -> Vec<CapabilityToken> {
        self.tokens.lock().unwrap()
            .iter()
            .filter(|t| t.grantee == plugin_id && t.is_valid())
            .cloned()
            .collect()
    }

    /// Return all registered capability IDs.
    #[must_use]
    pub fn capability_ids(&self) -> Vec<CapabilityId> {
        self.specs.keys().map(CapabilityId::new).collect()
    }

    /// Number of registered capabilities.
    #[must_use]
    pub fn count(&self) -> usize { self.specs.len() }
}

impl Default for CapabilityRegistry {
    fn default() -> Self { Self::new() }
}

impl fmt::Debug for CapabilityRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityRegistry({} caps)", self.specs.len())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_with_caps() -> CapabilityRegistry {
        let mut r = CapabilityRegistry::new();
        r.register(CapabilitySpec::new("read_binary", "Read Binary", "Read binary data", "1.0")).unwrap();
        r.register(CapabilitySpec::new("write_binary", "Write Binary", "Patch binary data", "1.0")
            .require_trust(TrustLevel::Elevated)).unwrap();
        r.register(CapabilitySpec::new("debug_attach", "Debug Attach", "Attach debugger", "1.0")
            .sensitive()
            .require_trust(TrustLevel::Elevated)).unwrap();
        r.register(CapabilitySpec::new("network", "Network", "Network access", "1.0")
            .non_delegatable()).unwrap();
        r
    }

    // ── CapabilityId ──────────────────────────────────────────────────────────

    #[test]
    fn test_cap_id_display() {
        let id = CapabilityId::new("my_cap");
        assert_eq!(id.to_string(), "my_cap");
    }

    #[test]
    fn test_cap_id_from_str() {
        let id = CapabilityId::from("test");
        assert_eq!(id.as_str(), "test");
    }

    // ── TrustLevel ────────────────────────────────────────────────────────────

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::System > TrustLevel::Elevated);
        assert!(TrustLevel::Elevated > TrustLevel::Basic);
        assert!(TrustLevel::Basic > TrustLevel::Sandbox);
    }

    #[test]
    fn test_trust_level_display() {
        assert_eq!(TrustLevel::System.to_string(), "system");
    }

    // ── CapabilitySpec ────────────────────────────────────────────────────────

    #[test]
    fn test_spec_new_defaults() {
        let s = CapabilitySpec::new("x", "X", "desc", "1.0");
        assert!(s.delegatable);
        assert!(!s.sensitive);
        assert_eq!(s.min_trust_level, TrustLevel::Basic);
    }

    #[test]
    fn test_spec_non_delegatable() {
        let s = CapabilitySpec::new("x", "X", "", "1.0").non_delegatable();
        assert!(!s.delegatable);
    }

    #[test]
    fn test_spec_sensitive() {
        let s = CapabilitySpec::new("x", "X", "", "1.0").sensitive();
        assert!(s.sensitive);
    }

    // ── CapabilityToken ───────────────────────────────────────────────────────

    #[test]
    fn test_token_valid_no_expiry() {
        let t = CapabilityToken::new(1, CapabilityId::new("x"), "plugin_a", "host", 0);
        assert!(t.is_valid());
    }

    #[test]
    fn test_token_valid_with_ttl() {
        let t = CapabilityToken::new(2, CapabilityId::new("x"), "plugin_a", "host", 3600);
        assert!(t.is_valid());
    }

    #[test]
    fn test_token_revoked() {
        let mut t = CapabilityToken::new(3, CapabilityId::new("x"), "p", "h", 0);
        t.revoke();
        assert!(!t.is_valid());
    }

    #[test]
    fn test_token_display() {
        let t = CapabilityToken::new(5, CapabilityId::new("read_binary"), "plugin", "host", 0);
        assert!(t.to_string().contains("plugin"));
    }

    #[test]
    fn test_token_add_meta() {
        let mut t = CapabilityToken::new(1, CapabilityId::new("x"), "p", "h", 0);
        t.add_meta("key", "value");
        assert_eq!(t.metadata["key"], "value");
    }

    // ── CapabilityRegistry ────────────────────────────────────────────────────

    #[test]
    fn test_registry_register_success() {
        let mut r = CapabilityRegistry::new();
        r.register(CapabilitySpec::new("x", "X", "", "1.0")).unwrap();
        assert!(r.is_registered(&CapabilityId::new("x")));
    }

    #[test]
    fn test_registry_duplicate_error() {
        let mut r = CapabilityRegistry::new();
        r.register(CapabilitySpec::new("x", "X", "", "1.0")).unwrap();
        let result = r.register(CapabilitySpec::new("x", "X", "", "1.0"));
        assert!(matches!(result, Err(CapabilityError::AlreadyRegistered(_))));
    }

    #[test]
    fn test_registry_find() {
        let r = reg_with_caps();
        assert!(r.find(&CapabilityId::new("read_binary")).is_some());
        assert!(r.find(&CapabilityId::new("nonexistent")).is_none());
    }

    #[test]
    fn test_registry_grant_basic_ok() {
        let r = reg_with_caps();
        let token = r.grant(&CapabilityId::new("read_binary"), "plugin_a", TrustLevel::Basic, 3600).unwrap();
        assert!(token.is_valid());
        assert_eq!(token.grantee, "plugin_a");
    }

    #[test]
    fn test_registry_grant_insufficient_trust() {
        let r = reg_with_caps();
        let result = r.grant(&CapabilityId::new("write_binary"), "plugin_a", TrustLevel::Basic, 3600);
        assert!(matches!(result, Err(CapabilityError::Denied(_))));
    }

    #[test]
    fn test_registry_grant_elevated_ok() {
        let r = reg_with_caps();
        let token = r.grant(&CapabilityId::new("write_binary"), "plugin_a", TrustLevel::Elevated, 3600).unwrap();
        assert!(token.is_valid());
    }

    #[test]
    fn test_registry_allow_list() {
        let mut r = reg_with_caps();
        r.allow("read_binary", "trusted_plugin");
        // plugin_a not in allow list → denied
        let result = r.check_grant(&CapabilityId::new("read_binary"), "plugin_a", TrustLevel::Basic);
        assert!(result.is_err());
        // trusted_plugin in allow list → ok
        let result2 = r.check_grant(&CapabilityId::new("read_binary"), "trusted_plugin", TrustLevel::Basic);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_registry_deny_list() {
        let mut r = reg_with_caps();
        r.deny("read_binary", "bad_plugin");
        let result = r.check_grant(&CapabilityId::new("read_binary"), "bad_plugin", TrustLevel::Basic);
        assert!(result.is_err());
        // other plugin ok
        let result2 = r.check_grant(&CapabilityId::new("read_binary"), "good_plugin", TrustLevel::Basic);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_registry_revoke() {
        let r = reg_with_caps();
        let t = r.grant(&CapabilityId::new("read_binary"), "p", TrustLevel::Basic, 3600).unwrap();
        let id = t.token_id;
        r.revoke_token(id);
        let active = r.active_tokens_for("p");
        assert!(active.is_empty());
    }

    #[test]
    fn test_registry_active_tokens() {
        let r = reg_with_caps();
        r.grant(&CapabilityId::new("read_binary"), "p", TrustLevel::Basic, 3600).unwrap();
        let tokens = r.active_tokens_for("p");
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn test_registry_count() {
        let r = reg_with_caps();
        assert_eq!(r.count(), 4);
    }

    // ── Delegation ────────────────────────────────────────────────────────────

    #[test]
    fn test_delegation_basic() {
        let r = reg_with_caps();
        let t = r.grant(&CapabilityId::new("read_binary"), "plugin_a", TrustLevel::Basic, 3600).unwrap();
        let delegated = r.delegate(t.token_id, "plugin_a", "plugin_b", 3, 1800).unwrap();
        assert_eq!(delegated.grantee, "plugin_b");
        assert_eq!(delegated.delegation_depth, 1);
    }

    #[test]
    fn test_delegation_non_delegatable() {
        let r = reg_with_caps();
        let t = r.grant(&CapabilityId::new("network"), "plugin_a", TrustLevel::Basic, 3600).unwrap();
        let result = r.delegate(t.token_id, "plugin_a", "plugin_b", 3, 1800);
        assert!(matches!(result, Err(CapabilityError::Denied(_))));
    }

    #[test]
    fn test_delegation_depth_exceeded() {
        let r = reg_with_caps();
        let t = r.grant(&CapabilityId::new("read_binary"), "pa", TrustLevel::Basic, 3600).unwrap();
        let t2 = r.delegate(t.token_id, "pa", "pb", 3, 1800).unwrap();
        let t3 = r.delegate(t2.token_id, "pb", "pc", 3, 1800).unwrap();
        let t4 = r.delegate(t3.token_id, "pc", "pd", 3, 1800).unwrap();
        // Depth is now 3, next attempt at max=3 should fail
        let result = r.delegate(t4.token_id, "pd", "pe", 3, 1800);
        assert!(matches!(result, Err(CapabilityError::DelegationDepth(_))));
    }

    // ── CapabilityNegotiation ────────────────────────────────────────────────

    #[test]
    fn test_negotiation_all_required_granted() {
        let r = reg_with_caps();
        let mut counter = 0u64;
        let negotiation = CapabilityNegotiation::new();
        let request = NegotiationRequest {
            plugin_id: "plugin_x".into(),
            required: vec![RequiredCapability::new("read_binary", "need it")],
            optional: vec![OptionalCapability::new("network", "nice to have", "network ops")],
            trust_level: TrustLevel::Basic,
        };
        let result = negotiation.negotiate(&request, &r, &mut counter).unwrap();
        assert!(result.can_proceed());
        assert!(result.get_token("read_binary").is_some());
    }

    #[test]
    fn test_negotiation_required_denied() {
        let r = reg_with_caps();
        let mut counter = 0u64;
        let negotiation = CapabilityNegotiation::new();
        let request = NegotiationRequest {
            plugin_id: "plugin_y".into(),
            required: vec![RequiredCapability::new("write_binary", "need it")],
            optional: vec![],
            trust_level: TrustLevel::Basic, // insufficient
        };
        let result = negotiation.negotiate(&request, &r, &mut counter).unwrap();
        assert!(!result.can_proceed());
        assert!(!result.denied_required.is_empty());
    }

    #[test]
    fn test_negotiation_optional_not_granted_ok() {
        let r = reg_with_caps();
        let mut counter = 0u64;
        let negotiation = CapabilityNegotiation::new();
        let request = NegotiationRequest {
            plugin_id: "plugin_z".into(),
            required: vec![RequiredCapability::new("read_binary", "essential")],
            optional: vec![OptionalCapability::new("write_binary", "nice", "patching")],
            trust_level: TrustLevel::Basic,
        };
        let result = negotiation.negotiate(&request, &r, &mut counter).unwrap();
        // Required granted, optional not (insufficient trust)
        assert!(result.can_proceed());
        assert!(!result.not_granted_optional.is_empty());
    }

    #[test]
    fn test_negotiation_granted_count() {
        let r = reg_with_caps();
        let mut counter = 0u64;
        let negotiation = CapabilityNegotiation::new();
        let request = NegotiationRequest {
            plugin_id: "p".into(),
            required: vec![
                RequiredCapability::new("read_binary", "r1"),
                RequiredCapability::new("network", "r2"),
            ],
            optional: vec![],
            trust_level: TrustLevel::Basic,
        };
        let result = negotiation.negotiate(&request, &r, &mut counter).unwrap();
        assert_eq!(result.granted_count(), 2);
    }

    #[test]
    fn test_required_capability_new() {
        let rc = RequiredCapability::new("x", "need x for Y");
        assert_eq!(rc.id.as_str(), "x");
        assert_eq!(rc.reason, "need x for Y");
    }

    #[test]
    fn test_optional_capability_new() {
        let oc = OptionalCapability::new("net", "for C2", "enables download");
        assert_eq!(oc.id.as_str(), "net");
        assert_eq!(oc.enables, "enables download");
    }
}
