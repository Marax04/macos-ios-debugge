use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};

// ── Capability taxonomy ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    // File system capabilities
    FileRead(FileScope),
    FileWrite(FileScope),
    FileDelete(FileScope),
    FileList(FileScope),
    // Network capabilities
    NetworkConnect(NetworkScope),
    NetworkListen(u16),
    NetworkSendRaw,
    // Process capabilities
    ProcessSpawn,
    ProcessKill,
    ProcessInspect,
    ProcessMemoryRead,
    ProcessMemoryWrite,
    // Binary analysis capabilities
    BinaryLoad,
    BinaryDisassemble,
    BinaryDecompile,
    BinaryModify,
    SymbolAccess,
    // Debug capabilities
    DebuggerAttach,
    DebuggerDetach,
    BreakpointSet,
    RegisterRead,
    RegisterWrite,
    MemoryRead,
    MemoryWrite,
    // UI capabilities
    UiCreatePanel,
    UiCreateDialog,
    UiShowNotification,
    UiMenuAdd,
    // Data capabilities
    DatabaseRead,
    DatabaseWrite,
    DatabaseCreate,
    // IPC capabilities
    IpcSend,
    IpcReceive,
    IpcBroadcast,
    // System capabilities
    SystemEnvRead,
    SystemEnvWrite,
    SystemTimeAccess,
    SystemClockAccess,
    // Plugin management
    PluginLoad,
    PluginUnload,
    PluginCommunicate,
    // Script execution
    ScriptLua,
    ScriptPython,
    ScriptRhai,
    // Full trust (dangerous)
    Unrestricted,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileScope {
    Anywhere,
    ProjectOnly,
    TempOnly,
    SpecificPath(String),
    ReadonlyPaths(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkScope {
    Localhost,
    LAN,
    Internet,
    SpecificHost(String),
    SpecificPort(u16),
}

// ── Capability set ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    caps: HashSet<CapabilityKey>,
    rules: Vec<CapabilityRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct CapabilityKey {
    cap: String,
    scope: Option<String>,
}

impl CapabilityKey {
    fn from_cap(cap: &Capability) -> Self {
        let name = format!("{:?}", cap).split('(').next().unwrap_or("Unknown").to_string();
        Self { cap: name, scope: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRule {
    pub capability: Capability,
    pub policy: CapabilityPolicy,
    pub reason: Option<String>,
    pub expiry: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CapabilityPolicy {
    Allow,
    Deny,
    Prompt,
    AllowWithAudit,
    DenyWithLog,
}

impl CapabilitySet {
    pub fn new() -> Self { Self::default() }

    /// Record `cap` in the fast lookup index so [`Self::contains_capability`]
    /// can answer membership questions without scanning the full rule list.
    fn index(&mut self, cap: &Capability) {
        self.caps.insert(CapabilityKey::from_cap(cap));
    }

    /// Return `true` if a rule for this capability has ever been recorded
    /// (regardless of whether the policy is `Allow` or `Deny`).
    #[must_use]
    pub fn contains_capability(&self, cap: &Capability) -> bool {
        self.caps.contains(&CapabilityKey::from_cap(cap))
    }

    pub fn allow(&mut self, cap: Capability) {
        self.index(&cap);
        self.rules.push(CapabilityRule { capability: cap, policy: CapabilityPolicy::Allow, reason: None, expiry: None });
    }

    pub fn deny(&mut self, cap: Capability) {
        self.index(&cap);
        self.rules.push(CapabilityRule { capability: cap, policy: CapabilityPolicy::Deny, reason: None, expiry: None });
    }

    pub fn allow_with_reason(&mut self, cap: Capability, reason: &str) {
        self.index(&cap);
        self.rules.push(CapabilityRule { capability: cap, policy: CapabilityPolicy::Allow, reason: Some(reason.to_string()), expiry: None });
    }

    pub fn check(&self, cap: &Capability) -> CapabilityPolicy {
        if matches!(cap, Capability::Unrestricted) { return CapabilityPolicy::Deny; }
        for rule in self.rules.iter().rev() {
            if &rule.capability == cap {
                return rule.policy.clone();
            }
            if self.caps_match_class(&rule.capability, cap) {
                return rule.policy.clone();
            }
        }
        CapabilityPolicy::Deny
    }

    fn caps_match_class(&self, rule_cap: &Capability, request_cap: &Capability) -> bool {
        use std::mem::discriminant;
        discriminant(rule_cap) == discriminant(request_cap)
    }

    pub fn is_allowed(&self, cap: &Capability) -> bool {
        matches!(self.check(cap), CapabilityPolicy::Allow | CapabilityPolicy::AllowWithAudit)
    }

    pub fn merge(&mut self, other: &CapabilitySet) {
        self.rules.extend(other.rules.clone());
    }

    pub fn all_allowed(&self) -> Vec<&Capability> {
        self.rules.iter().filter(|r| matches!(r.policy, CapabilityPolicy::Allow | CapabilityPolicy::AllowWithAudit)).map(|r| &r.capability).collect()
    }

    pub fn all_denied(&self) -> Vec<&Capability> {
        self.rules.iter().filter(|r| matches!(r.policy, CapabilityPolicy::Deny | CapabilityPolicy::DenyWithLog)).map(|r| &r.capability).collect()
    }
}

// ── Predefined capability profiles ────────────────────────────────────────────

pub struct CapabilityProfile;

impl CapabilityProfile {
    pub fn readonly_analyst() -> CapabilitySet {
        let mut set = CapabilitySet::new();
        set.allow(Capability::BinaryLoad);
        set.allow(Capability::BinaryDisassemble);
        set.allow(Capability::BinaryDecompile);
        set.allow(Capability::SymbolAccess);
        set.allow(Capability::FileRead(FileScope::ProjectOnly));
        set.allow(Capability::UiCreatePanel);
        set.allow(Capability::UiShowNotification);
        set.allow(Capability::DatabaseRead);
        set.deny(Capability::BinaryModify);
        set.deny(Capability::FileWrite(FileScope::Anywhere));
        set.deny(Capability::NetworkConnect(NetworkScope::Internet));
        set.deny(Capability::ProcessSpawn);
        set
    }

    pub fn network_monitor() -> CapabilitySet {
        let mut set = CapabilitySet::new();
        set.allow(Capability::NetworkConnect(NetworkScope::Localhost));
        set.allow(Capability::NetworkListen(0));
        set.allow(Capability::BinaryLoad);
        set.allow(Capability::FileRead(FileScope::TempOnly));
        set.allow(Capability::FileWrite(FileScope::TempOnly));
        set.allow(Capability::DatabaseWrite);
        set.allow(Capability::IpcSend);
        set.deny(Capability::ProcessSpawn);
        set.deny(Capability::DebuggerAttach);
        set
    }

    pub fn debugger_plugin() -> CapabilitySet {
        let mut set = CapabilitySet::new();
        set.allow(Capability::DebuggerAttach);
        set.allow(Capability::DebuggerDetach);
        set.allow(Capability::BreakpointSet);
        set.allow(Capability::RegisterRead);
        set.allow(Capability::RegisterWrite);
        set.allow(Capability::MemoryRead);
        set.allow(Capability::MemoryWrite);
        set.allow(Capability::ProcessInspect);
        set.allow(Capability::BinaryLoad);
        set.allow(Capability::SymbolAccess);
        set.allow(Capability::DatabaseWrite);
        set
    }

    pub fn script_sandbox() -> CapabilitySet {
        let mut set = CapabilitySet::new();
        set.allow(Capability::ScriptLua);
        set.allow(Capability::ScriptRhai);
        set.allow(Capability::FileRead(FileScope::TempOnly));
        set.allow(Capability::FileWrite(FileScope::TempOnly));
        set.allow(Capability::BinaryDisassemble);
        set.allow(Capability::SymbolAccess);
        set.deny(Capability::NetworkConnect(NetworkScope::Internet));
        set.deny(Capability::ProcessSpawn);
        set.deny(Capability::DebuggerAttach);
        set.deny(Capability::Unrestricted);
        set
    }

    pub fn full_trusted() -> CapabilitySet {
        let mut set = CapabilitySet::new();
        set.allow(Capability::Unrestricted);
        set
    }
}

// ── Capability checker ─────────────────────────────────────────────────────────

pub struct CapabilityChecker {
    pub plugin_id: String,
    pub caps: CapabilitySet,
    pub audit_log: Vec<CapabilityAuditEntry>,
    pub violation_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityAuditEntry {
    pub timestamp_ns: u64,
    pub plugin_id: String,
    pub capability: String,
    pub policy: String,
    pub granted: bool,
    pub context: Option<String>,
}

impl CapabilityChecker {
    pub fn new(plugin_id: String, caps: CapabilitySet) -> Self {
        Self { plugin_id, caps, audit_log: Vec::new(), violation_count: 0 }
    }

    pub fn check_and_log(&mut self, cap: &Capability, context: Option<&str>) -> Result<()> {
        let policy = self.caps.check(cap);
        let granted = matches!(policy, CapabilityPolicy::Allow | CapabilityPolicy::AllowWithAudit);
        let entry = CapabilityAuditEntry {
            timestamp_ns: 0,
            plugin_id: self.plugin_id.clone(),
            capability: format!("{:?}", cap),
            policy: format!("{:?}", policy),
            granted,
            context: context.map(|s| s.to_string()),
        };
        if matches!(policy, CapabilityPolicy::AllowWithAudit | CapabilityPolicy::DenyWithLog | CapabilityPolicy::Deny) {
            self.audit_log.push(entry);
        }
        if !granted {
            self.violation_count += 1;
            return Err(anyhow!("plugin '{}' denied capability {:?}", self.plugin_id, cap));
        }
        Ok(())
    }

    pub fn require(&mut self, cap: &Capability) -> Result<()> {
        self.check_and_log(cap, None)
    }

    pub fn require_ctx(&mut self, cap: &Capability, ctx: &str) -> Result<()> {
        self.check_and_log(cap, Some(ctx))
    }

    pub fn violations(&self) -> u64 { self.violation_count }

    pub fn audit_trail(&self) -> &[CapabilityAuditEntry] { &self.audit_log }

    pub fn summary(&self) -> CapabilitySummary {
        let granted = self.audit_log.iter().filter(|e| e.granted).count();
        let denied = self.audit_log.iter().filter(|e| !e.granted).count();
        CapabilitySummary { plugin_id: self.plugin_id.clone(), total_checks: self.audit_log.len(), granted, denied, violations: self.violation_count }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub plugin_id: String,
    pub total_checks: usize,
    pub granted: usize,
    pub denied: usize,
    pub violations: u64,
}

// ── Capability negotiation ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub plugin_id: String,
    pub required: Vec<Capability>,
    pub optional: Vec<Capability>,
    pub justification: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub plugin_id: String,
    pub granted: Vec<Capability>,
    pub denied: Vec<Capability>,
    pub effective_set: CapabilitySet,
}

pub struct CapabilityNegotiator {
    pub base_policy: CapabilitySet,
    pub overrides: HashMap<String, CapabilitySet>,
}

impl CapabilityNegotiator {
    pub fn new(base: CapabilitySet) -> Self {
        Self { base_policy: base, overrides: HashMap::new() }
    }

    pub fn negotiate(&self, request: &CapabilityRequest) -> CapabilityGrant {
        let mut effective = self.base_policy.clone();
        if let Some(plugin_override) = self.overrides.get(&request.plugin_id) {
            effective.merge(plugin_override);
        }
        let mut granted = Vec::new();
        let mut denied = Vec::new();
        for cap in &request.required {
            if effective.is_allowed(cap) {
                granted.push(cap.clone());
            } else {
                denied.push(cap.clone());
            }
        }
        for cap in &request.optional {
            if effective.is_allowed(cap) {
                granted.push(cap.clone());
            }
        }
        CapabilityGrant { plugin_id: request.plugin_id.clone(), granted, denied, effective_set: effective }
    }

    pub fn add_plugin_override(&mut self, plugin_id: String, caps: CapabilitySet) {
        self.overrides.insert(plugin_id, caps);
    }
}

// ── Resource quota enforcement ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub max_memory_mb: u64,
    pub max_cpu_percent: f64,
    pub max_file_handles: u32,
    pub max_network_connections: u32,
    pub max_threads: u32,
    pub max_runtime_seconds: Option<u64>,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self {
            max_memory_mb: 256,
            max_cpu_percent: 50.0,
            max_file_handles: 64,
            max_network_connections: 16,
            max_threads: 4,
            max_runtime_seconds: Some(300),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub memory_mb: u64,
    pub cpu_percent: f64,
    pub file_handles: u32,
    pub network_connections: u32,
    pub threads: u32,
    pub runtime_seconds: u64,
}

impl ResourceUsage {
    pub fn exceeds(&self, quota: &ResourceQuota) -> Vec<String> {
        let mut violations = Vec::new();
        if self.memory_mb > quota.max_memory_mb {
            violations.push(format!("memory {}MB > {}MB", self.memory_mb, quota.max_memory_mb));
        }
        if self.cpu_percent > quota.max_cpu_percent {
            violations.push(format!("cpu {:.1}% > {:.1}%", self.cpu_percent, quota.max_cpu_percent));
        }
        if self.file_handles > quota.max_file_handles {
            violations.push(format!("file handles {} > {}", self.file_handles, quota.max_file_handles));
        }
        if self.network_connections > quota.max_network_connections {
            violations.push(format!("network connections {} > {}", self.network_connections, quota.max_network_connections));
        }
        if self.threads > quota.max_threads {
            violations.push(format!("threads {} > {}", self.threads, quota.max_threads));
        }
        if let Some(max_rt) = quota.max_runtime_seconds {
            if self.runtime_seconds > max_rt {
                violations.push(format!("runtime {}s > {}s", self.runtime_seconds, max_rt));
            }
        }
        violations
    }

    pub fn is_within(&self, quota: &ResourceQuota) -> bool {
        self.exceeds(quota).is_empty()
    }
}
