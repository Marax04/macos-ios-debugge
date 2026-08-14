//! Semantic / behavioural binary diff: API call diff, side-effect diff,
//! external interaction tracking, behaviour signatures, diff severity scoring,
//! and security-relevant diff classification.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BehaviorDiffError {
    #[error("function not found: {0}")]
    FunctionNotFound(String),
    #[error("incompatible function signatures: {0} vs {1}")]
    IncompatibleSignatures(String, String),
    #[error("diff computation failed: {0}")]
    DiffFailed(String),
}

// ── ExternalInteraction ───────────────────────────────────────────────────────

/// An observable side effect or external interaction produced by a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalInteraction {
    /// Network connection or data transfer.
    Network(NetworkInteraction),
    /// File system read/write/delete.
    File(FileInteraction),
    /// Windows Registry read/write/delete.
    Registry(RegistryInteraction),
    /// Process creation, injection, or termination.
    Process(ProcessInteraction),
    /// Cryptographic operation.
    Crypto(CryptoInteraction),
    /// IPC / COM / RPC call.
    Ipc(IpcInteraction),
    /// Hardware access (GPU, USB, UART, ...).
    Hardware(String),
    /// Logging or UI interaction.
    Ui(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkInteraction {
    pub kind: NetworkKind,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub data_direction: DataDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkKind {
    Connect,
    Listen,
    Send,
    Receive,
    Dns,
    Http,
    Https,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataDirection {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileInteraction {
    pub path: Option<String>,
    pub kind: FileKind,
    pub persistence: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileKind {
    Read,
    Write,
    Append,
    Delete,
    Rename,
    Execute,
    Chmod,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegistryInteraction {
    pub key: Option<String>,
    pub value: Option<String>,
    pub kind: RegKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegKind {
    Read,
    Write,
    Delete,
    CreateKey,
    DeleteKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInteraction {
    pub target: Option<String>,
    pub kind: ProcessKind,
    pub privilege_change: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessKind {
    Spawn,
    Inject,
    Terminate,
    Suspend,
    Resume,
    SetPrivilege,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CryptoInteraction {
    pub algorithm: String,
    pub kind: CryptoKind,
    pub key_bits: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoKind {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Hash,
    KeyGen,
    KeyDerive,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpcInteraction {
    pub mechanism: String,
    pub target: Option<String>,
    pub kind: IpcKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpcKind {
    Send,
    Receive,
    Create,
    Destroy,
}

// ── APICallDiff ───────────────────────────────────────────────────────────────

/// Difference in API calls between two versions of a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct APICallDiff {
    pub function: String,
    pub added_calls: Vec<ApiCall>,
    pub removed_calls: Vec<ApiCall>,
    pub changed_calls: Vec<(ApiCall, ApiCall)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiCall {
    pub name: String,
    pub arguments: Vec<String>,
    pub return_type: Option<String>,
    pub is_security_sensitive: bool,
}

impl ApiCall {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arguments: Vec::new(),
            return_type: None,
            is_security_sensitive: false,
        }
    }

    #[must_use] 
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.arguments = args;
        self
    }

    #[must_use] 
    pub const fn security_sensitive(mut self) -> Self {
        self.is_security_sensitive = true;
        self
    }
}

impl APICallDiff {
    pub fn new(function: impl Into<String>) -> Self {
        Self {
            function: function.into(),
            added_calls: Vec::new(),
            removed_calls: Vec::new(),
            changed_calls: Vec::new(),
        }
    }

    /// True if any security-sensitive calls were added.
    #[must_use] 
    pub fn added_security_calls(&self) -> Vec<&ApiCall> {
        self.added_calls
            .iter()
            .filter(|c| c.is_security_sensitive)
            .collect()
    }

    /// True if security-sensitive calls were removed (potential regression).
    #[must_use] 
    pub fn removed_security_calls(&self) -> Vec<&ApiCall> {
        self.removed_calls
            .iter()
            .filter(|c| c.is_security_sensitive)
            .collect()
    }

    #[must_use] 
    pub const fn total_changes(&self) -> usize {
        self.added_calls.len() + self.removed_calls.len() + self.changed_calls.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.total_changes() == 0
    }
}

// ── SideEffectDiff ────────────────────────────────────────────────────────────

/// Difference in observable side effects between two function versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideEffectDiff {
    pub function: String,
    pub added_interactions: Vec<ExternalInteraction>,
    pub removed_interactions: Vec<ExternalInteraction>,
    pub severity: DiffSeverity,
}

impl SideEffectDiff {
    pub fn new(function: impl Into<String>) -> Self {
        Self {
            function: function.into(),
            added_interactions: Vec::new(),
            removed_interactions: Vec::new(),
            severity: DiffSeverity::None,
        }
    }

    pub fn compute_severity(&mut self) {
        let mut sev = DiffSeverity::None;
        for ia in &self.added_interactions {
            let s = interaction_severity(ia);
            if s > sev {
                sev = s;
            }
        }
        self.severity = sev;
    }

    #[must_use] 
    pub fn added_network_interactions(&self) -> Vec<&ExternalInteraction> {
        self.added_interactions
            .iter()
            .filter(|i| matches!(i, ExternalInteraction::Network(_)))
            .collect()
    }

    #[must_use] 
    pub fn added_registry_interactions(&self) -> Vec<&ExternalInteraction> {
        self.added_interactions
            .iter()
            .filter(|i| matches!(i, ExternalInteraction::Registry(_)))
            .collect()
    }
}

fn interaction_severity(i: &ExternalInteraction) -> DiffSeverity {
    match i {
        ExternalInteraction::Network(_) => DiffSeverity::High,
        ExternalInteraction::Process(p) => {
            if p.kind == ProcessKind::Inject {
                DiffSeverity::Critical
            } else {
                DiffSeverity::High
            }
        }
        ExternalInteraction::Registry(_) | ExternalInteraction::Crypto(_) | ExternalInteraction::Ipc(_) => DiffSeverity::Medium,
        ExternalInteraction::File(f) => {
            if f.persistence {
                DiffSeverity::High
            } else {
                DiffSeverity::Low
            }
        }
        ExternalInteraction::Hardware(_) | ExternalInteraction::Ui(_) => DiffSeverity::Low,
    }
}

// ── BehaviorSignature ─────────────────────────────────────────────────────────

/// A compact signature capturing the observable behaviour of a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorSignature {
    pub function_name: String,
    pub api_calls: Vec<String>,
    pub interaction_classes: Vec<String>,
    pub hash: u64,
}

impl BehaviorSignature {
    pub fn compute(
        function_name: impl Into<String>,
        api_calls: &[ApiCall],
        interactions: &[ExternalInteraction],
    ) -> Self {
        let name = function_name.into();
        let call_names: Vec<String> = api_calls.iter().map(|c| c.name.clone()).collect();
        let inter_classes: Vec<String> = interactions
            .iter()
            .map(|i| interaction_class(i).to_owned())
            .collect();

        // Simple FNV-like hash for the signature.
        let mut hash = 14_695_981_039_346_656_037_u64;
        for s in call_names.iter().chain(inter_classes.iter()) {
            for b in s.bytes() {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(1_099_511_628_211);
            }
        }

        Self {
            function_name: name,
            api_calls: call_names,
            interaction_classes: inter_classes,
            hash,
        }
    }

    #[must_use] 
    pub fn similarity(&self, other: &Self) -> f64 {
        if self.hash == other.hash {
            return 1.0;
        }
        // Jaccard over BOTH dimensions. Scoring `api_calls` alone made two
        // functions that call the same API identical even when one talks to the
        // network and the other writes files — the very distinction this metric
        // exists to draw, and one the hash above already makes. Classes are
        // prefixed so an API named "FILE" cannot collide with the FILE class.
        let a: std::collections::HashSet<String> = self
            .api_calls
            .iter()
            .map(|c| format!("api:{c}"))
            .chain(self.interaction_classes.iter().map(|c| format!("int:{c}")))
            .collect();
        let b: std::collections::HashSet<String> = other
            .api_calls
            .iter()
            .map(|c| format!("api:{c}"))
            .chain(other.interaction_classes.iter().map(|c| format!("int:{c}")))
            .collect();
        let intersection = a.intersection(&b).count();
        let union = a.union(&b).count();
        if union == 0 {
            1.0
        } else {
            count_as_f64(intersection) / count_as_f64(union)
        }
    }
}

const fn interaction_class(i: &ExternalInteraction) -> &'static str {
    match i {
        ExternalInteraction::Network(_) => "NETWORK",
        ExternalInteraction::File(_) => "FILE",
        ExternalInteraction::Registry(_) => "REGISTRY",
        ExternalInteraction::Process(_) => "PROCESS",
        ExternalInteraction::Crypto(_) => "CRYPTO",
        ExternalInteraction::Ipc(_) => "IPC",
        ExternalInteraction::Hardware(_) => "HARDWARE",
        ExternalInteraction::Ui(_) => "UI",
    }
}

// ── DiffSeverity ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DiffSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl DiffSeverity {
    #[must_use] 
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

// ── SecurityRelevantDiff ──────────────────────────────────────────────────────

/// A security-relevant behavioural change between two function versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRelevantDiff {
    pub function: String,
    pub diff_type: SecurityDiffType,
    pub severity: DiffSeverity,
    pub description: String,
    pub cve_hint: Option<String>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityDiffType {
    NewNetworkCommunication,
    RemovedSanitization,
    AddedCodeExecution,
    PrivilegeEscalation,
    CredentialAccess,
    NewPersistenceMechanism,
    CryptographicWeakening,
    AuthenticationBypass,
    InjectionSink,
    DataExfiltration,
}

// ── BehaviorDiff ──────────────────────────────────────────────────────────────

/// Complete behavioural difference between two binary versions.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BehaviorDiff {
    pub old_version: String,
    pub new_version: String,
    pub api_diffs: Vec<APICallDiff>,
    pub side_effect_diffs: Vec<SideEffectDiff>,
    pub security_diffs: Vec<SecurityRelevantDiff>,
    pub function_signatures: HashMap<String, (BehaviorSignature, BehaviorSignature)>,
}

impl BehaviorDiff {
    pub fn new(old: impl Into<String>, new: impl Into<String>) -> Self {
        Self {
            old_version: old.into(),
            new_version: new.into(),
            ..Default::default()
        }
    }

    pub fn add_api_diff(&mut self, d: APICallDiff) {
        self.api_diffs.push(d);
    }

    pub fn add_side_effect_diff(&mut self, d: SideEffectDiff) {
        self.side_effect_diffs.push(d);
    }

    pub fn add_security_diff(&mut self, d: SecurityRelevantDiff) {
        self.security_diffs.push(d);
    }

    #[must_use] 
    pub fn max_severity(&self) -> DiffSeverity {
        self.security_diffs
            .iter()
            .map(|d| d.severity)
            .max()
            .unwrap_or(DiffSeverity::None)
    }

    #[must_use] 
    pub const fn security_diff_count(&self) -> usize {
        self.security_diffs.len()
    }

    #[must_use] 
    pub fn functions_with_new_network(&self) -> Vec<&str> {
        self.security_diffs
            .iter()
            .filter(|d| d.diff_type == SecurityDiffType::NewNetworkCommunication)
            .map(|d| d.function.as_str())
            .collect()
    }

    #[must_use] 
    pub fn critical_diffs(&self) -> Vec<&SecurityRelevantDiff> {
        self.security_diffs
            .iter()
            .filter(|d| d.severity == DiffSeverity::Critical)
            .collect()
    }

    #[must_use] 
    pub const fn has_security_regressions(&self) -> bool {
        !self.security_diffs.is_empty()
    }

    /// Average similarity between matched function pairs.
    #[must_use] 
    pub fn average_signature_similarity(&self) -> f64 {
        if self.function_signatures.is_empty() {
            return 1.0;
        }
        let sum: f64 = self
            .function_signatures
            .values()
            .map(|(a, b)| a.similarity(b))
            .sum();
        sum / count_as_f64(self.function_signatures.len())
    }

    /// Generate a concise summary string.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "{} → {}: API-diffs={} side-effect-diffs={} security-diffs={} max-sev={}",
            self.old_version,
            self.new_version,
            self.api_diffs.len(),
            self.side_effect_diffs.len(),
            self.security_diffs.len(),
            self.max_severity().label()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ExternalInteraction helpers ──────────────────────────────────────────

    fn net_connect() -> ExternalInteraction {
        ExternalInteraction::Network(NetworkInteraction {
            kind: NetworkKind::Connect,
            address: Some("1.2.3.4".into()),
            port: Some(443),
            protocol: Some("HTTPS".into()),
            data_direction: DataDirection::ReadWrite,
        })
    }

    fn file_write_persistent() -> ExternalInteraction {
        ExternalInteraction::File(FileInteraction {
            path: Some(r"C:\Windows\System32\evil.dll".into()),
            kind: FileKind::Write,
            persistence: true,
        })
    }

    fn registry_write() -> ExternalInteraction {
        ExternalInteraction::Registry(RegistryInteraction {
            key: Some(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into()),
            value: Some("Updater".into()),
            kind: RegKind::Write,
        })
    }

    fn process_inject() -> ExternalInteraction {
        ExternalInteraction::Process(ProcessInteraction {
            target: Some("svchost.exe".into()),
            kind: ProcessKind::Inject,
            privilege_change: false,
        })
    }

    // ── ExternalInteraction severity tests ───────────────────────────────────

    #[test]
    fn test_interaction_severity_network() {
        assert_eq!(interaction_severity(&net_connect()), DiffSeverity::High);
    }

    #[test]
    fn test_interaction_severity_process_inject() {
        assert_eq!(
            interaction_severity(&process_inject()),
            DiffSeverity::Critical
        );
    }

    #[test]
    fn test_interaction_severity_registry() {
        assert_eq!(
            interaction_severity(&registry_write()),
            DiffSeverity::Medium
        );
    }

    #[test]
    fn test_interaction_severity_file_persistent() {
        assert_eq!(
            interaction_severity(&file_write_persistent()),
            DiffSeverity::High
        );
    }

    #[test]
    fn test_interaction_class() {
        assert_eq!(interaction_class(&net_connect()), "NETWORK");
        assert_eq!(interaction_class(&registry_write()), "REGISTRY");
        assert_eq!(interaction_class(&process_inject()), "PROCESS");
    }

    // ── ApiCall tests ────────────────────────────────────────────────────────

    #[test]
    fn test_api_call_builder() {
        let c = ApiCall::new("VirtualAllocEx")
            .with_args(vec!["hProcess".into(), "NULL".into()])
            .security_sensitive();
        assert!(c.is_security_sensitive);
        assert_eq!(c.arguments.len(), 2);
    }

    // ── APICallDiff tests ────────────────────────────────────────────────────

    #[test]
    fn test_api_diff_added_security_calls() {
        let mut d = APICallDiff::new("decrypt_buffer");
        d.added_calls
            .push(ApiCall::new("CreateRemoteThread").security_sensitive());
        d.added_calls.push(ApiCall::new("Sleep"));
        assert_eq!(d.added_security_calls().len(), 1);
    }

    #[test]
    fn test_api_diff_removed_security_calls() {
        let mut d = APICallDiff::new("check_auth");
        d.removed_calls
            .push(ApiCall::new("CryptVerifySignature").security_sensitive());
        assert_eq!(d.removed_security_calls().len(), 1);
    }

    #[test]
    fn test_api_diff_total_changes() {
        let mut d = APICallDiff::new("fn");
        d.added_calls.push(ApiCall::new("A"));
        d.removed_calls.push(ApiCall::new("B"));
        d.removed_calls.push(ApiCall::new("C"));
        assert_eq!(d.total_changes(), 3);
    }

    #[test]
    fn test_api_diff_empty() {
        let d = APICallDiff::new("fn");
        assert!(d.is_empty());
    }

    // ── SideEffectDiff tests ─────────────────────────────────────────────────

    #[test]
    fn test_side_effect_diff_compute_severity_critical() {
        let mut d = SideEffectDiff::new("inject_payload");
        d.added_interactions.push(process_inject());
        d.compute_severity();
        assert_eq!(d.severity, DiffSeverity::Critical);
    }

    #[test]
    fn test_side_effect_diff_added_network() {
        let mut d = SideEffectDiff::new("send_data");
        d.added_interactions.push(net_connect());
        assert_eq!(d.added_network_interactions().len(), 1);
    }

    #[test]
    fn test_side_effect_diff_added_registry() {
        let mut d = SideEffectDiff::new("persist");
        d.added_interactions.push(registry_write());
        assert_eq!(d.added_registry_interactions().len(), 1);
    }

    #[test]
    fn test_side_effect_diff_no_network() {
        let d = SideEffectDiff::new("fn");
        assert!(d.added_network_interactions().is_empty());
    }

    // ── BehaviorSignature tests ──────────────────────────────────────────────

    #[test]
    fn test_behavior_sig_identical_is_100_pct() {
        let calls = vec![ApiCall::new("WriteFile"), ApiCall::new("CloseHandle")];
        let ints = vec![net_connect()];
        let sig1 = BehaviorSignature::compute("fn", &calls, &ints);
        let sig2 = BehaviorSignature::compute("fn", &calls, &ints);
        assert_eq!(sig1.similarity(&sig2), 1.0);
    }

    #[test]
    fn test_behavior_sig_completely_different() {
        let calls1 = vec![ApiCall::new("ReadFile")];
        let calls2 = vec![ApiCall::new("CreateRemoteThread")];
        let sig1 = BehaviorSignature::compute("fn1", &calls1, &[]);
        let sig2 = BehaviorSignature::compute("fn2", &calls2, &[]);
        assert!(sig1.similarity(&sig2) < 1.0);
        assert!(sig1.similarity(&sig2) >= 0.0);
    }

    #[test]
    fn test_behavior_sig_partial_overlap() {
        let calls1 = vec![ApiCall::new("A"), ApiCall::new("B")];
        let calls2 = vec![ApiCall::new("B"), ApiCall::new("C")];
        let sig1 = BehaviorSignature::compute("fn", &calls1, &[]);
        let sig2 = BehaviorSignature::compute("fn", &calls2, &[]);
        let sim = sig1.similarity(&sig2);
        // 1 common ("B") out of 3 union (A, B, C)
        assert!((sim - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_behavior_sig_hash_changes_with_calls() {
        let sig1 = BehaviorSignature::compute("fn", &[ApiCall::new("A")], &[]);
        let sig2 = BehaviorSignature::compute("fn", &[ApiCall::new("B")], &[]);
        assert_ne!(sig1.hash, sig2.hash);
    }

    // ── DiffSeverity tests ───────────────────────────────────────────────────

    #[test]
    fn test_diff_severity_ordering() {
        assert!(DiffSeverity::Critical > DiffSeverity::High);
        assert!(DiffSeverity::High > DiffSeverity::Medium);
        assert!(DiffSeverity::Medium > DiffSeverity::Low);
        assert!(DiffSeverity::Low > DiffSeverity::None);
    }

    #[test]
    fn test_diff_severity_labels() {
        assert_eq!(DiffSeverity::Critical.label(), "Critical");
        assert_eq!(DiffSeverity::None.label(), "None");
    }

    // ── SecurityRelevantDiff tests ───────────────────────────────────────────

    #[test]
    fn test_security_relevant_diff_fields() {
        let d = SecurityRelevantDiff {
            function: "decrypt_data".into(),
            diff_type: SecurityDiffType::CryptographicWeakening,
            severity: DiffSeverity::High,
            description: "AES-256 replaced with RC4".into(),
            cve_hint: None,
            mitre_technique: Some("T1600".into()),
        };
        assert_eq!(d.severity, DiffSeverity::High);
        assert_eq!(d.diff_type, SecurityDiffType::CryptographicWeakening);
    }

    // ── BehaviorDiff tests ───────────────────────────────────────────────────

    #[test]
    fn test_behavior_diff_new() {
        let bd = BehaviorDiff::new("v1.0", "v1.1");
        assert_eq!(bd.old_version, "v1.0");
        assert_eq!(bd.max_severity(), DiffSeverity::None);
    }

    #[test]
    fn test_behavior_diff_max_severity() {
        let mut bd = BehaviorDiff::new("v1", "v2");
        bd.add_security_diff(SecurityRelevantDiff {
            function: "f1".into(),
            diff_type: SecurityDiffType::NewNetworkCommunication,
            severity: DiffSeverity::High,
            description: "new C2 channel".into(),
            cve_hint: None,
            mitre_technique: None,
        });
        bd.add_security_diff(SecurityRelevantDiff {
            function: "f2".into(),
            diff_type: SecurityDiffType::AddedCodeExecution,
            severity: DiffSeverity::Critical,
            description: "shellcode injection".into(),
            cve_hint: None,
            mitre_technique: None,
        });
        assert_eq!(bd.max_severity(), DiffSeverity::Critical);
    }

    #[test]
    fn test_behavior_diff_functions_with_new_network() {
        let mut bd = BehaviorDiff::new("v1", "v2");
        bd.add_security_diff(SecurityRelevantDiff {
            function: "send_payload".into(),
            diff_type: SecurityDiffType::NewNetworkCommunication,
            severity: DiffSeverity::High,
            description: String::new(),
            cve_hint: None,
            mitre_technique: None,
        });
        let funcs = bd.functions_with_new_network();
        assert_eq!(funcs, vec!["send_payload"]);
    }

    #[test]
    fn test_behavior_diff_critical_diffs() {
        let mut bd = BehaviorDiff::new("v1", "v2");
        bd.add_security_diff(SecurityRelevantDiff {
            function: "inject".into(),
            diff_type: SecurityDiffType::InjectionSink,
            severity: DiffSeverity::Critical,
            description: String::new(),
            cve_hint: None,
            mitre_technique: None,
        });
        assert_eq!(bd.critical_diffs().len(), 1);
    }

    #[test]
    fn test_behavior_diff_has_security_regressions() {
        let mut bd = BehaviorDiff::new("v1", "v2");
        assert!(!bd.has_security_regressions());
        bd.add_security_diff(SecurityRelevantDiff {
            function: "f".into(),
            diff_type: SecurityDiffType::AuthenticationBypass,
            severity: DiffSeverity::High,
            description: String::new(),
            cve_hint: None,
            mitre_technique: None,
        });
        assert!(bd.has_security_regressions());
    }

    #[test]
    fn test_behavior_diff_average_similarity_no_funcs() {
        let bd = BehaviorDiff::new("v1", "v2");
        assert_eq!(bd.average_signature_similarity(), 1.0);
    }

    #[test]
    fn test_behavior_diff_average_similarity_identical() {
        let mut bd = BehaviorDiff::new("v1", "v2");
        let calls = vec![ApiCall::new("ReadFile")];
        let sig = BehaviorSignature::compute("fn", &calls, &[]);
        bd.function_signatures
            .insert("fn".into(), (sig.clone(), sig));
        assert_eq!(bd.average_signature_similarity(), 1.0);
    }

    #[test]
    fn test_behavior_diff_summary() {
        let bd = BehaviorDiff::new("v1.0.0", "v2.0.0");
        let s = bd.summary();
        assert!(s.contains("v1.0.0"));
        assert!(s.contains("v2.0.0"));
    }

    #[test]
    fn test_api_diff_no_security_calls_removed() {
        let d = APICallDiff::new("fn");
        assert!(d.removed_security_calls().is_empty());
    }

    #[test]
    fn test_security_diff_count() {
        let mut bd = BehaviorDiff::new("a", "b");
        for _ in 0..5 {
            bd.add_security_diff(SecurityRelevantDiff {
                function: "f".into(),
                diff_type: SecurityDiffType::DataExfiltration,
                severity: DiffSeverity::High,
                description: String::new(),
                cve_hint: None,
                mitre_technique: None,
            });
        }
        assert_eq!(bd.security_diff_count(), 5);
    }

    #[test]
    fn test_crypto_interaction() {
        let ci = ExternalInteraction::Crypto(CryptoInteraction {
            algorithm: "AES-256-GCM".into(),
            kind: CryptoKind::Encrypt,
            key_bits: Some(256),
        });
        assert_eq!(interaction_class(&ci), "CRYPTO");
        assert_eq!(interaction_severity(&ci), DiffSeverity::Medium);
    }

    #[test]
    fn test_ipc_interaction() {
        let ipc = ExternalInteraction::Ipc(IpcInteraction {
            mechanism: "Named Pipe".into(),
            target: Some("\\\\.\\pipe\\evil".into()),
            kind: IpcKind::Send,
        });
        assert_eq!(interaction_class(&ipc), "IPC");
    }

    #[test]
    fn test_hardware_interaction_class() {
        let hw = ExternalInteraction::Hardware("USB HID".into());
        assert_eq!(interaction_class(&hw), "HARDWARE");
        assert_eq!(interaction_severity(&hw), DiffSeverity::Low);
    }

    #[test]
    fn test_ui_interaction_class() {
        let ui = ExternalInteraction::Ui("MessageBox".into());
        assert_eq!(interaction_class(&ui), "UI");
        assert_eq!(interaction_severity(&ui), DiffSeverity::Low);
    }

    #[test]
    fn test_file_non_persistent_low_severity() {
        let fi = ExternalInteraction::File(FileInteraction {
            path: Some("/tmp/output".into()),
            kind: FileKind::Write,
            persistence: false,
        });
        assert_eq!(interaction_severity(&fi), DiffSeverity::Low);
    }

    #[test]
    fn test_process_spawn_high_severity() {
        let pi = ExternalInteraction::Process(ProcessInteraction {
            target: Some("cmd.exe".into()),
            kind: ProcessKind::Spawn,
            privilege_change: false,
        });
        assert_eq!(interaction_severity(&pi), DiffSeverity::High);
    }

    #[test]
    fn test_behavior_sig_empty_calls() {
        let sig1 = BehaviorSignature::compute("fn", &[], &[]);
        let sig2 = BehaviorSignature::compute("fn", &[], &[]);
        assert_eq!(sig1.similarity(&sig2), 1.0);
    }

    #[test]
    fn test_diff_severity_none_label() {
        assert_eq!(DiffSeverity::None.label(), "None");
        assert_eq!(DiffSeverity::Medium.label(), "Medium");
    }

    #[test]
    fn test_behavior_diff_no_critical_by_default() {
        let bd = BehaviorDiff::new("v1", "v2");
        assert!(bd.critical_diffs().is_empty());
    }

    #[test]
    fn test_security_diff_exfiltration_type() {
        let d = SecurityRelevantDiff {
            function: "exfil_fn".into(),
            diff_type: SecurityDiffType::DataExfiltration,
            severity: DiffSeverity::Critical,
            description: "sends data to C2".into(),
            cve_hint: Some("CVE-2024-12345".into()),
            mitre_technique: Some("T1041".into()),
        };
        assert_eq!(d.diff_type, SecurityDiffType::DataExfiltration);
        assert!(d.cve_hint.is_some());
    }

    #[test]
    fn test_api_call_no_args() {
        let c = ApiCall::new("GetProcAddress");
        assert!(c.arguments.is_empty());
        assert!(!c.is_security_sensitive);
    }

    #[test]
    fn test_behavior_diff_functions_with_new_network_empty() {
        let bd = BehaviorDiff::new("a", "b");
        assert!(bd.functions_with_new_network().is_empty());
    }
}
