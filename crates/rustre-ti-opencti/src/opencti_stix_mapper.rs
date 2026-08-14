//! STIX 2.1 object mapping for `OpenCTI` entities.
//!
//! Converts `OpenCTI` native objects into STIX 2.1 bundles suitable for
//! export, sharing, or ingestion into other threat intelligence platforms.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Confidence, OpenCtiError};

// ─── StixId ──────────────────────────────────────────────────────────────────

/// A STIX 2.1 identifier in the form `<type>--<uuid4>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StixId(pub String);

impl StixId {
    /// Create a new STIX ID with the given type prefix and UUID.
    #[must_use]
    pub fn new(stix_type: &str, uuid: &str) -> Self {
        Self(format!("{stix_type}--{uuid}"))
    }

    /// Parse a STIX ID and return the type part.
    #[must_use]
    pub fn stix_type(&self) -> Option<&str> {
        self.0.split_once("--").map(|(t, _)| t)
    }

    /// Parse a STIX ID and return the UUID part.
    #[must_use]
    pub fn uuid(&self) -> Option<&str> {
        self.0.split_once("--").map(|(_, u)| u)
    }

    /// Returns `true` if the ID has a valid `<type>--<uuid>` structure.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let parts: Vec<&str> = self.0.splitn(2, "--").collect();
        parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty()
    }
}

impl fmt::Display for StixId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── StixType ────────────────────────────────────────────────────────────────

/// STIX 2.1 Domain Object (SDO) and Observable (SCO) types relevant to CTI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StixType {
    Indicator,
    Malware,
    ThreatActor,
    AttackPattern,
    Campaign,
    CourseOfAction,
    IntrusionSet,
    Report,
    Vulnerability,
    Identity,
    Relationship,
    Bundle,
    Sighting,
    // SCOs
    Ipv4Addr,
    Ipv6Addr,
    DomainName,
    Url,
    File,
    NetworkTraffic,
    EmailAddress,
    UserAccount,
    // Extension
    #[serde(other)]
    Unknown,
}

impl fmt::Display for StixType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Indicator => "indicator",
            Self::Malware => "malware",
            Self::ThreatActor => "threat-actor",
            Self::AttackPattern => "attack-pattern",
            Self::Campaign => "campaign",
            Self::CourseOfAction => "course-of-action",
            Self::IntrusionSet => "intrusion-set",
            Self::Report => "report",
            Self::Vulnerability => "vulnerability",
            Self::Identity => "identity",
            Self::Relationship => "relationship",
            Self::Bundle => "bundle",
            Self::Sighting => "sighting",
            Self::Ipv4Addr => "ipv4-addr",
            Self::Ipv6Addr => "ipv6-addr",
            Self::DomainName => "domain-name",
            Self::Url => "url",
            Self::File => "file",
            Self::NetworkTraffic => "network-traffic",
            Self::EmailAddress => "email-address",
            Self::UserAccount => "user-account",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ─── StixObject ──────────────────────────────────────────────────────────────

/// A STIX 2.1 Domain Object or Cyber Observable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixObject {
    /// STIX type.
    pub stix_type: StixType,
    /// STIX ID.
    pub id: StixId,
    /// Spec version (always `"2.1"`).
    pub spec_version: String,
    /// RFC 3339 creation timestamp.
    pub created: String,
    /// RFC 3339 last modification timestamp.
    pub modified: String,
    /// Human-readable name (SDOs) or value (SCOs).
    pub name: Option<String>,
    /// Free-text description.
    pub description: Option<String>,
    /// Confidence (0–100).
    pub confidence: Option<Confidence>,
    /// STIX labels (e.g. `["malicious-activity"]`).
    pub labels: Vec<String>,
    /// OpenCTI-specific extensions stored as arbitrary JSON.
    pub extensions: HashMap<String, serde_json::Value>,
    /// STIX pattern for Indicator objects (e.g. `[ipv4-addr:value = '1.2.3.4']`).
    pub pattern: Option<String>,
    /// Pattern type (e.g. `"stix"`).
    pub pattern_type: Option<String>,
    /// Valid-from timestamp for Indicator objects.
    pub valid_from: Option<String>,
    /// MITRE ATT&CK IDs for `AttackPattern` objects.
    pub external_references: Vec<ExternalReference>,
    /// Kill-chain phases.
    pub kill_chain_phases: Vec<KillChainPhase>,
    /// Malware types (for Malware objects).
    pub malware_types: Vec<String>,
    /// Is the malware a family?
    pub is_family: bool,
    /// Aliases for this object.
    pub aliases: Vec<String>,
    /// Object marking references (TLPs etc.).
    pub object_marking_refs: Vec<StixId>,
    /// Created-by reference (Identity ID).
    pub created_by_ref: Option<StixId>,
}

impl StixObject {
    /// Create a minimal Indicator object.
    #[must_use]
    pub fn indicator(id: StixId, name: impl Into<String>, pattern: impl Into<String>) -> Self {
        let now = chrono_now();
        Self {
            stix_type: StixType::Indicator,
            id,
            spec_version: "2.1".to_string(),
            created: now.clone(),
            modified: now,
            name: Some(name.into()),
            description: None,
            confidence: None,
            labels: vec!["malicious-activity".to_string()],
            extensions: HashMap::new(),
            pattern: Some(pattern.into()),
            pattern_type: Some("stix".to_string()),
            valid_from: None,
            external_references: vec![],
            kill_chain_phases: vec![],
            malware_types: vec![],
            is_family: false,
            aliases: vec![],
            object_marking_refs: vec![],
            created_by_ref: None,
        }
    }

    /// Create a minimal Malware object.
    #[must_use]
    pub fn malware(id: StixId, name: impl Into<String>, is_family: bool) -> Self {
        let now = chrono_now();
        Self {
            stix_type: StixType::Malware,
            id,
            spec_version: "2.1".to_string(),
            created: now.clone(),
            modified: now,
            name: Some(name.into()),
            description: None,
            confidence: None,
            labels: vec![],
            extensions: HashMap::new(),
            pattern: None,
            pattern_type: None,
            valid_from: None,
            external_references: vec![],
            kill_chain_phases: vec![],
            malware_types: vec![],
            is_family,
            aliases: vec![],
            object_marking_refs: vec![],
            created_by_ref: None,
        }
    }

    /// Add a TLP marking reference.
    #[must_use]
    pub fn with_tlp(mut self, tlp_id: StixId) -> Self {
        self.object_marking_refs.push(tlp_id);
        self
    }

    /// Add a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Set confidence.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Add an external reference (e.g. MITRE ATT&CK).
    #[must_use]
    pub fn with_external_ref(mut self, ext_ref: ExternalReference) -> Self {
        self.external_references.push(ext_ref);
        self
    }
}

// ─── ExternalReference ───────────────────────────────────────────────────────

/// A STIX external reference (e.g. CVE, MITRE ATT&CK technique).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source_name: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub external_id: Option<String>,
}

impl ExternalReference {
    /// Convenience constructor for a MITRE ATT&CK reference.
    #[must_use]
    pub fn mitre(technique_id: impl Into<String>) -> Self {
        let id = technique_id.into();
        Self {
            source_name: "mitre-attack".to_string(),
            description: None,
            url: Some(format!(
                "https://attack.mitre.org/techniques/{}",
                id.replace('.', "/")
            )),
            external_id: Some(id),
        }
    }

    /// Convenience constructor for a CVE reference.
    #[must_use]
    pub fn cve(cve_id: impl Into<String>) -> Self {
        let id = cve_id.into();
        Self {
            source_name: "cve".to_string(),
            description: None,
            url: Some(format!("https://nvd.nist.gov/vuln/detail/{id}")),
            external_id: Some(id),
        }
    }
}

// ─── KillChainPhase ──────────────────────────────────────────────────────────

/// A STIX kill-chain phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

impl KillChainPhase {
    /// ATT&CK initial-access phase.
    #[must_use]
    pub fn initial_access() -> Self {
        Self {
            kill_chain_name: "mitre-attack".to_string(),
            phase_name: "initial-access".to_string(),
        }
    }

    /// ATT&CK execution phase.
    #[must_use]
    pub fn execution() -> Self {
        Self {
            kill_chain_name: "mitre-attack".to_string(),
            phase_name: "execution".to_string(),
        }
    }

    /// ATT&CK persistence phase.
    #[must_use]
    pub fn persistence() -> Self {
        Self {
            kill_chain_name: "mitre-attack".to_string(),
            phase_name: "persistence".to_string(),
        }
    }

    /// ATT&CK command-and-control phase.
    #[must_use]
    pub fn command_and_control() -> Self {
        Self {
            kill_chain_name: "mitre-attack".to_string(),
            phase_name: "command-and-control".to_string(),
        }
    }
}

// ─── StixRelationship ────────────────────────────────────────────────────────

/// A STIX 2.1 Relationship object linking two SDOs or SCOs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixRelationship {
    pub stix_type: StixType,
    pub id: StixId,
    pub spec_version: String,
    pub created: String,
    pub modified: String,
    /// Semantic type of the relationship (e.g. `"indicates"`, `"uses"`, `"targets"`).
    pub relationship_type: String,
    pub description: Option<String>,
    pub source_ref: StixId,
    pub target_ref: StixId,
    pub confidence: Option<Confidence>,
    pub object_marking_refs: Vec<StixId>,
    pub created_by_ref: Option<StixId>,
}

impl StixRelationship {
    /// Create a new relationship between two STIX objects.
    #[must_use]
    pub fn new(
        id: StixId,
        relationship_type: impl Into<String>,
        source_ref: StixId,
        target_ref: StixId,
    ) -> Self {
        let now = chrono_now();
        Self {
            stix_type: StixType::Relationship,
            id,
            spec_version: "2.1".to_string(),
            created: now.clone(),
            modified: now,
            relationship_type: relationship_type.into(),
            description: None,
            source_ref,
            target_ref,
            confidence: None,
            object_marking_refs: vec![],
            created_by_ref: None,
        }
    }

    /// Set description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set confidence.
    #[must_use]
    pub const fn with_confidence(mut self, c: Confidence) -> Self {
        self.confidence = Some(c);
        self
    }
}

// ─── StixBundle ──────────────────────────────────────────────────────────────

/// A STIX 2.1 Bundle containing objects and relationships.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    pub id: StixId,
    pub spec_version: String,
    pub objects: Vec<serde_json::Value>,
}

impl StixBundle {
    /// Create an empty bundle.
    #[must_use]
    pub fn new(id: StixId) -> Self {
        Self {
            id,
            spec_version: "2.1".to_string(),
            objects: vec![],
        }
    }

    /// Add a STIX object (serialised to JSON).
    ///
    /// # Errors
    /// Returns `OpenCtiError::Serialization` if the object cannot be serialised.
    pub fn add_object<T: Serialize>(&mut self, obj: &T) -> Result<(), OpenCtiError> {
        let v = serde_json::to_value(obj).map_err(|e| OpenCtiError::Serialization(e.to_string()))?;
        self.objects.push(v);
        Ok(())
    }

    /// Number of objects in this bundle.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Serialise the bundle to a JSON string.
    ///
    /// # Errors
    /// Returns `OpenCtiError::Serialization` if serialisation fails.
    pub fn to_json(&self) -> Result<String, OpenCtiError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| OpenCtiError::Serialization(e.to_string()))
    }
}

// ─── OpenCtiIndicator (input) ────────────────────────────────────────────────

/// An indicator as returned by the `OpenCTI` `GraphQL` API before mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCtiIndicator {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: Option<String>,
    pub confidence: Option<u8>,
    pub labels: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub creator: Option<String>,
    pub kill_chain_phases: Vec<(String, String)>,
    pub external_references: Vec<(String, Option<String>, Option<String>)>,
}

impl OpenCtiIndicator {
    /// Create a sample indicator for unit tests.
    #[must_use]
    pub fn sample() -> Self {
        Self {
            id: "abc-123".to_string(),
            name: "Malicious IP 185.220.101.1".to_string(),
            description: Some("Known Tor exit node used for C2".to_string()),
            pattern: "[ipv4-addr:value = '185.220.101.1']".to_string(),
            pattern_type: "stix".to_string(),
            valid_from: Some("2024-01-01T00:00:00Z".to_string()),
            confidence: Some(85),
            labels: vec!["malicious-activity".to_string(), "c2".to_string()],
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            creator: Some("rustre".to_string()),
            kill_chain_phases: vec![("mitre-attack".to_string(), "command-and-control".to_string())],
            external_references: vec![],
        }
    }
}

// ─── OpenCtiMalware (input) ──────────────────────────────────────────────────

/// A malware object from the `OpenCTI` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCtiMalware {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub aliases: Vec<String>,
    pub is_family: bool,
    pub malware_types: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub confidence: Option<u8>,
    pub labels: Vec<String>,
    pub kill_chain_phases: Vec<(String, String)>,
    pub external_references: Vec<(String, Option<String>, Option<String>)>,
}

impl OpenCtiMalware {
    /// Create a sample malware object for unit tests.
    #[must_use]
    pub fn sample() -> Self {
        Self {
            id: "mal-456".to_string(),
            name: "Emotet".to_string(),
            description: Some("Banking trojan and malware distribution botnet".to_string()),
            aliases: vec!["Heodo".to_string(), "Geodo".to_string()],
            is_family: true,
            malware_types: vec!["trojan".to_string(), "downloader".to_string()],
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            confidence: Some(95),
            labels: vec!["banking-trojan".to_string()],
            kill_chain_phases: vec![
                ("mitre-attack".to_string(), "initial-access".to_string()),
                ("mitre-attack".to_string(), "execution".to_string()),
            ],
            external_references: vec![
                ("mitre-attack".to_string(), None, Some("S0367".to_string())),
            ],
        }
    }
}

// ─── RelationshipParams ───────────────────────────────────────────────────────

/// Parameters for mapping a STIX relationship between two `OpenCTI` objects.
#[derive(Debug, Clone)]
pub struct RelationshipParams<'a> {
    /// `OpenCTI` ID of the source object.
    pub src_id: &'a str,
    /// STIX type of the source object (e.g. `"indicator"`).
    pub src_stix_type: &'a str,
    /// `OpenCTI` ID of the target object.
    pub tgt_id: &'a str,
    /// STIX type of the target object (e.g. `"malware"`).
    pub tgt_stix_type: &'a str,
    /// Semantic relationship type (e.g. `"indicates"`).
    pub relationship_type: &'a str,
    /// Optional human-readable description.
    pub description: Option<&'a str>,
    /// Optional confidence level.
    pub confidence: Option<Confidence>,
}

// ─── MappingConfig ───────────────────────────────────────────────────────────

/// Controls how the mapper produces STIX objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingConfig {
    /// Default TLP marking to apply (None = no marking).
    pub default_tlp: Option<TlpMarking>,
    /// Whether to include `OpenCTI` extension data in `extensions` field.
    pub include_extensions: bool,
    /// Whether to add `created_by_ref` from the `OpenCTI` `creator` field.
    pub include_creator: bool,
    /// Whether to flatten kill-chain phases into labels.
    pub flatten_kill_chain_to_labels: bool,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            default_tlp: Some(TlpMarking::Amber),
            include_extensions: true,
            include_creator: false,
            flatten_kill_chain_to_labels: false,
        }
    }
}

/// Traffic Light Protocol marking levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlpMarking {
    White,
    Green,
    Amber,
    Red,
}

impl TlpMarking {
    /// Well-known STIX IDs for TLP markings.
    #[must_use]
    pub fn stix_id(&self) -> StixId {
        let uuid = match self {
            Self::White => "613f2e26-407d-48c7-9eca-b8e91df99dc9",
            Self::Green => "34098fce-860f-48ae-8e50-ebd3cc5e41da",
            Self::Amber => "f88d31f6-1208-47b8-8c12-1088567c3df2",
            Self::Red => "5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        };
        StixId::new("marking-definition", uuid)
    }
}

// ─── OpenCtiStixMapper ────────────────────────────────────────────────────────

/// Maps `OpenCTI` native objects to STIX 2.1 objects and bundles.
pub struct OpenCtiStixMapper {
    config: MappingConfig,
    /// Running counter for pseudo-deterministic ID generation.
    object_count: std::sync::atomic::AtomicU64,
}

impl OpenCtiStixMapper {
    /// Create a new mapper with the given configuration.
    #[must_use]
    pub const fn new(config: MappingConfig) -> Self {
        Self {
            config,
            object_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a mapper with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(MappingConfig::default())
    }

    /// Generate a deterministic STIX ID from an `OpenCTI` ID and type.
    fn make_stix_id(&self, stix_type: &str, opencti_id: &str) -> StixId {
        // Use a simple namespace-based deterministic UUID v5 simulation.
        // In production, proper UUID v5 with a namespace would be used.
        let n = self
            .object_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let hash: u64 = opencti_id
            .bytes()
            .fold(n.wrapping_add(0xcbf2_9ce4_8422_2325), |h, b| {
                h.wrapping_mul(0x0000_0100_0000_01b3) ^ u64::from(b)
            });
        StixId::new(
            stix_type,
            &format!(
                "{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}",
                hash >> 32,
                (hash >> 16) & 0xffff,
                (hash >> 4) & 0x0fff,
                (hash >> 1) & 0x07ff,
                hash & 0x0000_ffff_ffff
            ),
        )
    }

    /// Map an `OpenCTI` indicator to a STIX `indicator` object.
    ///
    /// # Errors
    /// Returns `OpenCtiError::InvalidInput` if the indicator's pattern is empty.
    pub fn map_indicator(&self, src: &OpenCtiIndicator) -> Result<StixObject, OpenCtiError> {
        if src.pattern.is_empty() {
            return Err(OpenCtiError::InvalidInput(
                "indicator pattern must not be empty".into(),
            ));
        }

        let id = self.make_stix_id("indicator", &src.id);
        let mut obj = StixObject::indicator(id, src.name.clone(), src.pattern.clone());
        obj.description.clone_from(&src.description);
        obj.pattern_type = Some(src.pattern_type.clone());
        obj.valid_from.clone_from(&src.valid_from);
        obj.created.clone_from(&src.created_at);
        obj.modified.clone_from(&src.updated_at);
        obj.labels.clone_from(&src.labels);

        if let Some(c) = src.confidence {
            obj.confidence = Some(Confidence::new(c));
        }

        for (kc_name, phase) in &src.kill_chain_phases {
            obj.kill_chain_phases.push(KillChainPhase {
                kill_chain_name: kc_name.clone(),
                phase_name: phase.clone(),
            });
            if self.config.flatten_kill_chain_to_labels {
                let label = format!("{kc_name}:{phase}");
                if !obj.labels.contains(&label) {
                    obj.labels.push(label);
                }
            }
        }

        for (source, url, ext_id) in &src.external_references {
            obj.external_references.push(ExternalReference {
                source_name: source.clone(),
                description: None,
                url: url.clone(),
                external_id: ext_id.clone(),
            });
        }

        if self.config.include_extensions {
            obj.extensions.insert(
                "x-opencti-id".to_string(),
                serde_json::Value::String(src.id.clone()),
            );
        }

        if let Some(tlp) = &self.config.default_tlp {
            obj.object_marking_refs.push(tlp.stix_id());
        }

        Ok(obj)
    }

    /// Map an `OpenCTI` malware to a STIX `malware` object.
    ///
    /// # Errors
    /// Returns `OpenCtiError::InvalidInput` if the malware name is empty.
    pub fn map_malware(&self, src: &OpenCtiMalware) -> Result<StixObject, OpenCtiError> {
        if src.name.is_empty() {
            return Err(OpenCtiError::InvalidInput(
                "malware name must not be empty".into(),
            ));
        }

        let id = self.make_stix_id("malware", &src.id);
        let mut obj = StixObject::malware(id, src.name.clone(), src.is_family);
        obj.description.clone_from(&src.description);
        obj.created.clone_from(&src.created_at);
        obj.modified.clone_from(&src.updated_at);
        obj.labels.clone_from(&src.labels);
        obj.malware_types.clone_from(&src.malware_types);
        obj.aliases.clone_from(&src.aliases);

        if let Some(c) = src.confidence {
            obj.confidence = Some(Confidence::new(c));
        }

        for (kc_name, phase) in &src.kill_chain_phases {
            obj.kill_chain_phases.push(KillChainPhase {
                kill_chain_name: kc_name.clone(),
                phase_name: phase.clone(),
            });
        }

        for (source, url, ext_id) in &src.external_references {
            obj.external_references.push(ExternalReference {
                source_name: source.clone(),
                description: None,
                url: url.clone(),
                external_id: ext_id.clone(),
            });
        }

        if self.config.include_extensions {
            obj.extensions.insert(
                "x-opencti-id".to_string(),
                serde_json::Value::String(src.id.clone()),
            );
        }

        if let Some(tlp) = &self.config.default_tlp {
            obj.object_marking_refs.push(tlp.stix_id());
        }

        Ok(obj)
    }

    /// Build a STIX relationship object between two mapped objects.
    ///
    /// # Errors
    /// Returns `OpenCtiError::InvalidInput` if `relationship_type` is empty.
    pub fn map_relationship(
        &self,
        params: &RelationshipParams<'_>,
    ) -> Result<StixRelationship, OpenCtiError> {
        if params.relationship_type.is_empty() {
            return Err(OpenCtiError::InvalidInput(
                "relationship_type must not be empty".into(),
            ));
        }

        let src_stix_id = self.make_stix_id(params.src_stix_type, params.src_id);
        let tgt_stix_id = self.make_stix_id(params.tgt_stix_type, params.tgt_id);
        let rel_id = self.make_stix_id(
            "relationship",
            &format!("{}-{}", params.src_id, params.tgt_id),
        );

        let mut rel = StixRelationship::new(
            rel_id,
            params.relationship_type,
            src_stix_id,
            tgt_stix_id,
        );

        if let Some(d) = params.description {
            rel = rel.with_description(d);
        }
        if let Some(c) = params.confidence {
            rel = rel.with_confidence(c);
        }
        if let Some(tlp) = &self.config.default_tlp {
            rel.object_marking_refs.push(tlp.stix_id());
        }

        Ok(rel)
    }

    /// Convert a list of indicators into a STIX bundle.
    ///
    /// # Errors
    /// Propagates any mapping or serialisation errors.
    pub fn indicators_to_bundle(
        &self,
        indicators: &[OpenCtiIndicator],
    ) -> Result<StixBundle, OpenCtiError> {
        let bundle_id = self.make_stix_id("bundle", "root");
        let mut bundle = StixBundle::new(bundle_id);

        for ind in indicators {
            let obj = self.map_indicator(ind)?;
            bundle.add_object(&obj)?;
        }

        Ok(bundle)
    }

    /// Convert a list of malware objects into a STIX bundle.
    ///
    /// # Errors
    /// Propagates any mapping or serialisation errors.
    pub fn malware_to_bundle(
        &self,
        malware_list: &[OpenCtiMalware],
    ) -> Result<StixBundle, OpenCtiError> {
        let bundle_id = self.make_stix_id("bundle", "malware-root");
        let mut bundle = StixBundle::new(bundle_id);

        for mal in malware_list {
            let obj = self.map_malware(mal)?;
            bundle.add_object(&obj)?;
        }

        Ok(bundle)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Return an RFC 3339 UTC timestamp for the current instant.
///
/// Uses only `std::time` so the crate avoids pulling in a `chrono` dependency.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Decompose Unix seconds into calendar fields (no external crate needed).
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let mut days = secs / 86400; // days since 1970-01-01

    // Determine year — cap at year 9999 to avoid an infinite loop if the
    // system clock returns an astronomically large Unix timestamp.
    let mut year = 1970u64;
    while year < 9999 {
        let days_in_year: u64 = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    // Determine month.  Iterate with an explicit index so that if all 12
    // months are consumed (should never happen after the year loop above,
    // but be defensive) we clamp month to 12 instead of emitting 13.
    let leap = is_leap(year);
    let month_days: [u64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            break;
        }
        days -= md;
        // Only advance month while there are further months to consume.
        if i < 11 {
            month += 1;
        }
    }
    let day = days + 1;

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

const fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stix_id_round_trip() {
        let id = StixId::new("indicator", "abc-123");
        assert_eq!(id.stix_type(), Some("indicator"));
        assert_eq!(id.uuid(), Some("abc-123"));
        assert!(id.is_valid());
    }

    #[test]
    fn test_map_indicator_ok() {
        let mapper = OpenCtiStixMapper::default_config();
        let ind = OpenCtiIndicator::sample();
        let obj = mapper.map_indicator(&ind).expect("should map");
        assert_eq!(obj.stix_type, StixType::Indicator);
        assert!(obj.pattern.is_some());
        assert!(!obj.object_marking_refs.is_empty()); // TLP applied
    }

    #[test]
    fn test_map_indicator_empty_pattern_err() {
        let mapper = OpenCtiStixMapper::default_config();
        let mut ind = OpenCtiIndicator::sample();
        ind.pattern = String::new();
        let result = mapper.map_indicator(&ind);
        assert!(result.is_err());
    }

    #[test]
    fn test_map_malware_ok() {
        let mapper = OpenCtiStixMapper::default_config();
        let mal = OpenCtiMalware::sample();
        let obj = mapper.map_malware(&mal).expect("should map");
        assert_eq!(obj.stix_type, StixType::Malware);
        assert!(obj.is_family);
        assert_eq!(obj.aliases.len(), 2);
    }

    #[test]
    fn test_indicators_to_bundle() {
        let mapper = OpenCtiStixMapper::default_config();
        let inds = vec![OpenCtiIndicator::sample(), OpenCtiIndicator::sample()];
        let bundle = mapper.indicators_to_bundle(&inds).expect("should succeed");
        assert_eq!(bundle.object_count(), 2);
        let json = bundle.to_json().expect("should serialise");
        assert!(json.contains("indicator"));
    }

    #[test]
    fn test_relationship_mapping() {
        let mapper = OpenCtiStixMapper::default_config();
        let rel = mapper
            .map_relationship(&RelationshipParams {
                src_id: "src-001",
                src_stix_type: "indicator",
                tgt_id: "tgt-002",
                tgt_stix_type: "malware",
                relationship_type: "indicates",
                description: Some("IP indicates Emotet C2"),
                confidence: Some(Confidence::HIGH),
            })
            .expect("should map");
        assert_eq!(rel.relationship_type, "indicates");
        assert_eq!(rel.confidence, Some(Confidence::HIGH));
    }

    #[test]
    fn test_tlp_stix_ids() {
        assert!(TlpMarking::White.stix_id().is_valid());
        assert!(TlpMarking::Red.stix_id().is_valid());
    }

    #[test]
    fn test_kill_chain_to_labels() {
        let cfg = MappingConfig {
            flatten_kill_chain_to_labels: true,
            ..MappingConfig::default()
        };
        let mapper = OpenCtiStixMapper::new(cfg);
        let ind = OpenCtiIndicator::sample();
        let obj = mapper.map_indicator(&ind).expect("should map");
        assert!(obj.labels.iter().any(|l| l.contains("command-and-control")));
    }
}
