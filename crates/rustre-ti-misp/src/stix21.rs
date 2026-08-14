//! STIX 2.1 types, serialization, bundle export, and bundle import.
//!
//! Covers the full STIX 2.1 object model used in MISP:
//! Indicator, Malware, `ThreatActor`, `AttackPattern`, Campaign,
//! `CourseOfAction`, Identity, `IntrusionSet`, `ObservedData`, Report,
//! Tool, Vulnerability, Relationship, and Sighting.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// STIX 2.1 base timestamps helpers
// ---------------------------------------------------------------------------

/// Return the current UTC time in STIX 2.1 timestamp format
/// `YYYY-MM-DDTHH:MM:SS.sssZ`.  Falls back to the epoch on error.
fn stix_now() -> String {
    // No external time crate dependency — use a fixed mock in tests,
    // real SystemTime for production.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    epoch_to_stix(secs)
}

/// Convert a Unix timestamp (seconds) to the STIX 2.1 string format.
fn epoch_to_stix(secs: u64) -> String {
    // Minimal ISO-8601 formatter without external dependencies.
    const SECS_PER_DAY: u64 = 86_400;
    const SECS_PER_HOUR: u64 = 3_600;
    const SECS_PER_MINUTE: u64 = 60;

    let days_since_epoch = secs / SECS_PER_DAY;
    let time_of_day = secs % SECS_PER_DAY;

    let h = time_of_day / SECS_PER_HOUR;
    let m = (time_of_day % SECS_PER_HOUR) / SECS_PER_MINUTE;
    let s = time_of_day % SECS_PER_MINUTE;

    // Gregorian calendar calculation from day count.
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.000Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    let mut d = days;
    loop {
        let leap = is_leap(y);
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    let month_days: [u64; 12] = [
        31,
        if is_leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mon = 1u64;
    for &md in &month_days {
        if d < md {
            break;
        }
        d -= md;
        mon += 1;
    }
    (y, mon, d + 1)
}

const fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

// ---------------------------------------------------------------------------
// StixId
// ---------------------------------------------------------------------------

/// A STIX 2.1 identifier: `<type>--<uuid>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StixId(pub String);

impl StixId {
    /// Generate a mock STIX ID for the given type prefix.
    #[must_use]
    pub fn generate(type_prefix: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(1);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        Self(format!("{type_prefix}--00000000-0000-4000-8000-{n:012x}"))
    }

    /// Return the type prefix (part before `--`).
    #[must_use]
    pub fn type_prefix(&self) -> &str {
        self.0.split("--").next().unwrap_or("")
    }
}

impl std::fmt::Display for StixId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// StixKillChainPhase
// ---------------------------------------------------------------------------

/// A MITRE ATT&CK / Lockheed Martin kill chain phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixKillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

// ---------------------------------------------------------------------------
// StixExternalReference
// ---------------------------------------------------------------------------

/// An external reference attached to a STIX object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixExternalReference {
    pub source_name: String,
    pub url: Option<String>,
    pub external_id: Option<String>,
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Granular marking
// ---------------------------------------------------------------------------

/// TLP marking definition reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlpMarking {
    pub definition_type: String,
    pub tlp: String,
}

// ---------------------------------------------------------------------------
// STIX Object types
// ---------------------------------------------------------------------------

/// STIX 2.1 Indicator object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub indicator_types: Vec<String>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub kill_chain_phases: Vec<StixKillChainPhase>,
    pub labels: Vec<String>,
    pub created: String,
    pub modified: String,
    pub external_references: Vec<StixExternalReference>,
}

impl StixIndicator {
    /// Create a new indicator with a STIX pattern.
    #[must_use]
    pub fn new(name: impl Into<String>, pattern: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("indicator"),
            type_: "indicator".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            indicator_types: vec!["malicious-activity".to_string()],
            pattern: pattern.into(),
            pattern_type: "stix".to_string(),
            valid_from: now.clone(),
            valid_until: None,
            kill_chain_phases: Vec::new(),
            labels: Vec::new(),
            created: now.clone(),
            modified: now,
            external_references: Vec::new(),
        }
    }
}

/// STIX 2.1 Malware object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixMalware {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub malware_types: Vec<String>,
    pub is_family: bool,
    pub aliases: Vec<String>,
    pub kill_chain_phases: Vec<StixKillChainPhase>,
    pub labels: Vec<String>,
    pub created: String,
    pub modified: String,
    pub capabilities: Vec<String>,
    pub operating_system_refs: Vec<StixId>,
}

impl StixMalware {
    #[must_use]
    pub fn new(name: impl Into<String>, is_family: bool) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("malware"),
            type_: "malware".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            malware_types: Vec::new(),
            is_family,
            aliases: Vec::new(),
            kill_chain_phases: Vec::new(),
            labels: Vec::new(),
            created: now.clone(),
            modified: now,
            capabilities: Vec::new(),
            operating_system_refs: Vec::new(),
        }
    }
}

/// STIX 2.1 `ThreatActor` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixThreatActor {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub threat_actor_types: Vec<String>,
    pub aliases: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub roles: Vec<String>,
    pub goals: Vec<String>,
    pub sophistication: Option<String>,
    pub resource_level: Option<String>,
    pub primary_motivation: Option<String>,
    pub secondary_motivations: Vec<String>,
    pub labels: Vec<String>,
    pub created: String,
    pub modified: String,
    pub external_references: Vec<StixExternalReference>,
}

impl StixThreatActor {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("threat-actor"),
            type_: "threat-actor".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            threat_actor_types: Vec::new(),
            aliases: Vec::new(),
            first_seen: None,
            last_seen: None,
            roles: Vec::new(),
            goals: Vec::new(),
            sophistication: None,
            resource_level: None,
            primary_motivation: None,
            secondary_motivations: Vec::new(),
            labels: Vec::new(),
            created: now.clone(),
            modified: now,
            external_references: Vec::new(),
        }
    }
}

/// STIX 2.1 `AttackPattern` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixAttackPattern {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub aliases: Vec<String>,
    pub kill_chain_phases: Vec<StixKillChainPhase>,
    pub external_references: Vec<StixExternalReference>,
    pub created: String,
    pub modified: String,
}

impl StixAttackPattern {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("attack-pattern"),
            type_: "attack-pattern".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            aliases: Vec::new(),
            kill_chain_phases: Vec::new(),
            external_references: Vec::new(),
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 Campaign object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixCampaign {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub aliases: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub objective: Option<String>,
    pub created: String,
    pub modified: String,
}

impl StixCampaign {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("campaign"),
            type_: "campaign".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            aliases: Vec::new(),
            first_seen: None,
            last_seen: None,
            objective: None,
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 `CourseOfAction` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixCourseOfAction {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub action_reference: Option<String>,
    pub created: String,
    pub modified: String,
}

impl StixCourseOfAction {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("course-of-action"),
            type_: "course-of-action".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            action_reference: None,
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 Identity object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIdentity {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub identity_class: String,
    pub description: Option<String>,
    pub sectors: Vec<String>,
    pub contact_information: Option<String>,
    pub created: String,
    pub modified: String,
}

impl StixIdentity {
    #[must_use]
    pub fn new(name: impl Into<String>, identity_class: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("identity"),
            type_: "identity".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            identity_class: identity_class.into(),
            description: None,
            sectors: Vec::new(),
            contact_information: None,
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 `IntrusionSet` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIntrusionSet {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub aliases: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub goals: Vec<String>,
    pub resource_level: Option<String>,
    pub primary_motivation: Option<String>,
    pub created: String,
    pub modified: String,
}

impl StixIntrusionSet {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("intrusion-set"),
            type_: "intrusion-set".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            aliases: Vec::new(),
            first_seen: None,
            last_seen: None,
            goals: Vec::new(),
            resource_level: None,
            primary_motivation: None,
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 `ObservedData` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixObservedData {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub first_observed: String,
    pub last_observed: String,
    pub number_observed: u32,
    pub object_refs: Vec<StixId>,
    pub created: String,
    pub modified: String,
}

impl StixObservedData {
    #[must_use]
    pub fn new(first_observed: impl Into<String>, number_observed: u32) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("observed-data"),
            type_: "observed-data".to_string(),
            spec_version: "2.1".to_string(),
            first_observed: first_observed.into(),
            last_observed: now.clone(),
            number_observed,
            object_refs: Vec::new(),
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 Report object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixReport {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub report_types: Vec<String>,
    pub published: String,
    pub object_refs: Vec<StixId>,
    pub labels: Vec<String>,
    pub created: String,
    pub modified: String,
}

impl StixReport {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("report"),
            type_: "report".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            report_types: vec!["threat-report".to_string()],
            published: now.clone(),
            object_refs: Vec::new(),
            labels: Vec::new(),
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 Tool object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixTool {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub tool_types: Vec<String>,
    pub aliases: Vec<String>,
    pub tool_version: Option<String>,
    pub kill_chain_phases: Vec<StixKillChainPhase>,
    pub created: String,
    pub modified: String,
}

impl StixTool {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("tool"),
            type_: "tool".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            tool_types: Vec::new(),
            aliases: Vec::new(),
            tool_version: None,
            kill_chain_phases: Vec::new(),
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 Vulnerability object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixVulnerability {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub external_references: Vec<StixExternalReference>,
    pub created: String,
    pub modified: String,
}

impl StixVulnerability {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("vulnerability"),
            type_: "vulnerability".to_string(),
            spec_version: "2.1".to_string(),
            name: name.into(),
            description: None,
            external_references: Vec::new(),
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 Relationship SRO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixRelationship {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub relationship_type: String,
    pub source_ref: StixId,
    pub target_ref: StixId,
    pub description: Option<String>,
    pub start_time: Option<String>,
    pub stop_time: Option<String>,
    pub created: String,
    pub modified: String,
}

impl StixRelationship {
    #[must_use]
    pub fn new(
        relationship_type: impl Into<String>,
        source_ref: StixId,
        target_ref: StixId,
    ) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("relationship"),
            type_: "relationship".to_string(),
            spec_version: "2.1".to_string(),
            relationship_type: relationship_type.into(),
            source_ref,
            target_ref,
            description: None,
            start_time: None,
            stop_time: None,
            created: now.clone(),
            modified: now,
        }
    }
}

/// STIX 2.1 Sighting SRO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixSighting {
    pub id: StixId,
    #[serde(skip, default)]
    pub type_: String,
    pub spec_version: String,
    pub sighting_of_ref: StixId,
    pub observed_data_refs: Vec<StixId>,
    pub where_sighted_refs: Vec<StixId>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub count: u32,
    pub created: String,
    pub modified: String,
}

impl StixSighting {
    #[must_use]
    pub fn new(sighting_of_ref: StixId) -> Self {
        let now = stix_now();
        Self {
            id: StixId::generate("sighting"),
            type_: "sighting".to_string(),
            spec_version: "2.1".to_string(),
            sighting_of_ref,
            observed_data_refs: Vec::new(),
            where_sighted_refs: Vec::new(),
            first_seen: None,
            last_seen: None,
            count: 1,
            created: now.clone(),
            modified: now,
        }
    }
}

// ---------------------------------------------------------------------------
// StixObject enum (discriminated union over all types)
// ---------------------------------------------------------------------------

/// A STIX 2.1 object — any of the supported SDO/SRO types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum StixObject {
    Indicator(StixIndicator),
    Malware(StixMalware),
    ThreatActor(StixThreatActor),
    AttackPattern(StixAttackPattern),
    Campaign(StixCampaign),
    CourseOfAction(StixCourseOfAction),
    Identity(StixIdentity),
    IntrusionSet(StixIntrusionSet),
    ObservedData(StixObservedData),
    Report(StixReport),
    Tool(StixTool),
    Vulnerability(StixVulnerability),
    Relationship(StixRelationship),
    Sighting(StixSighting),
}

impl StixObject {
    /// Return the STIX type string.
    #[must_use]
    pub const fn stix_type(&self) -> &'static str {
        match self {
            Self::Indicator(_) => "indicator",
            Self::Malware(_) => "malware",
            Self::ThreatActor(_) => "threat-actor",
            Self::AttackPattern(_) => "attack-pattern",
            Self::Campaign(_) => "campaign",
            Self::CourseOfAction(_) => "course-of-action",
            Self::Identity(_) => "identity",
            Self::IntrusionSet(_) => "intrusion-set",
            Self::ObservedData(_) => "observed-data",
            Self::Report(_) => "report",
            Self::Tool(_) => "tool",
            Self::Vulnerability(_) => "vulnerability",
            Self::Relationship(_) => "relationship",
            Self::Sighting(_) => "sighting",
        }
    }

    /// Return the object's STIX ID.
    #[must_use]
    pub const fn id(&self) -> &StixId {
        match self {
            Self::Indicator(o) => &o.id,
            Self::Malware(o) => &o.id,
            Self::ThreatActor(o) => &o.id,
            Self::AttackPattern(o) => &o.id,
            Self::Campaign(o) => &o.id,
            Self::CourseOfAction(o) => &o.id,
            Self::Identity(o) => &o.id,
            Self::IntrusionSet(o) => &o.id,
            Self::ObservedData(o) => &o.id,
            Self::Report(o) => &o.id,
            Self::Tool(o) => &o.id,
            Self::Vulnerability(o) => &o.id,
            Self::Relationship(o) => &o.id,
            Self::Sighting(o) => &o.id,
        }
    }

    /// Return `true` if this is a relationship or sighting (SRO).
    #[must_use]
    pub const fn is_relationship_object(&self) -> bool {
        matches!(self, Self::Relationship(_) | Self::Sighting(_))
    }
}

// ---------------------------------------------------------------------------
// StixBundle
// ---------------------------------------------------------------------------

/// A STIX 2.1 bundle — the top-level container for sharing objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: StixId,
    pub spec_version: String,
    pub objects: Vec<StixObject>,
    /// Arbitrary extension properties.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub extensions: HashMap<String, serde_json::Value>,
}

impl StixBundle {
    /// Create an empty bundle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            type_: "bundle".to_string(),
            id: StixId::generate("bundle"),
            spec_version: "2.1".to_string(),
            objects: Vec::new(),
            extensions: HashMap::new(),
        }
    }

    /// Add an object to the bundle.
    pub fn add(&mut self, obj: StixObject) {
        self.objects.push(obj);
    }

    /// Return all objects of a given STIX type string.
    #[must_use]
    pub fn filter_by_type(&self, stix_type: &str) -> Vec<&StixObject> {
        self.objects
            .iter()
            .filter(|o| o.stix_type() == stix_type)
            .collect()
    }

    /// Find an object by its STIX ID string.
    #[must_use]
    pub fn get_by_id(&self, id: &str) -> Option<&StixObject> {
        self.objects.iter().find(|o| o.id().0 == id)
    }

    /// Return the count of objects.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.objects.len()
    }

    /// Return `true` if the bundle has no objects.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl Default for StixBundle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StixExporter
// ---------------------------------------------------------------------------

/// Exports STIX 2.1 bundles to JSON.
pub struct StixExporter {
    /// Whether to use pretty-printed JSON.
    pub pretty: bool,
}

impl StixExporter {
    /// Create a compact exporter.
    #[must_use]
    pub const fn new() -> Self {
        Self { pretty: false }
    }

    /// Create a pretty-printing exporter.
    #[must_use]
    pub const fn pretty() -> Self {
        Self { pretty: true }
    }

    /// Export a bundle to a JSON string.
    ///
    /// # Errors
    /// Returns the `serde_json` error message as a string.
    pub fn export_bundle(&self, bundle: &StixBundle) -> Result<String, String> {
        if self.pretty {
            serde_json::to_string_pretty(bundle).map_err(|e| e.to_string())
        } else {
            serde_json::to_string(bundle).map_err(|e| e.to_string())
        }
    }

    /// Export a bundle to a `serde_json::Value`.
    ///
    /// # Errors
    /// Returns serialization errors as strings.
    pub fn export_value(&self, bundle: &StixBundle) -> Result<serde_json::Value, String> {
        serde_json::to_value(bundle).map_err(|e| e.to_string())
    }
}

impl Default for StixExporter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StixImporter
// ---------------------------------------------------------------------------

/// Imports STIX 2.1 bundles from JSON.
pub struct StixImporter;

impl StixImporter {
    /// Create a new importer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse a STIX 2.1 bundle from a JSON string.
    ///
    /// # Errors
    /// Returns a string error on JSON parse failure.
    pub fn import_bundle(&self, json: &str) -> Result<StixBundle, String> {
        serde_json::from_str::<StixBundle>(json).map_err(|e| e.to_string())
    }

    /// Parse a STIX 2.1 bundle from a `serde_json::Value`.
    ///
    /// # Errors
    /// Returns a string error on conversion failure.
    pub fn import_value(&self, value: serde_json::Value) -> Result<StixBundle, String> {
        serde_json::from_value::<StixBundle>(value).map_err(|e| e.to_string())
    }
}

impl Default for StixImporter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> StixBundle {
        let mut bundle = StixBundle::new();
        bundle.add(StixObject::Indicator(StixIndicator::new(
            "Malicious Hash",
            "[file:hashes.'SHA-256' = 'deadbeef']",
        )));
        bundle.add(StixObject::Malware(StixMalware::new("Emotet", true)));
        bundle.add(StixObject::ThreatActor(StixThreatActor::new("APT28")));
        bundle
    }

    // ---- StixId ----

    #[test]
    fn test_stix_id_generate() {
        let id = StixId::generate("indicator");
        assert!(id.0.starts_with("indicator--"));
    }

    #[test]
    fn test_stix_id_type_prefix() {
        let id = StixId::generate("malware");
        assert_eq!(id.type_prefix(), "malware");
    }

    #[test]
    fn test_stix_id_display() {
        let id = StixId::generate("campaign");
        assert!(id.to_string().contains("campaign--"));
    }

    // ---- StixIndicator ----

    #[test]
    fn test_indicator_new() {
        let ind = StixIndicator::new("Test", "[file:hashes = 'abc']");
        assert_eq!(ind.type_, "indicator");
        assert_eq!(ind.spec_version, "2.1");
        assert!(!ind.pattern.is_empty());
    }

    #[test]
    fn test_indicator_stix_type() {
        let ind = StixObject::Indicator(StixIndicator::new("T", "p"));
        assert_eq!(ind.stix_type(), "indicator");
    }

    // ---- StixMalware ----

    #[test]
    fn test_malware_new_family() {
        let m = StixMalware::new("Emotet", true);
        assert!(m.is_family);
        assert_eq!(m.type_, "malware");
    }

    // ---- StixRelationship ----

    #[test]
    fn test_relationship_new() {
        let src = StixId::generate("indicator");
        let tgt = StixId::generate("malware");
        let rel = StixRelationship::new("indicates", src.clone(), tgt.clone());
        assert_eq!(rel.relationship_type, "indicates");
        assert_eq!(rel.source_ref, src);
        assert_eq!(rel.target_ref, tgt);
        assert_eq!(rel.type_, "relationship");
    }

    #[test]
    fn test_relationship_is_sro() {
        let src = StixId::generate("indicator");
        let tgt = StixId::generate("malware");
        let rel = StixObject::Relationship(StixRelationship::new("indicates", src, tgt));
        assert!(rel.is_relationship_object());
    }

    // ---- StixSighting ----

    #[test]
    fn test_sighting_new() {
        let ind_id = StixId::generate("indicator");
        let s = StixSighting::new(ind_id.clone());
        assert_eq!(s.sighting_of_ref, ind_id);
        assert_eq!(s.count, 1);
    }

    // ---- StixBundle ----

    #[test]
    fn test_bundle_new() {
        let b = StixBundle::new();
        assert_eq!(b.type_, "bundle");
        assert!(b.is_empty());
    }

    #[test]
    fn test_bundle_add_and_len() {
        let mut b = StixBundle::new();
        b.add(StixObject::Malware(StixMalware::new("TestMalware", false)));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn test_bundle_filter_by_type() {
        let b = sample_bundle();
        let indicators = b.filter_by_type("indicator");
        assert_eq!(indicators.len(), 1);
        let malwares = b.filter_by_type("malware");
        assert_eq!(malwares.len(), 1);
    }

    #[test]
    fn test_bundle_get_by_id_found() {
        let b = sample_bundle();
        let first_id = b.objects[0].id().0.clone();
        assert!(b.get_by_id(&first_id).is_some());
    }

    #[test]
    fn test_bundle_get_by_id_not_found() {
        let b = sample_bundle();
        assert!(b.get_by_id("indicator--nonexistent").is_none());
    }

    // ---- StixExporter ----

    #[test]
    fn test_exporter_export_bundle() {
        let b = sample_bundle();
        let json = StixExporter::new().export_bundle(&b).unwrap();
        assert!(json.contains("\"type\":\"bundle\""));
        assert!(json.contains("indicator"));
    }

    #[test]
    fn test_exporter_pretty() {
        let b = sample_bundle();
        let json = StixExporter::pretty().export_bundle(&b).unwrap();
        assert!(json.contains('\n'));
    }

    #[test]
    fn test_exporter_value() {
        let b = sample_bundle();
        let val = StixExporter::new().export_value(&b).unwrap();
        assert_eq!(val["type"], "bundle");
    }

    // ---- StixImporter ----

    #[test]
    fn test_roundtrip() {
        let b = sample_bundle();
        let json = StixExporter::new().export_bundle(&b).unwrap();
        let b2 = StixImporter::new().import_bundle(&json).unwrap();
        assert_eq!(b2.len(), b.len());
        assert_eq!(b2.type_, "bundle");
    }

    #[test]
    fn test_import_invalid_json() {
        let result = StixImporter::new().import_bundle("not-json");
        assert!(result.is_err());
    }

    // ---- All SDO types ----

    #[test]
    fn test_attack_pattern_new() {
        let ap = StixAttackPattern::new("Spearphishing");
        assert_eq!(ap.type_, "attack-pattern");
    }

    #[test]
    fn test_campaign_new() {
        let c = StixCampaign::new("Operation Aurora");
        assert_eq!(c.type_, "campaign");
    }

    #[test]
    fn test_course_of_action_new() {
        let coa = StixCourseOfAction::new("Block Domain");
        assert_eq!(coa.type_, "course-of-action");
    }

    #[test]
    fn test_identity_new() {
        let id = StixIdentity::new("ACME Corp", "organization");
        assert_eq!(id.identity_class, "organization");
    }

    #[test]
    fn test_intrusion_set_new() {
        let is_ = StixIntrusionSet::new("APT28");
        assert_eq!(is_.type_, "intrusion-set");
    }

    #[test]
    fn test_observed_data_new() {
        let od = StixObservedData::new("2024-01-01T00:00:00.000Z", 1);
        assert_eq!(od.number_observed, 1);
    }

    #[test]
    fn test_report_new() {
        let r = StixReport::new("ThreatReport");
        assert!(r.report_types.contains(&"threat-report".to_string()));
    }

    #[test]
    fn test_tool_new() {
        let t = StixTool::new("Mimikatz");
        assert_eq!(t.type_, "tool");
    }

    #[test]
    fn test_vulnerability_new() {
        let v = StixVulnerability::new("CVE-2021-44228");
        assert_eq!(v.type_, "vulnerability");
    }

    // ---- epoch_to_stix ----

    #[test]
    fn test_epoch_to_stix_format() {
        let ts = epoch_to_stix(0);
        assert!(ts.starts_with("1970-01-01T"));
        assert!(ts.ends_with('Z'));
    }

    // ---- StixBundle roundtrip with all SDO types ----

    #[test]
    fn test_bundle_all_sdo_roundtrip() {
        let mut b = StixBundle::new();
        b.add(StixObject::Indicator(StixIndicator::new(
            "I",
            "[file:hashes = 'abc']",
        )));
        b.add(StixObject::Malware(StixMalware::new("M", false)));
        b.add(StixObject::ThreatActor(StixThreatActor::new("TA")));
        b.add(StixObject::AttackPattern(StixAttackPattern::new("AP")));
        b.add(StixObject::Campaign(StixCampaign::new("C")));
        b.add(StixObject::CourseOfAction(StixCourseOfAction::new("CoA")));
        b.add(StixObject::Identity(StixIdentity::new("Id", "individual")));
        b.add(StixObject::IntrusionSet(StixIntrusionSet::new("IS")));
        b.add(StixObject::ObservedData(StixObservedData::new(
            "2024-01-01T00:00:00.000Z",
            1,
        )));
        b.add(StixObject::Report(StixReport::new("R")));
        b.add(StixObject::Tool(StixTool::new("T")));
        b.add(StixObject::Vulnerability(StixVulnerability::new(
            "CVE-2024-1234",
        )));

        let src_id = b.objects[0].id().clone();
        let tgt_id = b.objects[1].id().clone();
        b.add(StixObject::Relationship(StixRelationship::new(
            "indicates",
            src_id.clone(),
            tgt_id,
        )));
        b.add(StixObject::Sighting(StixSighting::new(src_id)));

        assert_eq!(b.len(), 14);

        let json = StixExporter::new().export_bundle(&b).unwrap();
        let b2 = StixImporter::new().import_bundle(&json).unwrap();
        assert_eq!(b2.len(), b.len());
    }

    #[test]
    fn test_bundle_filter_relationships() {
        let mut b = StixBundle::new();
        let src = StixId::generate("indicator");
        let tgt = StixId::generate("malware");
        b.add(StixObject::Relationship(StixRelationship::new(
            "indicates",
            src,
            tgt,
        )));
        let rels = b.filter_by_type("relationship");
        assert_eq!(rels.len(), 1);
        assert!(rels[0].is_relationship_object());
    }

    #[test]
    fn test_bundle_filter_sightings() {
        let mut b = StixBundle::new();
        let id = StixId::generate("indicator");
        b.add(StixObject::Sighting(StixSighting::new(id)));
        let sightings = b.filter_by_type("sighting");
        assert_eq!(sightings.len(), 1);
        assert!(sightings[0].is_relationship_object());
    }

    // ---- Kill chain phase serde ----

    #[test]
    fn test_kill_chain_phase_serde() {
        let kcp = StixKillChainPhase {
            kill_chain_name: "mitre-attack".to_string(),
            phase_name: "defense-evasion".to_string(),
        };
        let json = serde_json::to_string(&kcp).unwrap();
        let kcp2: StixKillChainPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(kcp2.phase_name, "defense-evasion");
    }

    // ---- External reference serde ----

    #[test]
    fn test_external_reference_serde() {
        let er = StixExternalReference {
            source_name: "mitre-attack".to_string(),
            url: Some("https://attack.mitre.org/techniques/T1055".to_string()),
            external_id: Some("T1055".to_string()),
            description: None,
        };
        let json = serde_json::to_string(&er).unwrap();
        let er2: StixExternalReference = serde_json::from_str(&json).unwrap();
        assert_eq!(er2.external_id.as_deref(), Some("T1055"));
    }

    // ---- StixId uniqueness ----

    #[test]
    fn test_stix_ids_unique() {
        let id1 = StixId::generate("indicator");
        let id2 = StixId::generate("indicator");
        assert_ne!(id1, id2);
    }

    // ---- StixObject id dispatch ----

    #[test]
    fn test_stix_object_id_dispatch_all_types() {
        let objects = vec![
            StixObject::Indicator(StixIndicator::new("I", "p")),
            StixObject::Malware(StixMalware::new("M", false)),
            StixObject::ThreatActor(StixThreatActor::new("TA")),
            StixObject::AttackPattern(StixAttackPattern::new("AP")),
            StixObject::Campaign(StixCampaign::new("C")),
            StixObject::CourseOfAction(StixCourseOfAction::new("CoA")),
            StixObject::Identity(StixIdentity::new("Id", "org")),
            StixObject::IntrusionSet(StixIntrusionSet::new("IS")),
            StixObject::Report(StixReport::new("R")),
            StixObject::Tool(StixTool::new("T")),
            StixObject::Vulnerability(StixVulnerability::new("V")),
        ];
        for obj in &objects {
            assert!(!obj.id().0.is_empty());
            assert!(!obj.stix_type().is_empty());
        }
    }

    // ---- is_leap helper ----

    #[test]
    fn test_is_leap_year_2000() {
        assert!(is_leap(2000));
    }

    #[test]
    fn test_is_not_leap_year_1900() {
        assert!(!is_leap(1900));
    }

    #[test]
    fn test_is_leap_year_2024() {
        assert!(is_leap(2024));
    }

    // ---- export_value contains spec_version ----

    #[test]
    fn test_export_value_spec_version() {
        let b = StixBundle::new();
        let val = StixExporter::new().export_value(&b).unwrap();
        assert_eq!(val["spec_version"], "2.1");
    }

    // ---- importer from value ----

    #[test]
    fn test_import_from_value() {
        let b = sample_bundle();
        let val = StixExporter::new().export_value(&b).unwrap();
        let b2 = StixImporter::new().import_value(val).unwrap();
        assert_eq!(b2.len(), b.len());
    }

    // ---- StixBundle extensions field ----

    #[test]
    fn test_bundle_extensions_empty_by_default() {
        let b = StixBundle::new();
        assert!(b.extensions.is_empty());
    }

    // ---- StixThreatActor fields ----

    #[test]
    fn test_threat_actor_goals_and_motivation() {
        let mut ta = StixThreatActor::new("APT-X");
        ta.goals = vec!["financial-gain".to_string()];
        ta.primary_motivation = Some("financial-gain".to_string());
        ta.sophistication = Some("advanced".to_string());
        let json = serde_json::to_string(&ta).unwrap();
        let ta2: StixThreatActor = serde_json::from_str(&json).unwrap();
        assert_eq!(ta2.goals.len(), 1);
        assert_eq!(ta2.primary_motivation.as_deref(), Some("financial-gain"));
    }

    // ---- StixMalware malware_types ----

    #[test]
    fn test_malware_types_list() {
        let mut m = StixMalware::new("Ransomware Family", true);
        m.malware_types = vec!["ransomware".to_string()];
        let json = serde_json::to_string(&m).unwrap();
        let m2: StixMalware = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.malware_types.len(), 1);
    }

    // ---- StixIndicator valid_until field ----

    #[test]
    fn test_indicator_valid_until() {
        let mut ind = StixIndicator::new("Test", "[file:hashes = 'abc']");
        ind.valid_until = Some("2030-01-01T00:00:00.000Z".to_string());
        let json = serde_json::to_string(&ind).unwrap();
        let ind2: StixIndicator = serde_json::from_str(&json).unwrap();
        assert_eq!(
            ind2.valid_until.as_deref(),
            Some("2030-01-01T00:00:00.000Z")
        );
    }

    // ---- StixReport object_refs ----

    #[test]
    fn test_report_object_refs() {
        let mut r = StixReport::new("TI Report");
        let id = StixId::generate("malware");
        r.object_refs.push(id.clone());
        let json = serde_json::to_string(&r).unwrap();
        let r2: StixReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.object_refs.len(), 1);
        assert_eq!(r2.object_refs[0], id);
    }

    // ---- StixCampaign aliases field ----

    #[test]
    fn test_campaign_aliases() {
        let mut c = StixCampaign::new("Operation Aurora");
        c.aliases = vec!["Aurora".to_string()];
        let json = serde_json::to_string(&c).unwrap();
        let c2: StixCampaign = serde_json::from_str(&json).unwrap();
        assert_eq!(c2.aliases.len(), 1);
    }

    // ---- StixTool tool_version ----

    #[test]
    fn test_tool_version() {
        let mut t = StixTool::new("Mimikatz");
        t.tool_version = Some("2.2.0".to_string());
        let json = serde_json::to_string(&t).unwrap();
        let t2: StixTool = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.tool_version.as_deref(), Some("2.2.0"));
    }
}
