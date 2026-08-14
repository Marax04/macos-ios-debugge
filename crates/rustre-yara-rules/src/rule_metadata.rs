// rustre-yara-rules/src/rule_metadata.rs
// Rule metadata management: author, date, description, reference, hash, TLP,
// MITRE ATT&CK, family tags, and metadata validation.

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

// ─── TLP Level ───────────────────────────────────────────────────────────────

/// Traffic Light Protocol (TLP) classification for rule sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TlpLevel {
    /// No restrictions — public.
    White,
    /// Community sharing — trusted community.
    Green,
    /// Limited sharing — specific organisations.
    Amber,
    /// `AmberStrict` — organisation only, no further sharing.
    AmberStrict,
    /// No sharing — internal only.
    Red,
}

impl TlpLevel {
    /// Canonical TLP label string (e.g. `"TLP:WHITE"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::White => "TLP:WHITE",
            Self::Green => "TLP:GREEN",
            Self::Amber => "TLP:AMBER",
            Self::AmberStrict => "TLP:AMBER+STRICT",
            Self::Red => "TLP:RED",
        }
    }

    /// Parse from a string like `"TLP:WHITE"` or `"white"`.
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "WHITE" | "TLP:WHITE" | "TLP_WHITE" => Some(Self::White),
            "GREEN" | "TLP:GREEN" | "TLP_GREEN" => Some(Self::Green),
            "AMBER" | "TLP:AMBER" | "TLP_AMBER" => Some(Self::Amber),
            "AMBER+STRICT" | "TLP:AMBER+STRICT" | "AMBERSTRUCT" | "TLP:AMBERSTRICT" => {
                Some(Self::AmberStrict)
            }
            "RED" | "TLP:RED" | "TLP_RED" => Some(Self::Red),
            _ => None,
        }
    }

    /// Return `true` if this TLP level allows public distribution.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self, Self::White | Self::Green)
    }
}

impl std::fmt::Display for TlpLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ─── MITRE ATT&CK Reference ──────────────────────────────────────────────────

/// A MITRE ATT&CK technique or sub-technique reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreAttack {
    /// Technique ID (e.g. `"T1059.001"` for `PowerShell`).
    pub technique_id: String,
    /// Human-readable technique name.
    pub technique_name: String,
    /// Tactic (e.g. `"Execution"`, `"Persistence"`).
    pub tactic: String,
}

impl MitreAttack {
    /// Create a new MITRE reference.
    #[must_use]
    pub fn new(
        technique_id: impl Into<String>,
        technique_name: impl Into<String>,
        tactic: impl Into<String>,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            technique_name: technique_name.into(),
            tactic: tactic.into(),
        }
    }

    /// Return the MITRE ATT&CK URL for this technique.
    #[must_use]
    pub fn url(&self) -> String {
        let id = self.technique_id.replace('.', "/");
        format!("https://attack.mitre.org/techniques/{id}/")
    }

    /// Return `true` if this is a sub-technique (id contains a dot).
    #[must_use]
    pub fn is_sub_technique(&self) -> bool {
        self.technique_id.contains('.')
    }

    /// Return the parent technique ID (e.g. `"T1059"` from `"T1059.001"`).
    #[must_use]
    pub fn parent_id(&self) -> &str {
        if let Some(dot) = self.technique_id.find('.') {
            &self.technique_id[..dot]
        } else {
            &self.technique_id
        }
    }
}

impl std::fmt::Display for MitreAttack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} — {} ({})", self.technique_id, self.technique_name, self.tactic)
    }
}

// ─── External Reference ──────────────────────────────────────────────────────

/// A URL or CVE reference associated with a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    /// Reference kind: `"url"`, `"cve"`, `"malpedia"`, `"virustotal"`, etc.
    pub kind: String,
    /// The reference value (URL, CVE ID, etc.).
    pub value: String,
    /// Optional human-readable description.
    pub description: Option<String>,
}

impl ExternalReference {
    /// Create a URL reference.
    #[must_use]
    pub fn url(value: impl Into<String>) -> Self {
        Self {
            kind: "url".to_string(),
            value: value.into(),
            description: None,
        }
    }

    /// Create a CVE reference.
    #[must_use]
    pub fn cve(id: impl Into<String>) -> Self {
        Self {
            kind: "cve".to_string(),
            value: id.into(),
            description: None,
        }
    }

    /// Create a Malpedia reference.
    #[must_use]
    pub fn malpedia(family: impl Into<String>) -> Self {
        let fam = family.into();
        let url = format!("https://malpedia.caad.fkie.fraunhofer.de/details/{fam}");
        Self {
            kind: "malpedia".to_string(),
            value: url,
            description: Some(fam),
        }
    }

    /// Return `true` if this is a valid URL reference.
    #[must_use]
    pub fn is_url(&self) -> bool {
        self.value.starts_with("http://") || self.value.starts_with("https://")
    }
}

impl std::fmt::Display for ExternalReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref desc) = self.description {
            write!(f, "[{}] {} ({})", self.kind, self.value, desc)
        } else {
            write!(f, "[{}] {}", self.kind, self.value)
        }
    }
}

// ─── Malware Family Tags ──────────────────────────────────────────────────────

/// Structured tags for a malware family or threat actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyTag {
    /// Family name (e.g. `"Emotet"`, `"CobaltStrike"`).
    pub name: String,
    /// Variant or campaign name (optional).
    pub variant: Option<String>,
    /// Threat actor associated with this family (optional).
    pub actor: Option<String>,
    /// Platform(s) targeted: `"Windows"`, `"Linux"`, `"macOS"`, `"Android"`, etc.
    pub platforms: Vec<String>,
}

impl FamilyTag {
    /// Create a basic family tag.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            variant: None,
            actor: None,
            platforms: Vec::new(),
        }
    }

    /// Builder: set variant.
    #[must_use]
    pub fn with_variant(mut self, variant: impl Into<String>) -> Self {
        self.variant = Some(variant.into());
        self
    }

    /// Builder: set actor.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Builder: add a platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platforms.push(platform.into());
        self
    }
}

impl std::fmt::Display for FamilyTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref v) = self.variant {
            write!(f, "/{v}")?;
        }
        if let Some(ref a) = self.actor {
            write!(f, " [{a}]")?;
        }
        Ok(())
    }
}

// ─── Rich Rule Metadata ───────────────────────────────────────────────────────

/// Full, rich metadata record for a YARA rule.
///
/// Goes beyond the basic [`crate::RuleMeta`] to include TLP, MITRE mappings,
/// external references, family tags, sample hashes, and modification history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Unique rule identifier (e.g. `"source:RuleName"`).
    pub rule_id: String,
    /// Human-readable name matching the YARA rule block.
    pub name: String,
    /// Namespace used in the compiled rule set.
    pub namespace: String,

    // ─── Authorship ──────────────────────────────────────────────────────────
    /// Primary author.
    pub author: String,
    /// Additional contributors.
    pub contributors: Vec<String>,
    /// Organisation or team.
    pub organisation: Option<String>,
    /// Contact email or handle.
    pub contact: Option<String>,

    // ─── Dates ───────────────────────────────────────────────────────────────
    /// Creation date (`YYYY-MM-DD`).
    pub date_created: String,
    /// Last modification date (`YYYY-MM-DD`).
    pub date_modified: String,
    /// Rule version string (semver-ish).
    pub version: String,

    // ─── Description ─────────────────────────────────────────────────────────
    /// Short human-readable description.
    pub description: String,
    /// Long-form analysis notes.
    pub notes: Option<String>,

    // ─── Classification ───────────────────────────────────────────────────────
    /// TLP level for sharing.
    pub tlp: TlpLevel,
    /// Severity level.
    pub severity: String,
    /// Category (malware/packer/crypto/etc).
    pub category: String,
    /// Confidence in the rule accuracy `[0–100]`.
    pub confidence: u8,

    // ─── Threat Intelligence ─────────────────────────────────────────────────
    /// Associated malware families.
    pub families: Vec<FamilyTag>,
    /// MITRE ATT&CK mappings.
    pub mitre_attack: Vec<MitreAttack>,
    /// External references.
    pub references: Vec<ExternalReference>,
    /// Known-bad sample SHA-256 hashes used to derive the rule.
    pub sample_hashes: Vec<String>,

    // ─── Operational ─────────────────────────────────────────────────────────
    /// Tags for quick filtering.
    pub tags: Vec<String>,
    /// Custom key/value pairs from the rule meta section.
    pub custom_fields: HashMap<String, String>,
    /// Whether the rule is currently enabled.
    pub enabled: bool,
    /// Rule text hash (FNV-64 of the condition + strings block).
    pub content_hash: String,
    /// File path where the rule was loaded from.
    pub source_path: String,
    /// Source repository / database name.
    pub source_name: String,
    /// Modification history entries.
    pub history: Vec<HistoryEntry>,
}

impl RuleMetadata {
    /// Create a minimal metadata record.
    #[must_use]
    pub fn new(rule_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            name: name.into(),
            namespace: "default".to_string(),
            author: String::new(),
            contributors: Vec::new(),
            organisation: None,
            contact: None,
            date_created: String::new(),
            date_modified: String::new(),
            version: "1.0.0".to_string(),
            description: String::new(),
            notes: None,
            tlp: TlpLevel::White,
            severity: "medium".to_string(),
            category: "unknown".to_string(),
            confidence: 50,
            families: Vec::new(),
            mitre_attack: Vec::new(),
            references: Vec::new(),
            sample_hashes: Vec::new(),
            tags: Vec::new(),
            custom_fields: HashMap::new(),
            enabled: true,
            content_hash: String::new(),
            source_path: String::new(),
            source_name: String::new(),
            history: Vec::new(),
        }
    }

    /// Add a history entry for a modification.
    pub fn record_change(&mut self, author: &str, description: &str) {
        self.history.push(HistoryEntry {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            author: author.to_string(),
            description: description.to_string(),
        });
    }

    /// Return `true` if this rule is associated with a given MITRE technique ID.
    #[must_use]
    pub fn has_mitre_technique(&self, technique_id: &str) -> bool {
        self.mitre_attack
            .iter()
            .any(|m| m.technique_id == technique_id)
    }

    /// Return all unique tactic names.
    #[must_use]
    pub fn tactics(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.mitre_attack
            .iter()
            .filter(|m| seen.insert(m.tactic.as_str()))
            .map(|m| m.tactic.as_str())
            .collect()
    }

    /// Return the set of targeted platforms across all family tags.
    #[must_use]
    pub fn all_platforms(&self) -> Vec<String> {
        let mut platforms: Vec<String> = self
            .families
            .iter()
            .flat_map(|f| f.platforms.iter().cloned())
            .collect();
        platforms.sort();
        platforms.dedup();
        platforms
    }

    /// Return `true` if any sample hashes are recorded.
    #[must_use]
    pub const fn has_samples(&self) -> bool {
        !self.sample_hashes.is_empty()
    }

    /// Validate and return a list of errors/warnings.
    #[must_use]
    pub fn validate(&self) -> Vec<ValidationIssue> {
        validate_metadata(self)
    }

    /// Return `true` if the rule can be shared publicly based on TLP.
    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.tlp.is_public()
    }

    /// Bump the minor version (e.g. `"1.2.3"` → `"1.3.0"`).
    pub fn bump_minor(&mut self) {
        let parts: Vec<u32> = self
            .version
            .split('.')
            .map(|s| s.parse().unwrap_or(0))
            .collect();
        if parts.len() >= 2 {
            self.version = format!("{}.{}.0", parts[0], parts[1] + 1);
        }
    }

    /// Bump the patch version (e.g. `"1.2.3"` → `"1.2.4"`).
    pub fn bump_patch(&mut self) {
        let parts: Vec<u32> = self
            .version
            .split('.')
            .map(|s| s.parse().unwrap_or(0))
            .collect();
        if parts.len() >= 3 {
            self.version = format!("{}.{}.{}", parts[0], parts[1], parts[2] + 1);
        } else if parts.len() == 2 {
            self.version = format!("{}.{}.1", parts[0], parts[1]);
        }
    }
}

// ─── History Entry ────────────────────────────────────────────────────────────

/// A single entry in a rule's modification history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unix timestamp of the change.
    pub timestamp: u64,
    /// Author of the change.
    pub author: String,
    /// Description of what changed.
    pub description: String,
}

impl std::fmt::Display for HistoryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} — {}", self.timestamp, self.author, self.description)
    }
}

// ─── Validation ───────────────────────────────────────────────────────────────

/// Severity of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    /// The rule will not function correctly without fixing this.
    Error,
    /// The rule is likely to have quality issues.
    Warning,
    /// Informational suggestion.
    Info,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "ERROR"),
            Self::Warning => write!(f, "WARN"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

/// A single validation issue found in rule metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Severity.
    pub severity: IssueSeverity,
    /// Field name that has the issue.
    pub field: String,
    /// Human-readable message.
    pub message: String,
}

impl ValidationIssue {
    fn error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Error,
            field: field.into(),
            message: message.into(),
        }
    }

    fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Warning,
            field: field.into(),
            message: message.into(),
        }
    }

    fn info(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: IssueSeverity::Info,
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.field, self.message)
    }
}

/// Validate a [`RuleMetadata`] record and return all issues found.
#[must_use]
pub fn validate_metadata(meta: &RuleMetadata) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    // Required fields
    if meta.rule_id.is_empty() {
        issues.push(ValidationIssue::error("rule_id", "rule_id must not be empty"));
    }
    if meta.name.is_empty() {
        issues.push(ValidationIssue::error("name", "rule name must not be empty"));
    }

    // Author
    if meta.author.is_empty() {
        issues.push(ValidationIssue::warning("author", "author is not set"));
    }

    // Description
    if meta.description.is_empty() {
        issues.push(ValidationIssue::warning("description", "description is not set"));
    } else if meta.description.len() < 10 {
        issues.push(ValidationIssue::warning(
            "description",
            "description is too short (< 10 chars)",
        ));
    }

    // Date format YYYY-MM-DD
    if meta.date_created.is_empty() {
        issues.push(ValidationIssue::warning("date_created", "date_created is not set"));
    } else if !is_valid_date(&meta.date_created) {
        issues.push(ValidationIssue::warning(
            "date_created",
            "date_created should be in YYYY-MM-DD format",
        ));
    }

    // Version semver
    if !is_valid_version(&meta.version) {
        issues.push(ValidationIssue::warning(
            "version",
            "version should be in MAJOR.MINOR.PATCH format",
        ));
    }

    // Tags
    if meta.tags.is_empty() {
        issues.push(ValidationIssue::info("tags", "no tags set — consider adding family/category tags"));
    }

    // Confidence range
    if meta.confidence > 100 {
        issues.push(ValidationIssue::error(
            "confidence",
            "confidence must be in [0, 100]",
        ));
    }

    // Sample hashes should look like SHA-256 if present.
    for hash in &meta.sample_hashes {
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            issues.push(ValidationIssue::warning(
                "sample_hashes",
                format!("hash '{hash}' does not look like SHA-256"),
            ));
        }
    }

    // References
    for r in &meta.references {
        if r.kind == "url" && !r.is_url() {
            issues.push(ValidationIssue::warning(
                "references",
                format!("reference value '{}' does not start with http:// or https://", r.value),
            ));
        }
    }

    // MITRE technique ID format
    for m in &meta.mitre_attack {
        if !m.technique_id.starts_with('T') {
            issues.push(ValidationIssue::warning(
                "mitre_attack",
                format!("technique_id '{}' should start with 'T'", m.technique_id),
            ));
        }
    }

    // TLP and severity
    if meta.tlp == TlpLevel::Red && meta.confidence > 80 {
        issues.push(ValidationIssue::info(
            "tlp",
            "TLP:RED rule with high confidence — consider downgrading TLP for wider sharing",
        ));
    }

    issues
}

fn is_valid_date(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
}

fn is_valid_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

// ─── Metadata Builder (fluent API) ───────────────────────────────────────────

/// Fluent builder for [`RuleMetadata`].
pub struct MetadataBuilder {
    inner: RuleMetadata,
}

impl MetadataBuilder {
    /// Start building metadata for a rule.
    #[must_use]
    pub fn new(rule_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            inner: RuleMetadata::new(rule_id, name),
        }
    }

    /// Set the author.
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.inner.author = author.into();
        self
    }

    /// Add a contributor.
    #[must_use]
    pub fn contributor(mut self, c: impl Into<String>) -> Self {
        self.inner.contributors.push(c.into());
        self
    }

    /// Set the organisation.
    #[must_use]
    pub fn organisation(mut self, org: impl Into<String>) -> Self {
        self.inner.organisation = Some(org.into());
        self
    }

    /// Set the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.inner.description = desc.into();
        self
    }

    /// Set long-form notes.
    #[must_use]
    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.inner.notes = Some(notes.into());
        self
    }

    /// Set the creation date.
    #[must_use]
    pub fn date_created(mut self, date: impl Into<String>) -> Self {
        self.inner.date_created = date.into();
        self
    }

    /// Set the TLP level.
    #[must_use]
    pub const fn tlp(mut self, tlp: TlpLevel) -> Self {
        self.inner.tlp = tlp;
        self
    }

    /// Set the severity string.
    #[must_use]
    pub fn severity(mut self, sev: impl Into<String>) -> Self {
        self.inner.severity = sev.into();
        self
    }

    /// Set the category string.
    #[must_use]
    pub fn category(mut self, cat: impl Into<String>) -> Self {
        self.inner.category = cat.into();
        self
    }

    /// Set the confidence level.
    #[must_use]
    pub const fn confidence(mut self, c: u8) -> Self {
        self.inner.confidence = c;
        self
    }

    /// Set the rule version.
    #[must_use]
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.inner.version = v.into();
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.inner.tags.push(t.into());
        self
    }

    /// Add multiple tags.
    #[must_use]
    pub fn tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner.tags.extend(tags.into_iter().map(Into::into));
        self
    }

    /// Add a MITRE ATT&CK mapping.
    #[must_use]
    pub fn mitre(mut self, technique_id: &str, name: &str, tactic: &str) -> Self {
        self.inner.mitre_attack.push(MitreAttack::new(technique_id, name, tactic));
        self
    }

    /// Add a URL reference.
    #[must_use]
    pub fn reference_url(mut self, url: impl Into<String>) -> Self {
        self.inner.references.push(ExternalReference::url(url));
        self
    }

    /// Add a CVE reference.
    #[must_use]
    pub fn cve(mut self, id: impl Into<String>) -> Self {
        self.inner.references.push(ExternalReference::cve(id));
        self
    }

    /// Add a sample hash.
    #[must_use]
    pub fn sample_hash(mut self, hash: impl Into<String>) -> Self {
        self.inner.sample_hashes.push(hash.into());
        self
    }

    /// Add a family tag.
    #[must_use]
    pub fn family(mut self, tag: FamilyTag) -> Self {
        self.inner.families.push(tag);
        self
    }

    /// Set the source path.
    #[must_use]
    pub fn source_path(mut self, path: impl Into<String>) -> Self {
        self.inner.source_path = path.into();
        self
    }

    /// Set the source name.
    #[must_use]
    pub fn source_name(mut self, name: impl Into<String>) -> Self {
        self.inner.source_name = name.into();
        self
    }

    /// Finalize and return the metadata.
    #[must_use]
    pub fn build(self) -> RuleMetadata {
        self.inner
    }
}

// ─── Metadata Store ───────────────────────────────────────────────────────────

/// An in-memory registry of rich metadata records keyed by rule ID.
#[derive(Debug, Default)]
pub struct MetadataStore {
    records: HashMap<String, RuleMetadata>,
}

impl MetadataStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a metadata record.
    pub fn upsert(&mut self, meta: RuleMetadata) {
        self.records.insert(meta.rule_id.clone(), meta);
    }

    /// Look up a metadata record by rule ID.
    #[must_use]
    pub fn get(&self, rule_id: &str) -> Option<&RuleMetadata> {
        self.records.get(rule_id)
    }

    /// Mutable look up.
    pub fn get_mut(&mut self, rule_id: &str) -> Option<&mut RuleMetadata> {
        self.records.get_mut(rule_id)
    }

    /// Remove a metadata record.
    pub fn remove(&mut self, rule_id: &str) -> Option<RuleMetadata> {
        self.records.remove(rule_id)
    }

    /// All records.
    #[must_use]
    pub fn all(&self) -> Vec<&RuleMetadata> {
        self.records.values().collect()
    }

    /// Records with a given TLP level.
    #[must_use]
    pub fn by_tlp(&self, tlp: TlpLevel) -> Vec<&RuleMetadata> {
        self.records.values().filter(|m| m.tlp == tlp).collect()
    }

    /// Records for a given family name.
    #[must_use]
    pub fn by_family(&self, family: &str) -> Vec<&RuleMetadata> {
        self.records
            .values()
            .filter(|m| m.families.iter().any(|f| f.name.eq_ignore_ascii_case(family)))
            .collect()
    }

    /// Records tagged with a given MITRE technique.
    #[must_use]
    pub fn by_mitre_technique(&self, technique_id: &str) -> Vec<&RuleMetadata> {
        self.records
            .values()
            .filter(|m| m.has_mitre_technique(technique_id))
            .collect()
    }

    /// Records that have known validation errors.
    #[must_use]
    pub fn invalid_records(&self) -> Vec<(&RuleMetadata, Vec<ValidationIssue>)> {
        self.records
            .values()
            .filter_map(|m| {
                let issues: Vec<_> = m
                    .validate()
                    .into_iter()
                    .filter(|i| i.severity == IssueSeverity::Error)
                    .collect();
                if issues.is_empty() {
                    None
                } else {
                    Some((m, issues))
                }
            })
            .collect()
    }

    /// Total number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Export all records to JSON.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn export_json(&self) -> anyhow::Result<String> {
        let records: Vec<&RuleMetadata> = self.all();
        Ok(serde_json::to_string_pretty(&records)?)
    }

    /// Import records from a JSON string.
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn import_json(&mut self, json: &str) -> anyhow::Result<usize> {
        let records: Vec<RuleMetadata> = serde_json::from_str(json)?;
        let count = records.len();
        for m in records {
            self.upsert(m);
        }
        Ok(count)
    }

    /// Return aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> MetadataStats {
        let mut stats = MetadataStats {
            total: self.records.len(),
            ..MetadataStats::default()
        };
        for m in self.records.values() {
            if m.enabled {
                stats.enabled += 1;
            }
            if m.tlp.is_public() {
                stats.public_tlp += 1;
            }
            if !m.mitre_attack.is_empty() {
                stats.with_mitre += 1;
            }
            if !m.sample_hashes.is_empty() {
                stats.with_samples += 1;
            }
            *stats.by_category.entry(m.category.clone()).or_insert(0) += 1;
            *stats.by_severity.entry(m.severity.clone()).or_insert(0) += 1;
        }
        stats
    }
}

/// Summary statistics for a [`MetadataStore`].
#[derive(Debug, Default)]
pub struct MetadataStats {
    /// Total records.
    pub total: usize,
    /// Enabled records.
    pub enabled: usize,
    /// Records with public TLP.
    pub public_tlp: usize,
    /// Records with MITRE mappings.
    pub with_mitre: usize,
    /// Records with sample hashes.
    pub with_samples: usize,
    /// Count by category.
    pub by_category: HashMap<String, usize>,
    /// Count by severity.
    pub by_severity: HashMap<String, usize>,
}

// ─── Metadata extractor from YARA rule text ───────────────────────────────────

/// Parse the `meta:` section of a YARA rule into a [`RuleMetadata`].
#[must_use]
pub fn parse_metadata_from_yara(rule_text: &str, source_name: &str) -> Option<RuleMetadata> {
    // Find rule name.
    let name_line = rule_text
        .lines()
        .find(|l| l.trim().starts_with("rule ") || l.trim().starts_with("private rule "))?;
    let name = name_line
        .split_whitespace()
        .find(|w| !["rule", "private", "{"].contains(w))
        .map(|w| w.trim_end_matches('{').trim())?
        .to_string();

    let rule_id = format!("{source_name}:{name}");
    let mut meta = RuleMetadata::new(&rule_id, &name);
    meta.source_name = source_name.to_string();

    // Parse meta section.
    let mut in_meta = false;
    for line in rule_text.lines() {
        let t = line.trim();
        if t == "meta:" {
            in_meta = true;
            continue;
        }
        if t == "strings:" || t == "condition:" {
            in_meta = false;
        }
        if !in_meta || !t.contains('=') {
            continue;
        }
        let (key, val) = split_meta_kv(t);
        match key.trim() {
            "author" => meta.author.clone_from(&val),
            "description" | "desc" => meta.description.clone_from(&val),
            "date" => {
                meta.date_created.clone_from(&val);
                meta.date_modified.clone_from(&val);
            }
            "version" => meta.version.clone_from(&val),
            "severity" => meta.severity.clone_from(&val),
            "category" => meta.category.clone_from(&val),
            "tlp" => {
                if let Some(tlp) = TlpLevel::from_label(&val) {
                    meta.tlp = tlp;
                }
            }
            "reference" => meta.references.push(ExternalReference::url(val.clone())),
            "hash" => meta.sample_hashes.push(val.clone()),
            "tags" => {
                meta.tags = val.split(',').map(|s| s.trim().to_string()).collect();
            }
            "mitre_attack" | "mitre" => {
                let technique_id = val.trim().to_string();
                meta.mitre_attack.push(MitreAttack::new(
                    &technique_id,
                    "unknown",
                    "unknown",
                ));
            }
            "confidence" => {
                meta.confidence = val.parse().unwrap_or(50);
            }
            other => {
                meta.custom_fields.insert(other.to_string(), val.clone());
            }
        }
    }

    // Compute content hash.
    meta.content_hash = simple_fnv(rule_text);

    Some(meta)
}

fn split_meta_kv(line: &str) -> (String, String) {
    let pos = line.find('=').unwrap_or(line.len());
    let key = line[..pos].trim().to_string();
    let val = line[pos + 1..]
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    (key, val)
}

fn simple_fnv(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlp_level_label() {
        assert_eq!(TlpLevel::White.label(), "TLP:WHITE");
        assert_eq!(TlpLevel::Red.label(), "TLP:RED");
    }

    #[test]
    fn test_tlp_from_str() {
        assert_eq!(TlpLevel::from_label("TLP:GREEN"), Some(TlpLevel::Green));
        assert_eq!(TlpLevel::from_label("amber"), Some(TlpLevel::Amber));
        assert_eq!(TlpLevel::from_label("INVALID"), None);
    }

    #[test]
    fn test_tlp_is_public() {
        assert!(TlpLevel::White.is_public());
        assert!(TlpLevel::Green.is_public());
        assert!(!TlpLevel::Red.is_public());
    }

    #[test]
    fn test_mitre_attack_url() {
        let m = MitreAttack::new("T1059.001", "PowerShell", "Execution");
        assert!(m.url().contains("T1059/001"));
        assert!(m.is_sub_technique());
        assert_eq!(m.parent_id(), "T1059");
    }

    #[test]
    fn test_external_reference_is_url() {
        let r = ExternalReference::url("https://example.com/report");
        assert!(r.is_url());
        let r2 = ExternalReference::cve("CVE-2024-12345");
        assert!(!r2.is_url());
    }

    #[test]
    fn test_family_tag_display() {
        let tag = FamilyTag::new("Emotet")
            .with_variant("Epoch5")
            .with_actor("TA542");
        let s = tag.to_string();
        assert!(s.contains("Emotet"));
        assert!(s.contains("Epoch5"));
    }

    #[test]
    fn test_metadata_validation_missing_author() {
        let meta = RuleMetadata::new("test:Rule", "Rule");
        let issues = validate_metadata(&meta);
        let has_author_warn = issues
            .iter()
            .any(|i| i.field == "author" && i.severity == IssueSeverity::Warning);
        assert!(has_author_warn);
    }

    #[test]
    fn test_metadata_validation_bad_confidence() {
        let mut meta = RuleMetadata::new("test:Rule", "Rule");
        meta.confidence = 200;
        let issues = validate_metadata(&meta);
        assert!(issues.iter().any(|i| i.field == "confidence" && i.severity == IssueSeverity::Error));
    }

    #[test]
    fn test_metadata_builder() {
        let meta = MetadataBuilder::new("src:TestRule", "TestRule")
            .author("alice")
            .description("Detects something bad")
            .tlp(TlpLevel::Amber)
            .tag("ransomware")
            .mitre("T1486", "Data Encrypted for Impact", "Impact")
            .confidence(85)
            .build();
        assert_eq!(meta.author, "alice");
        assert_eq!(meta.tlp, TlpLevel::Amber);
        assert!(!meta.mitre_attack.is_empty());
        assert_eq!(meta.confidence, 85);
    }

    #[test]
    fn test_metadata_store_upsert_get() {
        let mut store = MetadataStore::new();
        let meta = MetadataBuilder::new("test:A", "A").author("bob").build();
        store.upsert(meta);
        assert_eq!(store.len(), 1);
        assert!(store.get("test:A").is_some());
    }

    #[test]
    fn test_metadata_store_by_tlp() {
        let mut store = MetadataStore::new();
        let m1 = MetadataBuilder::new("test:A", "A").tlp(TlpLevel::White).build();
        let m2 = MetadataBuilder::new("test:B", "B").tlp(TlpLevel::Red).build();
        store.upsert(m1);
        store.upsert(m2);
        assert_eq!(store.by_tlp(TlpLevel::White).len(), 1);
        assert_eq!(store.by_tlp(TlpLevel::Red).len(), 1);
    }

    #[test]
    fn test_parse_metadata_from_yara() {
        let rule = r#"
rule TestRule {
    meta:
        author = "alice"
        description = "Detects TestRule"
        date = "2025-06-01"
        severity = "high"
        tlp = "TLP:AMBER"
    strings:
        $a = "TestRule"
    condition:
        $a
}
"#;
        let meta = parse_metadata_from_yara(rule, "test").unwrap();
        assert_eq!(meta.author, "alice");
        assert_eq!(meta.severity, "high");
        assert_eq!(meta.tlp, TlpLevel::Amber);
        assert!(!meta.content_hash.is_empty());
    }

    #[test]
    fn test_is_valid_date() {
        assert!(is_valid_date("2025-06-01"));
        assert!(!is_valid_date("2025/06/01"));
        assert!(!is_valid_date("20250601"));
    }

    #[test]
    fn test_version_bump() {
        let mut meta = RuleMetadata::new("r:T", "T");
        meta.version = "1.2.3".to_string();
        meta.bump_patch();
        assert_eq!(meta.version, "1.2.4");
        meta.bump_minor();
        assert_eq!(meta.version, "1.3.0");
    }

    #[test]
    fn test_store_export_import_json() {
        let mut store = MetadataStore::new();
        let m = MetadataBuilder::new("test:X", "X").description("desc x").build();
        store.upsert(m);
        let json = store.export_json().unwrap();
        let mut store2 = MetadataStore::new();
        let count = store2.import_json(&json).unwrap();
        assert_eq!(count, 1);
        assert!(store2.get("test:X").is_some());
    }
}
