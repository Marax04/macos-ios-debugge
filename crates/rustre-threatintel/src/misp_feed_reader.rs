//! MISP (Malware Information Sharing Platform) feed reader.
//!
//! Parses MISP event JSON exports and REST API responses, extracting
//! attributes, objects, tags, galaxies, and galaxy clusters.  All types
//! implement [`serde::Deserialize`] so they can be loaded directly from
//! JSON files or HTTP response bodies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors produced by the MISP feed reader.
#[derive(Debug)]
pub enum MispError {
    /// JSON deserialization failed.
    Json(serde_json::Error),
    /// The payload does not contain the expected top-level structure.
    InvalidStructure(String),
    /// An attribute UUID is duplicated within one event.
    DuplicateUuid(String),
}

impl std::fmt::Display for MispError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::InvalidStructure(s) => write!(f, "invalid MISP structure: {s}"),
            Self::DuplicateUuid(u) => write!(f, "duplicate UUID: {u}"),
        }
    }
}

impl std::error::Error for MispError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Json(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<serde_json::Error> for MispError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

// ---------------------------------------------------------------------------
// Tag
// ---------------------------------------------------------------------------

/// A MISP tag (classification label attached to events or attributes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MispTag {
    /// Numeric tag ID.
    #[serde(default)]
    pub id: u64,
    /// Tag name (e.g. `"tlp:green"`, `"misp-galaxy:ransomware"`).
    #[serde(default)]
    pub name: String,
    /// Display colour in `#RRGGBB` format.
    #[serde(default)]
    pub colour: String,
    /// Whether this tag is exportable.
    #[serde(default)]
    pub exportable: bool,
    /// Whether the tag is hidden.
    #[serde(default)]
    pub hide_tag: bool,
}

impl MispTag {
    /// Returns `true` if this is a TLP classification tag.
    #[must_use]
    pub fn is_tlp(&self) -> bool {
        self.name.to_lowercase().starts_with("tlp:")
    }

    /// Returns the TLP level string (e.g. `"GREEN"`) or `None`.
    #[must_use]
    pub fn tlp_level(&self) -> Option<&str> {
        let lower = self.name.to_lowercase();
        lower.strip_prefix("tlp:").map(|_rest| {
            // Return a slice of the original name (preserving case) after "tlp:"
            let prefix_len = "tlp:".len();
            &self.name[prefix_len..]
        })
    }
}

// ---------------------------------------------------------------------------
// GalaxyCluster
// ---------------------------------------------------------------------------

/// A single entry in a MISP galaxy cluster (e.g. one MITRE ATT&CK technique).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxyCluster {
    /// Cluster UUID.
    #[serde(default)]
    pub uuid: String,
    /// Cluster type (mirrors the galaxy type).
    #[serde(rename = "type", default)]
    pub cluster_type: String,
    /// Short name/value of the cluster element.
    #[serde(default)]
    pub value: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// External references (ATT&CK technique IDs, etc.).
    #[serde(default)]
    pub meta: HashMap<String, serde_json::Value>,
}

impl MispGalaxyCluster {
    /// Returns the MITRE ATT&CK external ID from `meta.external_id`, if present.
    #[must_use]
    pub fn mitre_id(&self) -> Option<&str> {
        self.meta.get("external_id").and_then(|v| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// Galaxy
// ---------------------------------------------------------------------------

/// A MISP galaxy (collection of semantically related clusters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxy {
    /// Galaxy UUID.
    #[serde(default)]
    pub uuid: String,
    /// Galaxy type (e.g. `"mitre-attack-pattern"`).
    #[serde(rename = "type", default)]
    pub galaxy_type: String,
    /// Human-readable name.
    #[serde(default)]
    pub name: String,
    /// Namespace (e.g. `"mitre-attack"`).
    #[serde(default)]
    pub namespace: String,
    /// Clusters belonging to this galaxy.
    #[serde(rename = "GalaxyCluster", default)]
    pub clusters: Vec<MispGalaxyCluster>,
}

impl MispGalaxy {
    /// Return all ATT&CK technique IDs found in this galaxy's clusters.
    #[must_use]
    pub fn mitre_technique_ids(&self) -> Vec<&str> {
        self.clusters
            .iter()
            .filter_map(|c| c.mitre_id())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// MispObjectReference
// ---------------------------------------------------------------------------

/// A reference between two MISP objects or attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObjectReference {
    /// UUID of this reference record.
    #[serde(default)]
    pub uuid: String,
    /// UUID of the source object.
    #[serde(default)]
    pub object_uuid: String,
    /// UUID of the referenced object or attribute.
    #[serde(default)]
    pub referenced_uuid: String,
    /// Relationship type (e.g. `"related-to"`, `"dropped-by"`).
    #[serde(default)]
    pub relationship_type: String,
    /// Optional comment.
    #[serde(default)]
    pub comment: String,
}

// ---------------------------------------------------------------------------
// MispObject
// ---------------------------------------------------------------------------

/// A MISP object — a structured grouping of related attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObject {
    /// Object UUID.
    #[serde(default)]
    pub uuid: String,
    /// Object template name (e.g. `"domain-ip"`, `"file"`, `"pe"`).
    #[serde(default)]
    pub name: String,
    /// Meta-category (e.g. `"network-activity"`).
    #[serde(default)]
    pub meta_category: String,
    /// Human-readable description of this object instance.
    #[serde(default)]
    pub comment: String,
    /// Template version used.
    #[serde(default)]
    pub template_version: String,
    /// The attributes belonging to this object.
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<MispAttribute>,
    /// Outgoing object references.
    #[serde(rename = "ObjectReference", default)]
    pub object_references: Vec<MispObjectReference>,
    /// Timestamp (Unix epoch seconds as a string in MISP JSON).
    #[serde(default)]
    pub timestamp: String,
    /// Distribution level (0-5).
    #[serde(default)]
    pub distribution: String,
}

impl MispObject {
    /// Find the first attribute whose `object_relation` matches `relation`.
    #[must_use]
    pub fn attribute_by_relation(&self, relation: &str) -> Option<&MispAttribute> {
        self.attributes
            .iter()
            .find(|a| a.object_relation.as_deref() == Some(relation))
    }

    /// Collect all attribute values for a given `object_relation`.
    #[must_use]
    pub fn attribute_values(&self, relation: &str) -> Vec<&str> {
        self.attributes
            .iter()
            .filter(|a| a.object_relation.as_deref() == Some(relation))
            .map(|a| a.value.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// MispAttribute
// ---------------------------------------------------------------------------

/// A single MISP attribute — one observable (IP, domain, hash, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct MispAttribute {
    /// Attribute UUID.
    #[serde(default)]
    pub uuid: String,
    /// Attribute type (e.g. `"ip-dst"`, `"domain"`, `"md5"`).
    #[serde(rename = "type", default)]
    pub attr_type: String,
    /// Category (e.g. `"Network activity"`, `"Payload delivery"`).
    #[serde(default)]
    pub category: String,
    /// The observable value.
    #[serde(default)]
    pub value: String,
    /// Human-readable comment.
    #[serde(default)]
    pub comment: String,
    /// Whether this attribute is an IDS indicator.
    #[serde(default)]
    pub to_ids: bool,
    /// Timestamp (Unix epoch seconds as a string).
    #[serde(default)]
    pub timestamp: String,
    /// Distribution level (0-5).
    #[serde(default)]
    pub distribution: String,
    /// Object relation label (set when the attribute belongs to an object).
    #[serde(default)]
    pub object_relation: Option<String>,
    /// Tags attached to this attribute.
    #[serde(rename = "Tag", default)]
    pub tags: Vec<MispTag>,
}

impl MispAttribute {
    /// Categorise this attribute's type into a broad kind.
    #[must_use]
    pub fn kind(&self) -> AttributeKind {
        match self.attr_type.as_str() {
            "md5" | "sha1" | "sha256" | "sha512" | "ssdeep" | "imphash" | "tlsh" | "pehash"
            | "authentihash" => AttributeKind::Hash,
            "ip-src" | "ip-dst" | "ip-src|port" | "ip-dst|port" => AttributeKind::Ip,
            "domain" | "hostname" | "domain|ip" | "hostname|ip" => AttributeKind::Domain,
            "url" | "uri" => AttributeKind::Url,
            "email" | "email-src" | "email-dst" | "email-subject" | "email-body" => {
                AttributeKind::Email
            }
            "filename" | "filename|md5" | "filename|sha256" | "filepath" => {
                AttributeKind::Filename
            }
            "mutex" => AttributeKind::Mutex,
            "regkey" | "regkey|value" => AttributeKind::RegistryKey,
            "yara" | "sigma" | "snort" | "suricata" => AttributeKind::Signature,
            _ => AttributeKind::Other,
        }
    }

    /// Returns `true` if this attribute should be used as an IDS indicator.
    #[must_use]
    pub const fn is_ids_indicator(&self) -> bool {
        self.to_ids
    }

    /// Resolve the plain value when the type is a composite (`domain|ip`, etc.).
    /// Returns only the first component (before `|`).
    #[must_use]
    pub fn primary_value(&self) -> &str {
        self.value.split('|').next().unwrap_or(&self.value)
    }
}

/// Broad category for a MISP attribute type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributeKind {
    Hash,
    Ip,
    Domain,
    Url,
    Email,
    Filename,
    Mutex,
    RegistryKey,
    Signature,
    Other,
}

impl std::fmt::Display for AttributeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Hash => "Hash",
            Self::Ip => "IP",
            Self::Domain => "Domain",
            Self::Url => "URL",
            Self::Email => "Email",
            Self::Filename => "Filename",
            Self::Mutex => "Mutex",
            Self::RegistryKey => "RegistryKey",
            Self::Signature => "Signature",
            Self::Other => "Other",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// MispEventOrg
// ---------------------------------------------------------------------------

/// Organisation information embedded in MISP events.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MispOrg {
    /// Numeric organisation ID.
    #[serde(default)]
    pub id: String,
    /// Organisation UUID.
    #[serde(default)]
    pub uuid: String,
    /// Organisation name.
    #[serde(default)]
    pub name: String,
}

// ---------------------------------------------------------------------------
// MispEvent
// ---------------------------------------------------------------------------

/// A single MISP event (threat report).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    /// Numeric event ID.
    #[serde(default)]
    pub id: String,
    /// Event UUID.
    #[serde(default)]
    pub uuid: String,
    /// Event title / info field.
    #[serde(default)]
    pub info: String,
    /// Threat level (1=High, 2=Medium, 3=Low, 4=Undefined).
    #[serde(default)]
    pub threat_level_id: String,
    /// Distribution level (0-5).
    #[serde(default)]
    pub distribution: String,
    /// Analysis status (0=Initial, 1=Ongoing, 2=Complete).
    #[serde(default)]
    pub analysis: String,
    /// Creation timestamp (Unix epoch seconds as a string).
    #[serde(default)]
    pub date: String,
    /// Last modification timestamp.
    #[serde(default)]
    pub timestamp: String,
    /// Publishing timestamp.
    #[serde(default)]
    pub publish_timestamp: String,
    /// Whether the event has been published.
    #[serde(default)]
    pub published: bool,
    /// Owning organisation.
    #[serde(rename = "Org", default)]
    pub org: MispOrg,
    /// Organisation that created the event.
    #[serde(rename = "Orgc", default)]
    pub orgc: MispOrg,
    /// Top-level attributes (not belonging to an object).
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<MispAttribute>,
    /// Structured objects.
    #[serde(rename = "Object", default)]
    pub objects: Vec<MispObject>,
    /// Tags on the event.
    #[serde(rename = "Tag", default)]
    pub tags: Vec<MispTag>,
    /// Galaxies (ATT&CK mappings, threat groups, etc.).
    #[serde(rename = "Galaxy", default)]
    pub galaxies: Vec<MispGalaxy>,
}

impl MispEvent {
    /// Collect all attributes — both top-level and those inside objects.
    #[must_use]
    pub fn all_attributes(&self) -> Vec<&MispAttribute> {
        let mut out: Vec<&MispAttribute> = self.attributes.iter().collect();
        for obj in &self.objects {
            out.extend(obj.attributes.iter());
        }
        out
    }

    /// All IDS-flagged attributes.
    #[must_use]
    pub fn ids_attributes(&self) -> Vec<&MispAttribute> {
        self.all_attributes()
            .into_iter()
            .filter(|a| a.is_ids_indicator())
            .collect()
    }

    /// Numeric threat level (1=High … 4=Undefined), or `None` if unparseable.
    #[must_use]
    pub fn threat_level(&self) -> Option<u8> {
        self.threat_level_id.parse().ok()
    }

    /// All MITRE ATT&CK technique IDs mentioned in attached galaxies.
    #[must_use]
    pub fn mitre_technique_ids(&self) -> Vec<&str> {
        self.galaxies
            .iter()
            .flat_map(|g| g.mitre_technique_ids())
            .collect()
    }

    /// All TLP tags on the event.
    #[must_use]
    pub fn tlp_tags(&self) -> Vec<&MispTag> {
        self.tags.iter().filter(|t| t.is_tlp()).collect()
    }

    /// Return the highest (most restrictive) TLP level string, or `None`.
    #[must_use]
    pub fn highest_tlp(&self) -> Option<&str> {
        // Order: RED > AMBER+STRICT > AMBER > GREEN > CLEAR / WHITE
        let order = ["RED", "AMBER+STRICT", "AMBER", "GREEN", "CLEAR", "WHITE"];
        order.iter().find(|&level| self
                .tlp_tags()
                .iter()
                .any(|t| t.tlp_level().is_some_and(|l| l.eq_ignore_ascii_case(level)))).map(|v| v as _)
    }
}

// ---------------------------------------------------------------------------
// MispFeed — top-level wrapper
// ---------------------------------------------------------------------------

/// A MISP feed response (e.g. from `/events/index` or a manifest file).
///
/// MISP exposes several JSON layouts:
/// - A single event wrapped in `{"Event": {...}}`.
/// - A list of events at the top level `[{"Event": {...}}, …]`.
/// - A feed manifest (`{"uuid": {...}, …}`).
///
/// `MispFeed::from_json` handles the first two forms.
#[derive(Debug, Clone, Default)]
pub struct MispFeed {
    /// All parsed events.
    pub events: Vec<MispEvent>,
}

/// Intermediate wrapper matching `{"Event": {...}}`.
#[derive(Debug, Deserialize)]
struct EventWrapper {
    #[serde(rename = "Event")]
    event: MispEvent,
}

impl MispFeed {
    /// Parse a MISP JSON response that contains either a single event
    /// (`{"Event": {...}}`) or an array of event wrappers (`[{"Event":...}]`).
    ///
    /// # Errors
    ///
    /// Returns [`MispError`] if the JSON cannot be deserialized or if `json`
    /// exceeds [`Self::MAX_FEED_BYTES`].
    pub fn from_json(json: &str) -> Result<Self, MispError> {
        if json.len() > Self::MAX_FEED_BYTES {
            return Err(MispError::InvalidStructure(format!(
                "feed payload too large: {} bytes (max {})",
                json.len(),
                Self::MAX_FEED_BYTES,
            )));
        }
        let value: serde_json::Value = serde_json::from_str(json)?;
        Self::from_value(value)
    }

    /// Maximum byte length accepted by [`MispFeed::from_json`] and
    /// [`MispFeed::from_bytes`] — the two entry points into the same parser,
    /// which must not disagree about what they accept.
    /// Inputs beyond this limit are rejected to prevent runaway deserialization.
    pub const MAX_FEED_BYTES: usize = 256 * 1024 * 1024; // 256 MiB

    /// Parse from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MispError`] on deserialization failure or if `data` exceeds
    /// [`Self::MAX_FEED_BYTES`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, MispError> {
        if data.len() > Self::MAX_FEED_BYTES {
            return Err(MispError::InvalidStructure(format!(
                "feed payload too large: {} bytes (max {})",
                data.len(),
                Self::MAX_FEED_BYTES,
            )));
        }
        let value: serde_json::Value = serde_json::from_slice(data)?;
        Self::from_value(value)
    }

    fn from_value(value: serde_json::Value) -> Result<Self, MispError> {
        if value.is_object() {
            if value.get("Event").is_some() {
                let wrapper: EventWrapper = serde_json::from_value(value)?;
                return Ok(Self {
                    events: vec![wrapper.event],
                });
            }
            // Could be a manifest or an unknown object shape — return empty feed.
            return Ok(Self::default());
        }
        if value.is_array() {
            let wrappers: Vec<EventWrapper> = serde_json::from_value(value)?;
            return Ok(Self {
                events: wrappers.into_iter().map(|w| w.event).collect(),
            });
        }
        Err(MispError::InvalidStructure(
            "expected object or array at top level".to_string(),
        ))
    }

    /// Number of events in this feed.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` when the feed contains no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Find an event by UUID.
    #[must_use]
    pub fn find_event(&self, uuid: &str) -> Option<&MispEvent> {
        self.events.iter().find(|e| e.uuid == uuid)
    }

    /// Collect all IDS-flagged attributes across all events.
    #[must_use]
    pub fn all_ids_attributes(&self) -> Vec<&MispAttribute> {
        self.events
            .iter()
            .flat_map(|e| e.ids_attributes())
            .collect()
    }

    /// Collect all attributes of a given `AttributeKind` across all events.
    #[must_use]
    pub fn attributes_by_kind(&self, kind: AttributeKind) -> Vec<&MispAttribute> {
        self.events
            .iter()
            .flat_map(|e| e.all_attributes())
            .filter(|a| a.kind() == kind)
            .collect()
    }

    /// Deduplicated set of all unique tag names across all events.
    #[must_use]
    pub fn all_tag_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .events
            .iter()
            .flat_map(|e| e.tags.iter().map(|t| t.name.clone()))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// All MITRE ATT&CK technique IDs mentioned across all events.
    #[must_use]
    pub fn all_mitre_technique_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .events
            .iter()
            .flat_map(|e| e.mitre_technique_ids().into_iter().map(str::to_owned))
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Validate that no UUID appears more than once within any single event's
    /// attribute list (top-level + in-object).
    ///
    /// Returns the first duplicate UUID found, or `None` if all UUIDs are unique.
    #[must_use]
    pub fn find_duplicate_uuids(&self) -> Option<String> {
        for event in &self.events {
            let mut seen = std::collections::HashSet::new();
            for attr in event.all_attributes() {
                if !attr.uuid.is_empty() && !seen.insert(attr.uuid.clone()) {
                    return Some(attr.uuid.clone());
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// AttributeStats
// ---------------------------------------------------------------------------

/// Summary statistics computed from a collection of MISP attributes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeStats {
    /// Total number of attributes.
    pub total: usize,
    /// Count of IDS-flagged attributes.
    pub ids_count: usize,
    /// Per-kind counts.
    pub by_kind: HashMap<String, usize>,
    /// Per-type counts.
    pub by_type: HashMap<String, usize>,
}

impl AttributeStats {
    /// Compute statistics from a slice of attribute references.
    #[must_use]
    pub fn compute(attrs: &[&MispAttribute]) -> Self {
        let mut stats = Self {
            total: attrs.len(),
            ..Default::default()
        };
        for attr in attrs {
            if attr.to_ids {
                stats.ids_count += 1;
            }
            *stats.by_kind.entry(attr.kind().to_string()).or_insert(0) += 1;
            *stats.by_type.entry(attr.attr_type.clone()).or_insert(0) += 1;
        }
        stats
    }

    /// Most common attribute type.
    #[must_use]
    pub fn top_type(&self) -> Option<(&str, usize)> {
        // `by_type` is a `HashMap`, so resolving a tie by iteration order would
        // make the answer change between runs of the same binary on the same
        // feed. Keys are unique, so falling back to the smallest one keeps this
        // a total order — same rule as `ThreatReportAggregator::aggregate_iocs`.
        self.by_type
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, &v)| (k.as_str(), v))
    }
}

// ---------------------------------------------------------------------------
// MispFeedReader — high-level async-friendly reader
// ---------------------------------------------------------------------------

/// High-level reader that ingests multiple MISP feed payloads and merges them.
#[derive(Debug, Default)]
pub struct MispFeedReader {
    feeds: Vec<MispFeed>,
}

impl MispFeedReader {
    /// Create a new empty reader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a JSON payload, merging its events into the reader.
    ///
    /// # Errors
    ///
    /// Returns [`MispError`] if parsing fails.
    pub fn ingest_json(&mut self, json: &str) -> Result<usize, MispError> {
        let feed = MispFeed::from_json(json)?;
        let count = feed.len();
        self.feeds.push(feed);
        Ok(count)
    }

    /// Ingest raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MispError`] if parsing fails.
    pub fn ingest_bytes(&mut self, data: &[u8]) -> Result<usize, MispError> {
        let feed = MispFeed::from_bytes(data)?;
        let count = feed.len();
        self.feeds.push(feed);
        Ok(count)
    }

    /// Total number of events across all ingested feeds.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.feeds.iter().map(MispFeed::len).sum()
    }

    /// Iterate over all events across all feeds.
    pub fn events(&self) -> impl Iterator<Item = &MispEvent> {
        self.feeds.iter().flat_map(|f| f.events.iter())
    }

    /// All IDS-flagged attributes across all feeds.
    #[must_use]
    pub fn all_ids_attributes(&self) -> Vec<&MispAttribute> {
        self.feeds
            .iter()
            .flat_map(|f| f.all_ids_attributes())
            .collect()
    }

    /// Build a deduplicated index of attribute value → list of attributes
    /// for the given `AttributeKind`.
    #[must_use]
    pub fn value_index(&self, kind: AttributeKind) -> HashMap<&str, Vec<&MispAttribute>> {
        let mut index: HashMap<&str, Vec<&MispAttribute>> = HashMap::new();
        for feed in &self.feeds {
            for attr in feed.attributes_by_kind(kind) {
                index
                    .entry(attr.primary_value())
                    .or_default()
                    .push(attr);
            }
        }
        index
    }

    /// Compute aggregate `AttributeStats` across all ingested events.
    #[must_use]
    pub fn stats(&self) -> AttributeStats {
        let all: Vec<&MispAttribute> = self
            .feeds
            .iter()
            .flat_map(|f| f.events.iter().flat_map(|e| e.all_attributes()))
            .collect();
        AttributeStats::compute(&all)
    }

    /// Find events by a keyword substring match against the `info` field
    /// (case-insensitive).
    #[must_use]
    pub fn search_events(&self, keyword: &str) -> Vec<&MispEvent> {
        let kw = keyword.to_lowercase();
        self.events()
            .filter(|e| e.info.to_lowercase().contains(&kw))
            .collect()
    }

    /// All deduplicated MITRE ATT&CK technique IDs across all feeds.
    #[must_use]
    pub fn all_mitre_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .feeds
            .iter()
            .flat_map(MispFeed::all_mitre_technique_ids)
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_event_json(uuid: &str, info: &str) -> String {
        serde_json::json!({
            "Event": {
                "uuid": uuid,
                "info": info,
                "threat_level_id": "2",
                "Attribute": [
                    {
                        "uuid": "attr-001",
                        "type": "ip-dst",
                        "category": "Network activity",
                        "value": "1.2.3.4",
                        "to_ids": true
                    },
                    {
                        "uuid": "attr-002",
                        "type": "md5",
                        "category": "Payload delivery",
                        "value": "deadbeef00112233deadbeef00112233",
                        "to_ids": true
                    }
                ],
                "Tag": [
                    { "id": 1, "name": "tlp:green", "colour": "#00ff00", "exportable": true }
                ]
            }
        })
        .to_string()
    }

    #[test]
    fn parse_single_event() {
        let json = minimal_event_json("evt-uuid-1", "Test campaign");
        let feed = MispFeed::from_json(&json).unwrap();
        assert_eq!(feed.len(), 1);
        assert_eq!(feed.events[0].info, "Test campaign");
    }

    #[test]
    fn parse_event_array() {
        let json = serde_json::json!([
            { "Event": { "uuid": "a", "info": "Event A" } },
            { "Event": { "uuid": "b", "info": "Event B" } }
        ])
        .to_string();
        let feed = MispFeed::from_json(&json).unwrap();
        assert_eq!(feed.len(), 2);
    }

    #[test]
    fn ids_attributes_filtered() {
        let json = minimal_event_json("evt-uuid-2", "IDS test");
        let feed = MispFeed::from_json(&json).unwrap();
        let ids = feed.all_ids_attributes();
        assert_eq!(ids.len(), 2);
        assert!(ids.iter().all(|a| a.to_ids));
    }

    #[test]
    fn attribute_kind_ip() {
        let attr = MispAttribute {
            uuid: "x".to_string(),
            attr_type: "ip-dst".to_string(),
            category: "Network activity".to_string(),
            value: "10.0.0.1".to_string(),
            ..Default::default()
        };
        assert_eq!(attr.kind(), AttributeKind::Ip);
    }

    #[test]
    fn tlp_tag_detection() {
        let tag = MispTag {
            id: 1,
            name: "tlp:RED".to_string(),
            colour: "#ff0000".to_string(),
            exportable: false,
            hide_tag: false,
        };
        assert!(tag.is_tlp());
        assert_eq!(tag.tlp_level(), Some("RED"));
    }

    #[test]
    fn feed_reader_ingests_multiple() {
        let mut reader = MispFeedReader::new();
        reader
            .ingest_json(&minimal_event_json("e1", "Alpha"))
            .unwrap();
        reader
            .ingest_json(&minimal_event_json("e2", "Beta"))
            .unwrap();
        assert_eq!(reader.event_count(), 2);
    }

    #[test]
    fn feed_reader_search_events() {
        let mut reader = MispFeedReader::new();
        reader
            .ingest_json(&minimal_event_json("e3", "Emotet dropper"))
            .unwrap();
        reader
            .ingest_json(&minimal_event_json("e4", "APT29 phishing"))
            .unwrap();
        let results = reader.search_events("emotet");
        assert_eq!(results.len(), 1);
        assert!(results[0].info.contains("Emotet"));
    }

    #[test]
    fn attribute_stats_total() {
        let json = minimal_event_json("e5", "Stats test");
        let feed = MispFeed::from_json(&json).unwrap();
        let all: Vec<&MispAttribute> = feed.events[0].all_attributes().into_iter().collect();
        let stats = AttributeStats::compute(&all);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.ids_count, 2);
    }

    #[test]
    fn primary_value_composite() {
        let attr = MispAttribute {
            value: "evil.com|1.2.3.4".to_string(),
            attr_type: "domain|ip".to_string(),
            ..Default::default()
        };
        assert_eq!(attr.primary_value(), "evil.com");
    }
}
