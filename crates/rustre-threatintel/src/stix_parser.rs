//! STIX 2.x threat intelligence bundle parser.
//!
//! Deserialises STIX 2.1 JSON bundles into typed Rust objects.  Supported
//! STIX Domain Object (SDO) types: `indicator`, `threat-actor`, `malware`,
//! `campaign`, `tool`, `relationship`, `attack-pattern`, `identity`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Primitive STIX identifier
// ---------------------------------------------------------------------------

/// A STIX 2.1 identifier (e.g. `"indicator--abcdef12-..."`).
pub type StixId = String;

// ---------------------------------------------------------------------------
// StixObject — top-level SDO variant
// ---------------------------------------------------------------------------

/// A single parsed STIX Domain Object (SDO) or Relationship Object (SRO).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum StixObject {
    Indicator(Indicator),
    ThreatActor(ThreatActor),
    Malware(MalwareSdo),
    Campaign(CampaignSdo),
    AttackPattern(AttackPattern),
    Tool(Tool),
    Identity(Identity),
    Relationship(Relationship),
    #[serde(other)]
    Unknown,
}

impl StixObject {
    /// Return the STIX `id` of this object, if it can be determined.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Indicator(o) => Some(&o.id),
            Self::ThreatActor(o) => Some(&o.id),
            Self::Malware(o) => Some(&o.id),
            Self::Campaign(o) => Some(&o.id),
            Self::AttackPattern(o) => Some(&o.id),
            Self::Tool(o) => Some(&o.id),
            Self::Identity(o) => Some(&o.id),
            Self::Relationship(o) => Some(&o.id),
            Self::Unknown => None,
        }
    }

    /// Return the `name` field if present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Indicator(o) => Some(&o.name),
            Self::ThreatActor(o) => Some(&o.name),
            Self::Malware(o) => Some(&o.name),
            Self::Campaign(o) => Some(&o.name),
            Self::AttackPattern(o) => Some(&o.name),
            Self::Tool(o) => Some(&o.name),
            Self::Identity(o) => Some(&o.name),
            _ => None,
        }
    }

    /// Return the type tag string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Indicator(_) => "indicator",
            Self::ThreatActor(_) => "threat-actor",
            Self::Malware(_) => "malware",
            Self::Campaign(_) => "campaign",
            Self::AttackPattern(_) => "attack-pattern",
            Self::Tool(_) => "tool",
            Self::Identity(_) => "identity",
            Self::Relationship(_) => "relationship",
            Self::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// STIX Domain Objects
// ---------------------------------------------------------------------------

/// `indicator` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub id: StixId,
    pub name: String,
    pub description: Option<String>,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub confidence: Option<u8>,
    pub labels: Option<Vec<String>>,
    pub indicator_types: Option<Vec<String>>,
    #[serde(default)]
    pub object_marking_refs: Vec<StixId>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
}

impl Indicator {
    /// Returns `true` if the pattern references a file hash.
    #[must_use]
    pub fn is_file_hash(&self) -> bool {
        self.pattern.contains("file:hashes")
    }

    /// Returns `true` if the pattern references a network indicator.
    #[must_use]
    pub fn is_network_indicator(&self) -> bool {
        self.pattern.contains("ipv4-addr")
            || self.pattern.contains("domain-name")
            || self.pattern.contains("url:value")
    }

    /// Parse the `pattern` string and extract the indicator value.
    ///
    /// Handles simple patterns of the form `[type:field = 'value']`.
    #[must_use]
    pub fn extract_value(&self) -> Option<String> {
        let p = &self.pattern;

        // Scan for the closing quote honouring backslash escapes. A literal
        // quote inside the value is written `\'` in STIX, so stopping at the
        // first raw quote truncates the value silently — which is exactly what
        // this crate's own `export_stix` output used to trigger.
        fn unescape_until(rest: &str, quote: char) -> Option<String> {
            let mut out = String::new();
            let mut chars = rest.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    // A trailing backslash is malformed; treat the literal as
                    // unterminated rather than inventing a character.
                    out.push(chars.next()?);
                } else if c == quote {
                    return Some(out);
                } else {
                    out.push(c);
                }
            }
            None
        }

        // Last occurrence: an escaped `= '` inside the value cannot match this
        // marker, so the last raw one is the operator of the final comparison.
        let marker = "= '";
        if let Some(start) = p.rfind(marker) {
            if let Some(v) = unescape_until(&p[start + marker.len()..], '\'') {
                return Some(v);
            }
        }
        let marker2 = "= \"";
        if let Some(start) = p.rfind(marker2) {
            if let Some(v) = unescape_until(&p[start + marker2.len()..], '"') {
                return Some(v);
            }
        }
        None
    }
}

/// `threat-actor` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub id: StixId,
    pub name: String,
    pub description: Option<String>,
    pub threat_actor_types: Option<Vec<String>>,
    pub aliases: Option<Vec<String>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub sophistication: Option<String>,
    pub resource_level: Option<String>,
    pub primary_motivation: Option<String>,
    pub secondary_motivations: Option<Vec<String>>,
    pub goals: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub confidence: Option<u8>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
}

/// `malware` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareSdo {
    pub id: StixId,
    pub name: String,
    pub description: Option<String>,
    pub malware_types: Option<Vec<String>>,
    pub is_family: Option<bool>,
    pub aliases: Option<Vec<String>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub operating_system_refs: Option<Vec<StixId>>,
    pub confidence: Option<u8>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
}

impl MalwareSdo {
    /// Returns `true` if this is a malware family (vs. a specific sample).
    #[must_use]
    pub fn is_family(&self) -> bool {
        self.is_family.unwrap_or(false)
    }
}

/// `campaign` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSdo {
    pub id: StixId,
    pub name: String,
    pub description: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub objective: Option<String>,
    pub confidence: Option<u8>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
}

/// `attack-pattern` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: StixId,
    pub name: String,
    pub description: Option<String>,
    pub aliases: Option<Vec<String>>,
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    pub confidence: Option<u8>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
}

impl AttackPattern {
    /// Extract MITRE ATT&CK technique IDs from external references.
    #[must_use]
    pub fn mitre_technique_ids(&self) -> Vec<String> {
        self.external_references
            .iter()
            .filter(|r| r.source_name.contains("mitre-attack"))
            .filter_map(|r| r.external_id.clone())
            .collect()
    }
}

/// `tool` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub id: StixId,
    pub name: String,
    pub description: Option<String>,
    pub tool_types: Option<Vec<String>>,
    pub aliases: Option<Vec<String>>,
    pub kill_chain_phases: Option<Vec<KillChainPhase>>,
    pub confidence: Option<u8>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
}

/// `identity` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: StixId,
    pub name: String,
    pub description: Option<String>,
    pub identity_class: Option<String>,
    pub sectors: Option<Vec<String>>,
    pub contact_information: Option<String>,
    pub confidence: Option<u8>,
}

/// `relationship` SRO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub id: StixId,
    pub relationship_type: String,
    pub source_ref: StixId,
    pub target_ref: StixId,
    pub description: Option<String>,
    pub start_time: Option<String>,
    pub stop_time: Option<String>,
    pub confidence: Option<u8>,
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Kill-chain phase as used in STIX 2.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

/// External reference to a knowledge base or URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source_name: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub external_id: Option<String>,
    pub hashes: Option<HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// StixBundle
// ---------------------------------------------------------------------------

/// A STIX 2.1 bundle containing a collection of [`StixObject`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    /// Bundle type (must be `"bundle"`).
    #[serde(rename = "type")]
    pub bundle_type: String,
    /// Spec version (e.g. `"2.1"`).
    pub spec_version: String,
    /// Bundle identifier.
    pub id: String,
    /// Objects contained in the bundle.
    #[serde(default)]
    pub objects: Vec<StixObject>,
}

impl StixBundle {
    /// Parse a STIX bundle from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] if the JSON is malformed, the bundle
    /// structure is invalid, or `json` exceeds [`Self::MAX_INPUT_BYTES`].
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        // `MAX_INPUT_BYTES` is documented as applying to this function as well
        // as to `from_bytes`, but only `from_bytes` enforced it — so the very
        // same bundle was size-limited as `&[u8]` and unbounded as `&str`.
        if json.len() > Self::MAX_INPUT_BYTES {
            return serde_json::from_str::<Self>(
                "{\"__rustre_error\":\"input exceeds maximum allowed size\"}"
            );
        }
        serde_json::from_str(json)
    }

    /// Maximum byte length accepted by [`StixBundle::from_bytes`] and
    /// [`StixBundle::from_json`].  Inputs that exceed this limit are rejected
    /// to prevent unbounded deserialization of adversarially large bundles.
    pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024; // 256 MiB

    /// Parse a STIX bundle from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] on parse failure or if `bytes` exceeds
    /// [`Self::MAX_INPUT_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        if bytes.len() > Self::MAX_INPUT_BYTES {
            // Construct a serde_json error for "data too large" by trying to
            // deserialise an intentionally invalid token so we get a typed error.
            return serde_json::from_str::<Self>(
                "{\"__rustre_error\":\"input exceeds maximum allowed size\"}"
            );
        }
        serde_json::from_slice(bytes)
    }

    /// Serialise this bundle to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] on serialisation failure.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Total number of objects in the bundle.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Return all `indicator` objects.
    #[must_use]
    pub fn indicators(&self) -> Vec<&Indicator> {
        self.objects
            .iter()
            .filter_map(|o| {
                if let StixObject::Indicator(i) = o {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all `threat-actor` objects.
    #[must_use]
    pub fn threat_actors(&self) -> Vec<&ThreatActor> {
        self.objects
            .iter()
            .filter_map(|o| {
                if let StixObject::ThreatActor(t) = o {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all `relationship` objects.
    #[must_use]
    pub fn relationships(&self) -> Vec<&Relationship> {
        self.objects
            .iter()
            .filter_map(|o| {
                if let StixObject::Relationship(r) = o {
                    Some(r)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all `malware` objects.
    #[must_use]
    pub fn malware_objects(&self) -> Vec<&MalwareSdo> {
        self.objects
            .iter()
            .filter_map(|o| {
                if let StixObject::Malware(m) = o {
                    Some(m)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Build an object index by STIX id.
    #[must_use]
    pub fn build_id_index(&self) -> HashMap<&str, &StixObject> {
        self.objects
            .iter()
            .filter_map(|o| o.id().map(|id| (id, o)))
            .collect()
    }

    /// Return objects that are related to `target_id` (where this object is
    /// the source of a relationship).
    #[must_use]
    pub fn related_to(&self, target_id: &str) -> Vec<&StixObject> {
        let idx = self.build_id_index();
        self.relationships()
            .iter()
            .filter(|r| r.target_ref == target_id)
            .filter_map(|r| idx.get(r.source_ref.as_str()).copied())
            .collect()
    }

    /// Verify that `bundle_type == "bundle"` and `spec_version` starts with `"2."`.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.bundle_type == "bundle" && self.spec_version.starts_with("2.")
    }

    /// Return all attack-pattern objects.
    #[must_use]
    pub fn attack_patterns(&self) -> Vec<&AttackPattern> {
        self.objects
            .iter()
            .filter_map(|o| {
                if let StixObject::AttackPattern(a) = o {
                    Some(a)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract all MITRE ATT&CK technique IDs referenced by attack-patterns.
    #[must_use]
    pub fn all_mitre_technique_ids(&self) -> Vec<String> {
        self.attack_patterns()
            .into_iter()
            .flat_map(AttackPattern::mitre_technique_ids)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_bundle(objects: &serde_json::Value) -> String {
        serde_json::json!({
            "type": "bundle",
            "spec_version": "2.1",
            "id": "bundle--test",
            "objects": objects
        })
        .to_string()
    }

    fn indicator_json() -> serde_json::Value {
        serde_json::json!({
            "type": "indicator",
            "id": "indicator--0001",
            "name": "Malicious hash",
            "pattern": "[file:hashes.'SHA-256' = 'deadbeef']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z"
        })
    }

    fn threat_actor_json() -> serde_json::Value {
        serde_json::json!({
            "type": "threat-actor",
            "id": "threat-actor--0001",
            "name": "APT99"
        })
    }

    fn relationship_json() -> serde_json::Value {
        serde_json::json!({
            "type": "relationship",
            "id": "relationship--0001",
            "relationship_type": "uses",
            "source_ref": "threat-actor--0001",
            "target_ref": "indicator--0001"
        })
    }

    #[test]
    fn test_parse_empty_bundle() {
        let json = minimal_bundle(&serde_json::json!([]));
        let b = StixBundle::from_json(&json).unwrap();
        assert!(b.is_valid());
        assert_eq!(b.object_count(), 0);
    }

    #[test]
    fn test_parse_indicator() {
        let json = minimal_bundle(&serde_json::json!([indicator_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        assert_eq!(b.indicators().len(), 1);
        assert_eq!(b.indicators()[0].name, "Malicious hash");
    }

    #[test]
    fn test_indicator_is_file_hash() {
        let json = minimal_bundle(&serde_json::json!([indicator_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        assert!(b.indicators()[0].is_file_hash());
        assert!(!b.indicators()[0].is_network_indicator());
    }

    #[test]
    fn test_indicator_extract_value() {
        let json = minimal_bundle(&serde_json::json!([indicator_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        let val = b.indicators()[0].extract_value();
        assert_eq!(val, Some("deadbeef".to_string()));
    }

    #[test]
    fn test_parse_threat_actor() {
        let json = minimal_bundle(&serde_json::json!([threat_actor_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        assert_eq!(b.threat_actors().len(), 1);
        assert_eq!(b.threat_actors()[0].name, "APT99");
    }

    #[test]
    fn test_parse_relationship() {
        let json = minimal_bundle(&serde_json::json!([relationship_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        assert_eq!(b.relationships().len(), 1);
        assert_eq!(b.relationships()[0].relationship_type, "uses");
    }

    #[test]
    fn test_bundle_id_index() {
        let json = minimal_bundle(&serde_json::json!([indicator_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        let idx = b.build_id_index();
        assert!(idx.contains_key("indicator--0001"));
    }

    #[test]
    fn test_bundle_related_to() {
        let json = minimal_bundle(&serde_json::json!([
            threat_actor_json(),
            indicator_json(),
            relationship_json()
        ]));
        let b = StixBundle::from_json(&json).unwrap();
        let related = b.related_to("indicator--0001");
        assert!(related.iter().any(|o| o.name() == Some("APT99")));
    }

    #[test]
    fn test_bundle_is_valid() {
        let json = minimal_bundle(&serde_json::json!([]));
        let b = StixBundle::from_json(&json).unwrap();
        assert!(b.is_valid());
    }

    #[test]
    fn test_bundle_invalid_type() {
        let json = serde_json::json!({
            "type": "not-a-bundle",
            "spec_version": "2.1",
            "id": "bundle--x",
            "objects": []
        })
        .to_string();
        let b = StixBundle::from_json(&json).unwrap();
        assert!(!b.is_valid());
    }

    #[test]
    fn test_malware_sdo_is_family() {
        let json = minimal_bundle(&serde_json::json!([{
            "type": "malware",
            "id": "malware--0001",
            "name": "Emotet",
            "is_family": true
        }]));
        let b = StixBundle::from_json(&json).unwrap();
        assert_eq!(b.malware_objects().len(), 1);
        assert!(b.malware_objects()[0].is_family());
    }

    #[test]
    fn test_stix_object_type_name() {
        let json = minimal_bundle(&serde_json::json!([indicator_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        assert_eq!(b.objects[0].type_name(), "indicator");
    }

    #[test]
    fn test_round_trip_json() {
        let json = minimal_bundle(&serde_json::json!([indicator_json()]));
        let b = StixBundle::from_json(&json).unwrap();
        let out = b.to_json().unwrap();
        let b2 = StixBundle::from_json(&out).unwrap();
        assert_eq!(b.object_count(), b2.object_count());
    }

    #[test]
    fn test_unknown_object_type() {
        let json = minimal_bundle(&serde_json::json!([{
            "type": "observed-data",
            "id": "observed-data--0001"
        }]));
        let b = StixBundle::from_json(&json).unwrap();
        // Unknown type should parse as StixObject::Unknown without panicking.
        assert_eq!(b.object_count(), 1);
    }
}
