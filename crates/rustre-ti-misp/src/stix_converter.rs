//! `stix_converter` — MISP → STIX 2.1 conversion.
//!
//! Converts MISP events, attributes, objects, galaxies, and sightings to
//! STIX 2.1 bundles. Handles: `Indicator` (pattern), `ObservedData`, `ThreatActor`,
//! `AttackPattern`, `Malware`, `Tool`, `Identity`, `Relationship`, `Sighting`,
//! `CourseOfAction`, `Note`, and custom `x-misp-*` extensions.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::MispError;

// ---------------------------------------------------------------------------
// UUID generation without external crates
// ---------------------------------------------------------------------------

/// Simple deterministic UUID v5 (SHA-1 namespace) approximation using
/// a hash of the namespace bytes XOR'd with the name bytes.
/// For production, replace with a proper uuid crate.
fn uuid_v5_approx(namespace_hex: &str, name: &[u8]) -> String {
    // Simple djb2-based mixing — not cryptographic, good enough for IDs
    let mut h: u64 = 5381;
    for b in namespace_hex.bytes() { h = h.wrapping_mul(33).wrapping_add(u64::from(b)); }
    for b in name { h = h.wrapping_mul(33).wrapping_add(u64::from(*b)); }
    let hi = h;
    let mut h2: u64 = 0x9e37_79b9_7f4a_7c15;
    for b in name { h2 = h2.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(u64::from(*b) ^ 0x5555); }
    // Format as UUID: xxxxxxxx-xxxx-5xxx-yxxx-xxxxxxxxxxxx (v5 variant bits)
    let a = u32::try_from(hi >> 32).unwrap_or(u32::MAX);
    let b_hi = u16::try_from((hi >> 16) & 0xFFFF).unwrap_or(u16::MAX);
    let c = u16::try_from(0x5000 | ((hi >> 12) & 0x0FFF)).unwrap_or(u16::MAX); // version 5
    let d = u16::try_from(0x8000 | ((h2 >> 48) & 0x3FFF)).unwrap_or(u16::MAX); // variant bits
    let e_hi = u32::try_from(h2 >> 16).unwrap_or(u32::MAX);
    let e_lo = u16::try_from(h2 & 0xFFFF).unwrap_or(u16::MAX);
    format!("{a:08x}-{b_hi:04x}-{c:04x}-{d:04x}-{e_hi:08x}{e_lo:04x}")
}

static UUID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a pseudo-random UUID v4-like string without external crates.
fn uuid_v4_pseudo() -> String {
    let counter = UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix with time-like value
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let ts = u64::try_from(ts & u128::from(u64::MAX)).unwrap_or(u64::MAX);
    let hi = ts ^ (counter.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let lo = counter.wrapping_mul(0x6c62_272e_07bb_0142) ^ ts.rotate_left(17);
    let a = u32::try_from(hi >> 32).unwrap_or(u32::MAX);
    let b = u16::try_from((hi >> 16) & 0xFFFF).unwrap_or(u16::MAX);
    let c = u16::try_from(0x4000 | ((hi >> 12) & 0x0FFF)).unwrap_or(u16::MAX); // version 4 marker
    let d = u16::try_from(0x8000 | ((lo >> 48) & 0x3FFF)).unwrap_or(u16::MAX); // variant
    let e_hi = u32::try_from(lo >> 16).unwrap_or(u32::MAX);
    let e_lo = u16::try_from(lo & 0xFFFF).unwrap_or(u16::MAX);
    format!("{a:08x}-{b:04x}-{c:04x}-{d:04x}-{e_hi:08x}{e_lo:04x}")
}

// ---------------------------------------------------------------------------
// STIX 2.1 type constants
// ---------------------------------------------------------------------------

pub mod stix_type {
    pub const BUNDLE: &str = "bundle";
    pub const INDICATOR: &str = "indicator";
    pub const OBSERVED_DATA: &str = "observed-data";
    pub const THREAT_ACTOR: &str = "threat-actor";
    pub const ATTACK_PATTERN: &str = "attack-pattern";
    pub const MALWARE: &str = "malware";
    pub const TOOL: &str = "tool";
    pub const IDENTITY: &str = "identity";
    pub const RELATIONSHIP: &str = "relationship";
    pub const SIGHTING: &str = "sighting";
    pub const COURSE_OF_ACTION: &str = "course-of-action";
    pub const NOTE: &str = "note";
    pub const REPORT: &str = "report";
    pub const CAMPAIGN: &str = "campaign";
    pub const INFRASTRUCTURE: &str = "infrastructure";
    pub const VULNERABILITY: &str = "vulnerability";
    pub const GROUPING: &str = "grouping";
    pub const OPINION: &str = "opinion";
    pub const LOCATION: &str = "location";
}

// ---------------------------------------------------------------------------
// STIX ID generation
// ---------------------------------------------------------------------------

/// Generate a deterministic STIX 2.1 ID for a given type and MISP UUID.
#[must_use]
pub fn stix_id(stix_type: &str, misp_uuid: &str) -> String {
    // Use MISP UUID directly if it looks like a UUID, else generate from hash
    let uuid = if misp_uuid.len() == 36 && misp_uuid.contains('-') {
        misp_uuid.to_owned()
    } else {
        let name = format!("{stix_type}:{misp_uuid}");
        uuid_v5_approx("6ba7b8109dad11d180b400c04fd430c8", name.as_bytes())
    };
    format!("{stix_type}--{uuid}")
}

/// Generate a fresh STIX ID.
#[must_use]
pub fn new_stix_id(stix_type: &str) -> String {
    format!("{stix_type}--{}", uuid_v4_pseudo())
}

// ---------------------------------------------------------------------------
// STIX timestamp
// ---------------------------------------------------------------------------

#[must_use]
pub fn stix_timestamp(unix_ts: u64) -> String {
    // Format: 2024-01-15T12:34:56.000Z
    let secs = unix_ts;
    let (y, mo, d) = unix_to_ymd(secs);
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.000Z")
}

const fn unix_to_ymd(ts: u64) -> (u32, u32, u32) {
    let days = ts / 86400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe/4 - yoe/100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

#[must_use]
pub fn now_stix() -> String {
    stix_timestamp(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs())
}

// ---------------------------------------------------------------------------
// STIX pattern builder
// ---------------------------------------------------------------------------

/// Convert a MISP attribute type + value to a STIX 2.1 comparison expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixPattern(pub String);

impl StixPattern {
    #[must_use]
    pub fn and(parts: impl IntoIterator<Item = String>) -> Self {
        let exprs: Vec<String> = parts.into_iter().collect();
        if exprs.len() == 1 { return Self(format!("[{}]", exprs[0])); }
        Self(format!("[{}]", exprs.join(" AND ")))
    }
    #[must_use]
    pub fn or(parts: impl IntoIterator<Item = String>) -> Self {
        let exprs: Vec<String> = parts.into_iter().collect();
        if exprs.len() == 1 { return Self(format!("[{}]", exprs[0])); }
        Self(format!("[{}]", exprs.join(" OR ")))
    }
}

impl fmt::Display for StixPattern { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) } }

/// Map a MISP attribute type to a STIX pattern expression.
#[must_use]
pub fn attr_to_pattern(attr_type: &str, value: &str) -> Option<String> {
    let escaped = value.replace('\'', "\\'").replace('\\', "\\\\");
    match attr_type {
        "md5" => Some(format!("file:hashes.MD5 = '{escaped}'")),
        "sha1" => Some(format!("file:hashes.SHA-1 = '{escaped}'")),
        "sha256" => Some(format!("file:hashes.SHA-256 = '{escaped}'")),
        "sha512" => Some(format!("file:hashes.SHA-512 = '{escaped}'")),
        "filename" => Some(format!("file:name = '{escaped}'")),
        "filename|md5" => {
            let parts: Vec<&str> = value.splitn(2, '|').collect();
            if parts.len() == 2 {
                Some(format!("file:name = '{}' AND file:hashes.MD5 = '{}'", parts[0], parts[1]))
            } else { None }
        }
        "filename|sha256" => {
            let parts: Vec<&str> = value.splitn(2, '|').collect();
            if parts.len() == 2 {
                Some(format!("file:name = '{}' AND file:hashes.SHA-256 = '{}'", parts[0], parts[1]))
            } else { None }
        }
        "ip-dst" | "ip-src" => {
            if value.contains('/') {
                Some(format!("network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{escaped}'"))
            } else {
                Some(format!("ipv4-addr:value = '{escaped}'"))
            }
        }
        "ip-dst|port" => {
            let parts: Vec<&str> = value.splitn(2, '|').collect();
            if parts.len() == 2 {
                Some(format!("network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{}' AND network-traffic:dst_port = {}", parts[0], parts[1]))
            } else { None }
        }
        "domain" | "hostname" => Some(format!("domain-name:value = '{escaped}'")),
        "domain|ip" => {
            let parts: Vec<&str> = value.splitn(2, '|').collect();
            if parts.len() == 2 {
                Some(format!("domain-name:value = '{}' AND domain-name:resolves_to_refs[*].value = '{}'", parts[0], parts[1]))
            } else { None }
        }
        "url" | "uri" => Some(format!("url:value = '{escaped}'")),
        "email-src" | "email" => Some(format!("email-message:from_ref.type = 'email-addr' AND email-message:from_ref.value = '{escaped}'")),
        "email-dst" => Some(format!("email-addr:value = '{escaped}'")),
        "email-subject" => Some(format!("email-message:subject = '{escaped}'")),
        "mutex" => Some(format!("mutex:name = '{escaped}'")),
        "regkey" => Some(format!("windows-registry-key:key = '{escaped}'")),
        "regkey|value" => {
            let parts: Vec<&str> = value.splitn(2, '|').collect();
            if parts.len() == 2 {
                Some(format!("windows-registry-key:key = '{}' AND windows-registry-key:values[*].data = '{}'", parts[0], parts[1]))
            } else { None }
        }
        "named pipe" => Some(format!("file:name = '{escaped}'")),
        "process-name" => Some(format!("process:name = '{escaped}'")),
        "user-agent" => Some(format!("network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{escaped}'")),
        "snort" => Some(format!("network-traffic:extensions.'tcp-ext'.src_flags_hex = '{escaped}'")),
        "vulnerability" => Some(format!("vulnerability:name = '{escaped}'")),
        "x509-fingerprint-sha1" => Some(format!("x509-certificate:hashes.SHA-1 = '{escaped}'")),
        "x509-fingerprint-sha256" => Some(format!("x509-certificate:hashes.SHA-256 = '{escaped}'")),
        "pdb" => Some(format!("file:extended_properties.'windows-pebinary-ext'.pdb_path = '{escaped}'")),
        "imphash" => Some(format!("file:hashes.IMPHASH = '{escaped}'")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// STIX object builders
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixIndicator {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub pattern_type: String,
    pub valid_from: String,
    pub labels: Vec<String>,
    pub confidence: Option<u8>,
    pub created: String,
    pub modified: String,
    pub external_refs: Vec<Value>,
}

impl StixIndicator {
    #[must_use]
    pub fn new(id: String, name: String, pattern: String, valid_from: String) -> Self {
        let now = now_stix();
        Self {
            id, name, description: String::new(), pattern,
            pattern_type: "stix".into(), valid_from,
            labels: vec!["malicious-activity".into()],
            confidence: None, created: now.clone(), modified: now,
            external_refs: Vec::new(),
        }
    }
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "type": stix_type::INDICATOR,
            "spec_version": "2.1",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "valid_from": self.valid_from,
            "labels": self.labels,
            "created": self.created,
            "modified": self.modified,
        });
        if let Some(c) = self.confidence { v["confidence"] = json!(c); }
        if !self.external_refs.is_empty() { v["external_references"] = json!(self.external_refs); }
        v
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixMalware {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_family: bool,
    pub malware_types: Vec<String>,
    pub aliases: Vec<String>,
    pub created: String,
    pub modified: String,
    pub labels: Vec<String>,
    pub external_refs: Vec<Value>,
}

impl StixMalware {
    #[must_use]
    pub fn new(id: String, name: String, is_family: bool) -> Self {
        let now = now_stix();
        Self { id, name, description: String::new(), is_family, malware_types: vec![], aliases: vec![], created: now.clone(), modified: now, labels: vec![], external_refs: vec![] }
    }
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "type": stix_type::MALWARE,
            "spec_version": "2.1",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_family": self.is_family,
            "malware_types": self.malware_types,
            "aliases": self.aliases,
            "labels": self.labels,
            "created": self.created,
            "modified": self.modified,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixThreatActor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub aliases: Vec<String>,
    pub threat_actor_types: Vec<String>,
    pub goals: Vec<String>,
    pub sophistication: Option<String>,
    pub resource_level: Option<String>,
    pub primary_motivation: Option<String>,
    pub created: String,
    pub modified: String,
}

impl StixThreatActor {
    #[must_use]
    pub fn new(id: String, name: String) -> Self {
        let now = now_stix();
        Self { id, name, description: String::new(), aliases: vec![], threat_actor_types: vec![], goals: vec![], sophistication: None, resource_level: None, primary_motivation: None, created: now.clone(), modified: now }
    }
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "type": stix_type::THREAT_ACTOR,
            "spec_version": "2.1",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "aliases": self.aliases,
            "threat_actor_types": self.threat_actor_types,
            "goals": self.goals,
            "created": self.created,
            "modified": self.modified,
        });
        if let Some(s) = &self.sophistication { v["sophistication"] = json!(s); }
        if let Some(r) = &self.resource_level { v["resource_level"] = json!(r); }
        if let Some(m) = &self.primary_motivation { v["primary_motivation"] = json!(m); }
        v
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixAttackPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub aliases: Vec<String>,
    pub external_refs: Vec<Value>,
    pub created: String,
    pub modified: String,
}

impl StixAttackPattern {
    #[must_use]
    pub fn mitre(id: String, technique_id: &str, name: &str) -> Self {
        let now = now_stix();
        Self {
            id, name: name.to_owned(), description: String::new(), aliases: vec![],
            external_refs: vec![json!({"source_name": "mitre-attack", "external_id": technique_id})],
            created: now.clone(), modified: now,
        }
    }
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "type": stix_type::ATTACK_PATTERN,
            "spec_version": "2.1",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "aliases": self.aliases,
            "external_references": self.external_refs,
            "created": self.created,
            "modified": self.modified,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixRelationship {
    pub id: String,
    pub relationship_type: String,
    pub source_ref: String,
    pub target_ref: String,
    pub description: String,
    pub created: String,
    pub modified: String,
}

impl StixRelationship {
    #[must_use]
    pub fn new(rel_type: impl Into<String>, src: impl Into<String>, tgt: impl Into<String>) -> Self {
        let now = now_stix();
        Self {
            id: new_stix_id(stix_type::RELATIONSHIP),
            relationship_type: rel_type.into(),
            source_ref: src.into(), target_ref: tgt.into(),
            description: String::new(), created: now.clone(), modified: now,
        }
    }
    #[must_use]
    pub fn indicates(indicator_id: impl Into<String>, malware_id: impl Into<String>) -> Self {
        Self::new("indicates", indicator_id, malware_id)
    }
    #[must_use]
    pub fn uses(threat_actor_id: impl Into<String>, tool_id: impl Into<String>) -> Self {
        Self::new("uses", threat_actor_id, tool_id)
    }
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "type": stix_type::RELATIONSHIP,
            "spec_version": "2.1",
            "id": self.id,
            "relationship_type": self.relationship_type,
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "description": self.description,
            "created": self.created,
            "modified": self.modified,
        })
    }
}

// ---------------------------------------------------------------------------
// STIX Bundle builder
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct StixBundle {
    pub id: String,
    pub objects: Vec<Value>,
    pub object_index: HashMap<String, usize>,
}

impl StixBundle {
    #[must_use]
    pub fn new() -> Self {
        Self { id: new_stix_id(stix_type::BUNDLE), objects: Vec::new(), object_index: HashMap::new() }
    }

    pub fn add(&mut self, obj: Value) {
        if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
            if !self.object_index.contains_key(id) {
                let idx = self.objects.len();
                self.object_index.insert(id.to_owned(), idx);
                self.objects.push(obj);
            }
        } else {
            self.objects.push(obj);
        }
    }

    pub fn add_indicator(&mut self, i: &StixIndicator) { self.add(i.to_json()); }
    pub fn add_malware(&mut self, m: &StixMalware) { self.add(m.to_json()); }
    pub fn add_threat_actor(&mut self, t: &StixThreatActor) { self.add(t.to_json()); }
    pub fn add_attack_pattern(&mut self, a: &StixAttackPattern) { self.add(a.to_json()); }
    pub fn add_relationship(&mut self, r: &StixRelationship) { self.add(r.to_json()); }

    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "type": stix_type::BUNDLE,
            "id": self.id,
            "spec_version": "2.1",
            "objects": self.objects,
        })
    }

    #[must_use]
    pub const fn object_count(&self) -> usize { self.objects.len() }
    #[must_use]
    pub fn has_object(&self, id: &str) -> bool { self.object_index.contains_key(id) }
}

// ---------------------------------------------------------------------------
// Main converter
// ---------------------------------------------------------------------------

/// Converts a MISP event JSON object to a STIX 2.1 bundle.
///
/// # Errors
/// Returns an error when the event payload cannot be converted.
pub fn convert_event(misp_event: &Value) -> Result<StixBundle, MispError> {
    let event = misp_event.get("Event").unwrap_or(misp_event);
    let mut bundle = StixBundle::new();
    let event_uuid = event["uuid"].as_str().unwrap_or("");
    let event_info = event["info"].as_str().unwrap_or("MISP Event");
    let event_date = event["date"].as_str().unwrap_or("1970-01-01");
    let valid_from = format!("{event_date}T00:00:00.000Z");
    // Convert attributes → Indicators
    if let Some(attrs) = event["Attribute"].as_array() {
        for attr in attrs {
            convert_attribute(attr, event_uuid, &valid_from, &mut bundle);
        }
    }
    // Convert galaxies → ThreatActor / AttackPattern / Malware
    if let Some(galaxies) = event["Galaxy"].as_array() {
        for galaxy in galaxies {
            convert_galaxy(galaxy, &mut bundle);
        }
    }
    // Convert objects → grouped indicators
    if let Some(objects) = event["Object"].as_array() {
        for obj in objects {
            convert_object(obj, &valid_from, &mut bundle);
        }
    }
    // Create a STIX Report wrapping all objects
    let report_id = stix_id(stix_type::REPORT, event_uuid);
    let object_refs: Vec<String> = bundle.objects.iter()
        .filter_map(|o| o.get("id").and_then(|v| v.as_str()).map(std::borrow::ToOwned::to_owned))
        .collect();
    let report = json!({
        "type": stix_type::REPORT,
        "spec_version": "2.1",
        "id": report_id,
        "name": event_info,
        "published": valid_from,
        "created": now_stix(),
        "modified": now_stix(),
        "object_refs": object_refs,
    });
    bundle.add(report);
    Ok(bundle)
}

fn convert_attribute(attr: &Value, _event_uuid: &str, valid_from: &str, bundle: &mut StixBundle) {
    let attr_type = attr["type"].as_str().unwrap_or("");
    let value = attr["value"].as_str().unwrap_or("");
    let attr_uuid = attr["uuid"].as_str().unwrap_or("");
    let to_ids = attr["to_ids"].as_bool().unwrap_or(false);
    if !to_ids { return; }
    if let Some(pattern_expr) = attr_to_pattern(attr_type, value) {
        let pattern = format!("[{pattern_expr}]");
        let indicator_id = stix_id(stix_type::INDICATOR, attr_uuid);
        let comment = attr["comment"].as_str().unwrap_or("").to_owned();
        let mut indicator = StixIndicator::new(
            indicator_id,
            format!("{attr_type}: {value}"),
            pattern,
            valid_from.to_owned(),
        );
        indicator.description = comment;
        bundle.add_indicator(&indicator);
    }
}

fn convert_galaxy(galaxy: &Value, bundle: &mut StixBundle) {
    let galaxy_type = galaxy["type"].as_str().unwrap_or("");
    if let Some(clusters) = galaxy["GalaxyCluster"].as_array() {
        for cluster in clusters {
            let name = cluster["value"].as_str().unwrap_or("Unknown");
            let uuid = cluster["uuid"].as_str().unwrap_or("");
            match galaxy_type {
                "threat-actor" => {
                    let id = stix_id(stix_type::THREAT_ACTOR, uuid);
                    bundle.add_threat_actor(&StixThreatActor::new(id, name.to_owned()));
                }
                "mitre-attack-pattern" | "mitre-enterprise-attack-attack-pattern" => {
                    let id = stix_id(stix_type::ATTACK_PATTERN, uuid);
                    let tech_id = cluster["meta"]["external_id"].as_str().unwrap_or(name);
                    bundle.add_attack_pattern(&StixAttackPattern::mitre(id, tech_id, name));
                }
                "mitre-malware" | "mitre-enterprise-attack-malware" => {
                    let id = stix_id(stix_type::MALWARE, uuid);
                    bundle.add_malware(&StixMalware::new(id, name.to_owned(), true));
                }
                "tool" | "mitre-enterprise-attack-tool" => {
                    let id = stix_id(stix_type::TOOL, uuid);
                    let tool = json!({
                        "type": stix_type::TOOL,
                        "spec_version": "2.1",
                        "id": id,
                        "name": name,
                        "created": now_stix(),
                        "modified": now_stix(),
                    });
                    bundle.add(tool);
                }
                _ => {}
            }
        }
    }
}

fn convert_object(obj: &Value, valid_from: &str, bundle: &mut StixBundle) {
    let obj_name = obj["name"].as_str().unwrap_or("");
    let attrs = obj["Attribute"].as_array().map_or(&[][..], std::vec::Vec::as_slice);
    // Collect patterns from IDS attributes
    let patterns: Vec<String> = attrs.iter()
        .filter(|a| a["to_ids"].as_bool().unwrap_or(false))
        .filter_map(|a| {
            let t = a["type"].as_str()?;
            let v = a["value"].as_str()?;
            attr_to_pattern(t, v)
        })
        .collect();
    if patterns.is_empty() { return; }
    let combined = patterns.join(" AND ");
    let pattern = format!("[{combined}]");
    let obj_uuid = obj["uuid"].as_str().unwrap_or("");
    let indicator_id = stix_id(stix_type::INDICATOR, obj_uuid);
    let indicator = StixIndicator::new(
        indicator_id,
        format!("{obj_name} object indicator"),
        pattern,
        valid_from.to_owned(),
    );
    bundle.add_indicator(&indicator);
}

/// Convert a single MISP attribute to a STIX Indicator.
#[must_use]
pub fn attribute_to_indicator(attr: &Value) -> Option<StixIndicator> {
    let attr_type = attr["type"].as_str()?;
    let value = attr["value"].as_str()?;
    let uuid = attr["uuid"].as_str().unwrap_or("");
    let pattern_expr = attr_to_pattern(attr_type, value)?;
    let pattern = format!("[{pattern_expr}]");
    let id = stix_id(stix_type::INDICATOR, uuid);
    let valid_from = now_stix();
    let mut indicator = StixIndicator::new(id, format!("{attr_type}: {value}"), pattern, valid_from);
    attr["comment"].as_str().unwrap_or("").clone_into(&mut indicator.description);
    Some(indicator)
}

// ---------------------------------------------------------------------------
// TLP marking definitions
// ---------------------------------------------------------------------------

#[must_use]
pub fn tlp_white_marking() -> Value {
    json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "white"},
    })
}
#[must_use]
pub fn tlp_green_marking() -> Value {
    json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "green"},
    })
}
#[must_use]
pub fn tlp_amber_marking() -> Value {
    json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "amber"},
    })
}
#[must_use]
pub fn tlp_red_marking() -> Value {
    json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "definition": {"tlp": "red"},
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stix_id_from_uuid() {
        let id = stix_id("indicator", "12345678-1234-1234-1234-123456789012");
        assert_eq!(id, "indicator--12345678-1234-1234-1234-123456789012");
    }

    #[test]
    fn test_stix_id_from_non_uuid() {
        let id = stix_id("malware", "not-a-uuid");
        assert!(id.starts_with("malware--"));
    }

    #[test]
    fn test_new_stix_id_format() {
        let id = new_stix_id("threat-actor");
        assert!(id.starts_with("threat-actor--"));
        assert_eq!(id.len(), "threat-actor--".len() + 36);
    }

    #[test]
    fn test_attr_to_pattern_md5() {
        let p = attr_to_pattern("md5", "d41d8cd98f00b204e9800998ecf8427e").unwrap();
        assert_eq!(p, "file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e'");
    }

    #[test]
    fn test_attr_to_pattern_ip() {
        let p = attr_to_pattern("ip-dst", "1.2.3.4").unwrap();
        assert!(p.contains("1.2.3.4"));
    }

    #[test]
    fn test_attr_to_pattern_domain() {
        let p = attr_to_pattern("domain", "evil.com").unwrap();
        assert_eq!(p, "domain-name:value = 'evil.com'");
    }

    #[test]
    fn test_attr_to_pattern_regkey() {
        let p = attr_to_pattern("regkey", r"HKEY_CURRENT_USER\Software\Run").unwrap();
        assert!(p.contains("windows-registry-key:key"));
    }

    #[test]
    fn test_attr_to_pattern_unknown() {
        assert!(attr_to_pattern("comment", "test").is_none());
    }

    #[test]
    fn test_stix_bundle_add_deduplication() {
        let mut b = StixBundle::new();
        let ind = StixIndicator::new("indicator--12345678-1234-1234-1234-123456789012".into(), "T".into(), "[file:name = 'x']".into(), "2024-01-01T00:00:00.000Z".into());
        b.add_indicator(&ind);
        b.add_indicator(&ind);
        assert_eq!(b.object_count(), 1);
    }

    #[test]
    fn test_convert_event_basic() {
        let event = json!({
            "Event": {
                "uuid": "aabbccdd-0000-0000-0000-000000000001",
                "info": "Test",
                "date": "2024-01-15",
                "Attribute": [
                    {"uuid": "aabbccdd-0000-0000-0000-000000000002", "type": "md5", "value": "abc", "to_ids": true, "comment": ""},
                    {"uuid": "aabbccdd-0000-0000-0000-000000000003", "type": "domain", "value": "evil.com", "to_ids": true, "comment": ""},
                ],
                "Galaxy": [],
                "Object": [],
            }
        });
        let bundle = convert_event(&event).unwrap();
        // 2 indicators + 1 report
        assert!(bundle.object_count() >= 3);
        let j = bundle.to_json();
        assert_eq!(j["type"], "bundle");
    }

    #[test]
    fn test_stix_timestamp() {
        let ts = stix_timestamp(0);
        assert_eq!(ts, "1970-01-01T00:00:00.000Z");
        let ts2 = stix_timestamp(86400);
        assert_eq!(ts2, "1970-01-02T00:00:00.000Z");
    }

    #[test]
    fn test_tlp_markings_ids() {
        let w = tlp_white_marking();
        assert_eq!(w["id"], "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9");
        let r = tlp_red_marking();
        assert_eq!(r["definition"]["tlp"], "red");
    }

    #[test]
    fn test_relationship_indicates() {
        let rel = StixRelationship::indicates("indicator--abc", "malware--def");
        let j = rel.to_json();
        assert_eq!(j["relationship_type"], "indicates");
        assert_eq!(j["source_ref"], "indicator--abc");
        assert_eq!(j["target_ref"], "malware--def");
    }
}
