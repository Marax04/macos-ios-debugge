//! `misp_event_builder` — Fluent MISP event builder from analysis results.
//!
//! Constructs well-formed MISP events from reverse engineering findings:
//! malware samples, network `IoCs`, behavioral indicators, YARA rules,
//! file hashes, registry keys, dropped files, C2 infrastructure, and
//! PE metadata. Supports tagging, galaxy attachment, object templates,
//! sighting generation, and JSON serialization.

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::MispError;
use crate::misp_client::MispAttrType;

// ---------------------------------------------------------------------------
// Distribution levels
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum Distribution {
    YourOrganisationOnly = 0,
    #[default]
    ThisCommunity = 1,
    ConnectedCommunities = 2,
    AllCommunities = 3,
    SharingGroup = 4,
    Inherit = 5,
}


impl fmt::Display for Distribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::YourOrganisationOnly => "Your organisation only",
            Self::ThisCommunity => "This community only",
            Self::ConnectedCommunities => "Connected communities",
            Self::AllCommunities => "All communities",
            Self::SharingGroup => "Sharing group",
            Self::Inherit => "Inherit",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Threat level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum ThreatLevel {
    High = 1,
    Medium = 2,
    Low = 3,
    #[default]
    Undefined = 4,
}


impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self { Self::High => "High", Self::Medium => "Medium", Self::Low => "Low", Self::Undefined => "Undefined" };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Analysis level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum AnalysisStatus {
    #[default]
    Initial = 0,
    Ongoing = 1,
    Complete = 2,
}


// ---------------------------------------------------------------------------
// Attribute builder
// ---------------------------------------------------------------------------

/// A single MISP attribute in the builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeEntry {
    pub attr_type: String,
    pub category: String,
    pub value: String,
    pub comment: String,
    pub to_ids: bool,
    pub distribution: u8,
    pub tags: Vec<String>,
    pub object_relation: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

impl AttributeEntry {
    pub fn new(attr_type: MispAttrType, value: impl Into<String>) -> Self {
        Self {
            attr_type: attr_type.type_str().to_owned(),
            category: attr_type.category().to_owned(),
            value: value.into(),
            comment: String::new(),
            to_ids: true,
            distribution: Distribution::Inherit as u8,
            tags: Vec::new(),
            object_relation: None,
            first_seen: None,
            last_seen: None,
        }
    }

    #[must_use]
    pub fn with_comment(mut self, c: impl Into<String>) -> Self { self.comment = c.into(); self }
    #[must_use]
    pub const fn no_ids(mut self) -> Self { self.to_ids = false; self }
    #[must_use]
    pub fn with_tag(mut self, t: impl Into<String>) -> Self { self.tags.push(t.into()); self }
    #[must_use]
    pub fn with_relation(mut self, r: impl Into<String>) -> Self { self.object_relation = Some(r.into()); self }
    #[must_use]
    pub const fn with_distribution(mut self, d: Distribution) -> Self { self.distribution = d as u8; self }

    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "type": self.attr_type,
            "category": self.category,
            "value": self.value,
            "comment": self.comment,
            "to_ids": self.to_ids,
            "distribution": self.distribution,
        });
        if !self.tags.is_empty() {
            v["Tag"] = json!(self.tags.iter().map(|t| json!({"name": t})).collect::<Vec<_>>());
        }
        if let Some(r) = &self.object_relation { v["object_relation"] = json!(r); }
        if let Some(fs) = &self.first_seen { v["first_seen"] = json!(fs); }
        if let Some(ls) = &self.last_seen { v["last_seen"] = json!(ls); }
        v
    }
}

// ---------------------------------------------------------------------------
// MISP Object builder
// ---------------------------------------------------------------------------

/// A MISP object (structured attribute group based on a template).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObject {
    pub name: String,
    pub meta_category: String,
    pub description: String,
    pub template_uuid: Option<String>,
    pub template_version: Option<String>,
    pub distribution: u8,
    pub attributes: Vec<AttributeEntry>,
    pub comment: String,
}

impl MispObject {
    pub fn new(name: impl Into<String>, meta_category: impl Into<String>) -> Self {
        Self {
            name: name.into(), meta_category: meta_category.into(),
            description: String::new(), template_uuid: None,
            template_version: None, distribution: Distribution::Inherit as u8,
            attributes: Vec::new(), comment: String::new(),
        }
    }

    pub fn file(name: impl Into<String>) -> Self {
        let mut o = Self::new("file", "file");
        o.description = format!("File object for {}", name.into());
        o.template_uuid = Some("688c46fb-b6a7-11e8-8f00-8b3c946c696e".into());
        o
    }

    #[must_use]
    pub fn network_connection() -> Self {
        let mut o = Self::new("network-connection", "network");
        o.template_uuid = Some("e40b52ae-c521-4c09-ac99-9e6af66a6e3c".into());
        o
    }

    #[must_use]
    pub fn domain_ip() -> Self {
        let mut o = Self::new("domain-ip", "network");
        o.template_uuid = Some("43b3b146-77eb-4931-b4cc-b66c28bc9f5a".into());
        o
    }

    #[must_use]
    pub fn with_attr(mut self, attr: AttributeEntry) -> Self { self.attributes.push(attr); self }
    pub fn add_attr(&mut self, attr: AttributeEntry) { self.attributes.push(attr); }

    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "name": self.name,
            "meta-category": self.meta_category,
            "description": self.description,
            "distribution": self.distribution,
            "comment": self.comment,
            "Attribute": self.attributes.iter().map(AttributeEntry::to_json).collect::<Vec<_>>(),
        });
        if let Some(u) = &self.template_uuid { v["template_uuid"] = json!(u); }
        if let Some(ver) = &self.template_version { v["template_version"] = json!(ver); }
        v
    }
}

// ---------------------------------------------------------------------------
// Galaxy cluster attachment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GalaxyAttachment {
    pub galaxy_type: String,
    pub cluster_value: String,
    pub cluster_uuid: Option<String>,
}

impl GalaxyAttachment {
    pub fn mitre_attack(technique_id: impl Into<String>) -> Self {
        Self {
            galaxy_type: "mitre-attack-pattern".into(),
            cluster_value: technique_id.into(),
            cluster_uuid: None,
        }
    }
    pub fn threat_actor(name: impl Into<String>) -> Self {
        Self { galaxy_type: "threat-actor".into(), cluster_value: name.into(), cluster_uuid: None }
    }
    pub fn tool(name: impl Into<String>) -> Self {
        Self { galaxy_type: "tool".into(), cluster_value: name.into(), cluster_uuid: None }
    }
    pub fn malware(name: impl Into<String>) -> Self {
        Self { galaxy_type: "mitre-malware".into(), cluster_value: name.into(), cluster_uuid: None }
    }
}

// ---------------------------------------------------------------------------
// Main event builder
// ---------------------------------------------------------------------------

/// Fluent builder for constructing a MISP event JSON payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBuilder {
    pub info: String,
    pub threat_level: ThreatLevel,
    pub analysis: AnalysisStatus,
    pub distribution: Distribution,
    pub tags: Vec<String>,
    pub galaxies: Vec<GalaxyAttachment>,
    pub attributes: Vec<AttributeEntry>,
    pub objects: Vec<MispObject>,
    pub date: Option<String>,
    pub publish: bool,
    pub sharing_group_id: Option<u32>,
    pub comment: String,
    pub metadata: HashMap<String, String>,
}

impl EventBuilder {
    pub fn new(info: impl Into<String>) -> Self {
        Self {
            info: info.into(),
            threat_level: ThreatLevel::Undefined,
            analysis: AnalysisStatus::Initial,
            distribution: Distribution::ThisCommunity,
            tags: Vec::new(),
            galaxies: Vec::new(),
            attributes: Vec::new(),
            objects: Vec::new(),
            date: None,
            publish: false,
            sharing_group_id: None,
            comment: String::new(),
            metadata: HashMap::new(),
        }
    }

    // --- fluent setters ---

    #[must_use]
    pub const fn threat_level(mut self, level: ThreatLevel) -> Self { self.threat_level = level; self }
    #[must_use]
    pub const fn analysis(mut self, a: AnalysisStatus) -> Self { self.analysis = a; self }
    #[must_use]
    pub const fn distribution(mut self, d: Distribution) -> Self { self.distribution = d; self }
    pub fn date(mut self, d: impl Into<String>) -> Self { self.date = Some(d.into()); self }
    #[must_use]
    pub const fn publish(mut self) -> Self { self.publish = true; self }
    #[must_use]
    pub fn comment(mut self, c: impl Into<String>) -> Self { self.comment = c.into(); self }
    #[must_use]
    pub const fn sharing_group(mut self, id: u32) -> Self { self.sharing_group_id = Some(id); self }

    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self { self.tags.push(t.into()); self }
    #[must_use]
    pub fn tlp_white(self) -> Self { self.tag("tlp:white") }
    #[must_use]
    pub fn tlp_green(self) -> Self { self.tag("tlp:green") }
    #[must_use]
    pub fn tlp_amber(self) -> Self { self.tag("tlp:amber") }
    #[must_use]
    pub fn tlp_red(self) -> Self { self.tag("tlp:red") }

    #[must_use]
    pub fn galaxy(mut self, g: GalaxyAttachment) -> Self { self.galaxies.push(g); self }
    pub fn mitre_technique(self, id: impl Into<String>) -> Self { self.galaxy(GalaxyAttachment::mitre_attack(id)) }
    #[must_use]
    pub fn threat_actor(self, name: impl Into<String>) -> Self { self.galaxy(GalaxyAttachment::threat_actor(name)) }
    pub fn malware_name(self, name: impl Into<String>) -> Self { self.galaxy(GalaxyAttachment::malware(name)) }

    #[must_use]
    pub fn attribute(mut self, a: AttributeEntry) -> Self { self.attributes.push(a); self }
    #[must_use]
    pub fn object(mut self, o: MispObject) -> Self { self.objects.push(o); self }

    // --- convenience IoC adders ---

    #[must_use]
    pub fn add_md5(self, hash: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Md5, hash))
    }
    #[must_use]
    pub fn add_sha1(self, hash: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Sha1, hash))
    }
    #[must_use]
    pub fn add_sha256(self, hash: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Sha256, hash))
    }
    #[must_use]
    pub fn add_ip(self, ip: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::IpDst, ip))
    }
    #[must_use]
    pub fn add_domain(self, domain: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Domain, domain))
    }
    #[must_use]
    pub fn add_url(self, url: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Url, url))
    }
    #[must_use]
    pub fn add_filename(self, name: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Filename, name))
    }
    #[must_use]
    pub fn add_regkey(self, key: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Regkey, key))
    }
    #[must_use]
    pub fn add_mutex(self, m: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::MutexName, m))
    }
    #[must_use]
    pub fn add_yara(self, rule: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Yara, rule).no_ids())
    }
    #[must_use]
    pub fn add_comment(self, c: impl Into<String>) -> Self {
        self.attribute(AttributeEntry::new(MispAttrType::Comment, c).no_ids())
    }

    // --- metadata helpers ---

    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into()); self
    }

    /// # Errors
    ///
    /// Returns an error if the operation fails.
    /// Build the final MISP event JSON object.
    pub fn build(&self) -> Result<Value, MispError> {
        let date = self.date.clone().unwrap_or_else(|| {
            let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let (y, m, d) = unix_to_ymd(secs);
            format!("{y:04}-{m:02}-{d:02}")
        });
        let mut event = json!({
            "info": self.info,
            "threat_level_id": self.threat_level as u8,
            "analysis": self.analysis as u8,
            "distribution": self.distribution as u8,
            "date": date,
            "published": self.publish,
            "comment": self.comment,
        });
        if let Some(sg) = self.sharing_group_id { event["sharing_group_id"] = json!(sg); }
        if !self.tags.is_empty() {
            event["Tag"] = json!(self.tags.iter().map(|t| json!({"name": t})).collect::<Vec<_>>());
        }
        if !self.galaxies.is_empty() {
            event["Galaxy"] = json!(self.galaxies.iter().map(|g| json!({
                "type": g.galaxy_type,
                "GalaxyCluster": [{"value": g.cluster_value}]
            })).collect::<Vec<_>>());
        }
        if !self.attributes.is_empty() {
            event["Attribute"] = json!(self.attributes.iter().map(AttributeEntry::to_json).collect::<Vec<_>>());
        }
        if !self.objects.is_empty() {
            event["Object"] = json!(self.objects.iter().map(MispObject::to_json).collect::<Vec<_>>());
        }
        Ok(json!({ "Event": event }))
    }

    #[must_use]
    pub const fn attribute_count(&self) -> usize { self.attributes.len() }
    #[must_use]
    pub const fn object_count(&self) -> usize { self.objects.len() }
    #[must_use]
    pub fn ioc_count(&self) -> usize { self.attributes.iter().filter(|a| a.to_ids).count() }
}

// ---------------------------------------------------------------------------
// Sighting builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SightingType {
    Sighting = 0,
    FalsePositive = 1,
    Expiration = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SightingBuilder {
    pub attribute_id: Option<u64>,
    pub attribute_uuid: Option<String>,
    pub event_id: Option<u64>,
    pub sighting_type: SightingType,
    pub source: String,
    pub timestamp: Option<u64>,
}

impl SightingBuilder {
    #[must_use]
    pub const fn new(sighting_type: SightingType) -> Self {
        Self { attribute_id: None, attribute_uuid: None, event_id: None, sighting_type, source: String::new(), timestamp: None }
    }
    #[must_use]
    pub const fn for_attribute(mut self, id: u64) -> Self { self.attribute_id = Some(id); self }
    pub fn for_uuid(mut self, uuid: impl Into<String>) -> Self { self.attribute_uuid = Some(uuid.into()); self }
    pub fn source(mut self, s: impl Into<String>) -> Self { self.source = s.into(); self }
    #[must_use]
    pub const fn timestamp(mut self, ts: u64) -> Self { self.timestamp = Some(ts); self }

    #[must_use]
    pub fn build(&self) -> Value {
        let ts = self.timestamp.unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
        let mut v = json!({
            "type": self.sighting_type as u8,
            "source": self.source,
            "timestamp": ts.to_string(),
        });
        if let Some(id) = self.attribute_id { v["id"] = json!(id.to_string()); }
        if let Some(u) = &self.attribute_uuid { v["uuid"] = json!(u); }
        v
    }
}

// ---------------------------------------------------------------------------
// PE analysis event builder (domain-specific convenience)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysisResult {
    pub filename: String,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub compile_timestamp: Option<u64>,
    pub imphash: Option<String>,
    pub pe_type: Option<String>,
    pub sections: Vec<String>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub yara_matches: Vec<String>,
    pub c2_ips: Vec<String>,
    pub c2_domains: Vec<String>,
    pub registry_keys: Vec<String>,
    pub mutexes: Vec<String>,
    pub dropped_files: Vec<String>,
    pub pdb_path: Option<String>,
    pub notes: String,
}

impl PeAnalysisResult {
    pub fn new(filename: impl Into<String>) -> Self {
        Self {
            filename: filename.into(), md5: None, sha1: None, sha256: None,
            compile_timestamp: None, imphash: None, pe_type: None,
            sections: vec![], imports: vec![], exports: vec![],
            yara_matches: vec![], c2_ips: vec![], c2_domains: vec![],
            registry_keys: vec![], mutexes: vec![], dropped_files: vec![],
            pdb_path: None, notes: String::new(),
        }
    }

    pub fn into_event(self, info: impl Into<String>) -> EventBuilder {
        let mut b = EventBuilder::new(info)
            .analysis(AnalysisStatus::Ongoing)
            .tlp_amber();
        if let Some(md5) = &self.md5 { b = b.add_md5(md5.clone()); }
        if let Some(sha1) = &self.sha1 { b = b.add_sha1(sha1.clone()); }
        if let Some(sha256) = &self.sha256 { b = b.add_sha256(sha256.clone()); }
        b = b.add_filename(self.filename.clone());
        for ip in &self.c2_ips { b = b.add_ip(ip.clone()); }
        for d in &self.c2_domains { b = b.add_domain(d.clone()); }
        for r in &self.registry_keys { b = b.add_regkey(r.clone()); }
        for m in &self.mutexes { b = b.add_mutex(m.clone()); }
        for y in &self.yara_matches { b = b.add_yara(y.clone()); }
        for f in &self.dropped_files { b = b.add_filename(f.clone()); }
        if !self.notes.is_empty() { b = b.add_comment(self.notes.clone()); }
        if let Some(pdb) = &self.pdb_path {
            b = b.attribute(AttributeEntry::new(MispAttrType::Comment, format!("PDB: {pdb}")).no_ids());
        }
        b
    }
}

// ---------------------------------------------------------------------------
// Utility: Unix timestamp to Y/M/D
// ---------------------------------------------------------------------------

const fn unix_to_ymd(ts: u64) -> (u32, u32, u32) {
    let days = ts / 86400;
    // Compute Y/M/D from days since epoch (Gregorian calendar)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe/4 - yoe/100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_builder_basic() {
        let evt = EventBuilder::new("Test Event")
            .threat_level(ThreatLevel::High)
            .tlp_amber()
            .add_md5("d41d8cd98f00b204e9800998ecf8427e")
            .add_domain("evil.example.com")
            .build()
            .unwrap();
        assert_eq!(evt["Event"]["info"], "Test Event");
        assert_eq!(evt["Event"]["threat_level_id"], 1u8);
        let attrs = &evt["Event"]["Attribute"];
        assert!(attrs.as_array().unwrap().len() >= 2);
    }

    #[test]
    fn test_event_has_tlp_tag() {
        let evt = EventBuilder::new("T").tlp_red().build().unwrap();
        let tags = evt["Event"]["Tag"].as_array().unwrap();
        assert!(tags.iter().any(|t| t["name"] == "tlp:red"));
    }

    #[test]
    fn test_attribute_entry() {
        let a = AttributeEntry::new(MispAttrType::Sha256, "abc123")
            .with_comment("test hash")
            .with_tag("malware:ransomware");
        let j = a.to_json();
        assert_eq!(j["type"], "sha256");
        assert_eq!(j["comment"], "test hash");
    }

    #[test]
    fn test_misp_object_file() {
        let obj = MispObject::file("malware.exe")
            .with_attr(AttributeEntry::new(MispAttrType::Filename, "malware.exe").with_relation("filename"))
            .with_attr(AttributeEntry::new(MispAttrType::Md5, "abc").with_relation("md5"));
        let j = obj.to_json();
        assert_eq!(j["name"], "file");
        assert_eq!(j["Attribute"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_sighting_builder() {
        let s = SightingBuilder::new(SightingType::Sighting)
            .for_attribute(42)
            .source("sandbox")
            .timestamp(1_700_000_000)
            .build();
        assert_eq!(s["type"], 0u8);
        assert_eq!(s["source"], "sandbox");
        assert_eq!(s["id"], "42");
    }

    #[test]
    fn test_pe_analysis_into_event() {
        let mut pe = PeAnalysisResult::new("sample.exe");
        pe.sha256 = Some("a".repeat(64));
        pe.c2_ips.push("192.168.1.1".into());
        pe.c2_domains.push("evil.tld".into());
        pe.yara_matches.push("rule Ransomware { }".into());
        let b = pe.into_event("Ransomware sample");
        let evt = b.build().unwrap();
        let attrs = evt["Event"]["Attribute"].as_array().unwrap();
        assert!(attrs.len() >= 4);
    }

    #[test]
    fn test_unix_to_ymd() {
        let (y, m, d) = unix_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_ioc_count() {
        let b = EventBuilder::new("T")
            .add_sha256("x")
            .add_ip("1.2.3.4")
            .add_yara("rule X {}"); // no_ids
        assert_eq!(b.ioc_count(), 2);
        assert_eq!(b.attribute_count(), 3);
    }

    #[test]
    fn test_distribution_display() {
        assert_eq!(Distribution::AllCommunities.to_string(), "All communities");
        assert_eq!(ThreatLevel::High.to_string(), "High");
    }
}
