//! `rustre-threatintel`
//!
//! Core threat intelligence types, abstractions, and storage for the `RustRE` Suite.
//! Provides `IoC` management, threat actor tracking, malware family classification,
//! MITRE ATT&CK TTP representation, campaign tracking, `IoC` enrichment,
//! confidence scoring, and a dual SQLite/MySQL persistence layer.

// The mysql crate (v25) transitively pulls in older versions of base64, getrandom,
// ahash, thiserror, core-foundation, etc. that conflict with newer workspace deps.
// These duplicate versions are transitive and cannot be resolved without upstream
// crate updates.

pub mod casts;
pub use casts::*;
pub mod campaign;
pub mod confidence;
pub mod enrichment;
pub mod error;
pub mod intel;
pub mod ioc;
pub mod ioc_extractor;
pub mod ioc_normalizer;
pub mod threat_scorer;
pub mod attribution_engine;
pub mod malware;
pub mod malwarebazaar;
pub mod misp_client;
pub mod mitre_attack;
pub mod provider;
pub mod report;
pub mod store;
pub mod threat_actor;
pub mod threat_correlation;
pub mod virustotal;
pub mod stix_parser;
pub mod misp_feed_reader;
pub mod intel_enricher;
pub mod threat_report_aggregator;
pub mod malware_family_classifier;
pub mod threat_score_calculator;

pub use campaign::{Campaign, CampaignStore, KillChainPhase, TargetingScope};
pub use confidence::{
    AggregationMethod, ConfidenceDecay, ConfidenceModel, ConfidenceTier, EvidenceSignal,
};
pub use enrichment::{
    AbuseConfidence, EnrichedIoC, EnrichmentPipeline, GeoIpInfo, IoCEnricher, MetadataEnricher,
    NullEnricher, PdnsData, PdnsRecord, WhoisRecord,
};
pub use error::TiError;
pub use intel::{
    IntelProvider, IntelReport, IocExtractor as IntelIocExtractor, MalwareBazaarIntelClient,
    VirusTotalIntelClient, query_all_providers, query_ip_all_providers,
};
pub use ioc::{IoC, IoCType, Severity};
pub use malware::{MalwareFamily, MalwareType};
pub use provider::{TiProvider, TiResult, Verdict};
pub use report::{ThreatReport, TlpLevel};
pub use store::{DbConnection, IoCStore};
pub use threat_actor::{Motivation, ThreatActor, Ttp};

pub mod registry;

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // IoC tests
    // ------------------------------------------------------------------

    #[test]
    fn test_ioc_new_and_fields() {
        let ioc = IoC::new(
            IoCType::Domain,
            "evil.example.com".to_string(),
            "feed".to_string(),
        );
        assert_eq!(ioc.ioc_type, IoCType::Domain);
        assert_eq!(ioc.value, "evil.example.com");
        assert_eq!(ioc.source, "feed");
        assert!(ioc.id.is_none());
        assert!(ioc.description.is_none());
    }

    #[test]
    fn test_ioc_is_network() {
        assert!(IoC::new(IoCType::Ip, String::new(), String::new()).is_network());
        assert!(IoC::new(IoCType::Domain, String::new(), String::new()).is_network());
        assert!(IoC::new(IoCType::Url, String::new(), String::new()).is_network());
        assert!(!IoC::new(IoCType::Sha256, String::new(), String::new()).is_network());
    }

    #[test]
    fn test_ioc_is_hash() {
        assert!(IoC::new(IoCType::Md5, String::new(), String::new()).is_hash());
        assert!(IoC::new(IoCType::Sha256, String::new(), String::new()).is_hash());
        assert!(!IoC::new(IoCType::Email, String::new(), String::new()).is_hash());
    }

    #[test]
    fn test_severity_ord() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    // ------------------------------------------------------------------
    // MalwareFamily tests
    // ------------------------------------------------------------------

    #[test]
    fn test_malware_family_builder() {
        let fam = MalwareFamily::new("Emotet".to_string(), MalwareType::Trojan)
            .with_alias("Heodo".to_string());
        assert_eq!(fam.name, "Emotet");
        assert_eq!(fam.aliases, vec!["Heodo"]);
    }

    #[test]
    fn test_malware_type_variants() {
        let types = [
            MalwareType::Ransomware,
            MalwareType::Trojan,
            MalwareType::Backdoor,
            MalwareType::Rootkit,
            MalwareType::Banker,
            MalwareType::Stealer,
        ];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            assert!(!json.is_empty());
        }
    }

    // ------------------------------------------------------------------
    // ThreatActor tests
    // ------------------------------------------------------------------

    #[test]
    fn test_threat_actor_builder() {
        let ttp = Ttp::new("T1055", "Process Injection", "Defense Evasion");
        let actor = ThreatActor::new("APT29".to_string(), Motivation::Espionage).with_ttp(ttp);
        assert_eq!(actor.ttps.len(), 1);
        assert_eq!(actor.motivation, Motivation::Espionage);
    }

    #[test]
    fn test_motivation_variants() {
        let motivations = [
            Motivation::FinancialGain,
            Motivation::Espionage,
            Motivation::Sabotage,
            Motivation::Hacktivism,
            Motivation::Research,
            Motivation::Unknown,
        ];
        for m in &motivations {
            assert!(!m.to_string().is_empty());
        }
    }

    // ------------------------------------------------------------------
    // ThreatReport tests
    // ------------------------------------------------------------------

    #[test]
    fn test_report_add_ioc_and_count() {
        let mut r = ThreatReport::new("Test".to_string(), "me".to_string());
        r.add_ioc(IoC::new(
            IoCType::Ip,
            "1.2.3.4".to_string(),
            "test".to_string(),
        ));
        assert_eq!(r.ioc_count(), 1);
    }

    #[test]
    fn test_tlp_level_order() {
        assert!(TlpLevel::White < TlpLevel::Red);
    }

    #[test]
    fn test_report_to_json_round_trip() {
        let r = ThreatReport::new("Roundtrip".to_string(), "author".to_string());
        let json = r.to_json().unwrap();
        let decoded: ThreatReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.title, "Roundtrip");
    }

    // ------------------------------------------------------------------
    // TiResult / Verdict tests
    // ------------------------------------------------------------------

    #[test]
    fn test_ti_result_malicious_flag() {
        let mut result = TiResult::new(IoC::new(IoCType::Md5, "abc".to_string(), "vt".to_string()));
        assert!(!result.is_malicious());
        result.verdicts.push(Verdict {
            malicious: true,
            confidence: 95,
            tags: vec![],
            engine_count: 70,
            positive_count: 60,
            first_seen: None,
            last_seen: None,
            description: None,
            provider: "vt".to_string(),
        });
        assert!(result.is_malicious());
    }

    #[test]
    fn test_ti_result_max_confidence_empty() {
        let result = TiResult::new(IoC::new(IoCType::Md5, "abc".to_string(), "vt".to_string()));
        assert_eq!(result.max_confidence(), 0);
    }

    // ------------------------------------------------------------------
    // IoCStore (SQLite) tests
    // ------------------------------------------------------------------

    #[test]
    fn test_store_insert_and_count() {
        let conn = DbConnection::sqlite_in_memory().unwrap();
        let store = IoCStore::new(conn);
        let ioc = IoC::new(IoCType::Sha256, "abc123".to_string(), "test".to_string());
        let id = store.insert_ioc(&ioc).unwrap();
        assert!(id > 0);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn test_store_find_by_value() {
        let conn = DbConnection::sqlite_in_memory().unwrap();
        let store = IoCStore::new(conn);
        let ioc = IoC::new(
            IoCType::Domain,
            "malware.io".to_string(),
            "test".to_string(),
        );
        store.insert_ioc(&ioc).unwrap();
        let found = store.find_by_value("malware.io").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().ioc_type, IoCType::Domain);
    }

    #[test]
    fn test_store_find_by_type() {
        let conn = DbConnection::sqlite_in_memory().unwrap();
        let store = IoCStore::new(conn);
        store
            .insert_ioc(&IoC::new(
                IoCType::Ip,
                "10.0.0.1".to_string(),
                "test".to_string(),
            ))
            .unwrap();
        store
            .insert_ioc(&IoC::new(
                IoCType::Ip,
                "10.0.0.2".to_string(),
                "test".to_string(),
            ))
            .unwrap();
        store
            .insert_ioc(&IoC::new(
                IoCType::Md5,
                "hash".to_string(),
                "test".to_string(),
            ))
            .unwrap();
        let ips = store.find_by_type(&IoCType::Ip).unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_store_all_iocs() {
        let conn = DbConnection::sqlite_in_memory().unwrap();
        let store = IoCStore::new(conn);
        for i in 0..5u32 {
            store
                .insert_ioc(&IoC::new(
                    IoCType::Md5,
                    format!("hash{i}"),
                    "test".to_string(),
                ))
                .unwrap();
        }
        let all = store.all_iocs().unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_store_delete() {
        let conn = DbConnection::sqlite_in_memory().unwrap();
        let store = IoCStore::new(conn);
        let id = store
            .insert_ioc(&IoC::new(
                IoCType::Email,
                "bad@evil.com".to_string(),
                "test".to_string(),
            ))
            .unwrap();
        assert!(store.delete_ioc(id).unwrap());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_store_delete_nonexistent() {
        let conn = DbConnection::sqlite_in_memory().unwrap();
        let store = IoCStore::new(conn);
        assert!(!store.delete_ioc(42).unwrap());
    }

    #[test]
    fn test_error_display() {
        let e = TiError::NotFound("test-ioc".to_string());
        assert!(e.to_string().contains("test-ioc"));
        let e2 = TiError::RateLimit("virustotal".to_string());
        assert!(e2.to_string().contains("virustotal"));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatIndicatorDatabase
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::HashMap;

/// Opaque identifier for a stored `ThreatIoc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IocId(pub u64);

/// IOC type used by the in-memory indicator database.
///
/// Mirrors the persisted `IoCType` from `ioc.rs` but is a standalone enum so
/// that `ThreatIndicatorDatabase` has no `SQLite` dependency.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IocType {
    Md5,
    Sha1,
    Sha256,
    /// SHA-512 file hash.
    Sha512,
    Ip,
    Domain,
    Url,
    Email,
    /// Windows registry key or value.
    Registry,
    Filename,
    Mutex,
    /// YARA rule text.
    Yara,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Ip => "IP",
            Self::Domain => "Domain",
            Self::Url => "URL",
            Self::Email => "Email",
            Self::Registry => "Registry",
            Self::Filename => "Filename",
            Self::Mutex => "Mutex",
            Self::Yara => "YARA",
        };
        f.write_str(s)
    }
}

/// A single threat indicator of compromise held by `ThreatIndicatorDatabase`.
#[derive(Debug, Clone)]
pub struct ThreatIoc {
    /// Categorical type of the indicator.
    pub ioc_type: IocType,
    /// Raw indicator value (hash hex string, IP, domain, etc.).
    pub value: String,
    /// Human-readable name of the threat associated with this indicator.
    pub threat_name: String,
    /// Analyst confidence in the association, 0.0–1.0.
    pub confidence: f32,
    /// Data origin / feed name.
    pub source: String,
}

impl ThreatIoc {
    /// Construct a new `ThreatIoc`.
    #[must_use]
    pub fn new(
        ioc_type: IocType,
        value: impl Into<String>,
        threat_name: impl Into<String>,
        confidence: f32,
        source: impl Into<String>,
    ) -> Self {
        Self {
            ioc_type,
            value: value.into(),
            threat_name: threat_name.into(),
            confidence: confidence.clamp(0.0, 1.0),
            source: source.into(),
        }
    }
}

/// In-memory database of threat indicators with lookup and STIX export.
#[derive(Debug, Default)]
pub struct ThreatIndicatorDatabase {
    next_id: u64,
    store: HashMap<IocId, ThreatIoc>,
    /// Value-to-IDs index for O(1) lookup.
    value_index: HashMap<String, Vec<IocId>>,
}

impl ThreatIndicatorDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an IOC and return its assigned `IocId`.
    pub fn add_ioc(&mut self, ioc: ThreatIoc) -> IocId {
        self.next_id += 1;
        let id = IocId(self.next_id);
        self.value_index
            .entry(ioc.value.clone())
            .or_default()
            .push(id);
        self.store.insert(id, ioc);
        id
    }

    /// Look up all IOCs whose value matches `value` exactly.
    #[must_use]
    pub fn lookup(&self, value: &str) -> Vec<&ThreatIoc> {
        self.value_index.get(value).map_or_else(
            Vec::new,
            |ids| ids.iter().filter_map(|id| self.store.get(id)).collect(),
        )
    }

    /// Retrieve an IOC by its `IocId`, returning `None` if not found.
    #[must_use]
    pub fn get(&self, id: IocId) -> Option<&ThreatIoc> {
        self.store.get(&id)
    }

    /// Number of stored indicators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Returns `true` when there are no stored indicators.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Export a slice of `ThreatIoc` records as a minimal STIX 2.1 JSON bundle.
    ///
    /// Produces a valid JSON object containing a `bundle` with `spec_version`
    /// and one `indicator` STIX Domain Object per IOC.  No external crate is
    /// required; the JSON is assembled manually.
    #[must_use]
    pub fn export_stix(iocs: &[ThreatIoc]) -> String {
        use std::hash::{Hash, Hasher};
        // Deterministic UUID v5-like identifier derived from the indicator value.
        // We use a simple FNV-64 hash and format it as a valid UUID v4 hex string
        // (RFC 4122 variant bits set) so STIX validators accept the bundle.
        fn indicator_uuid(value: &str, ioc_type_str: &str) -> String {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            value.hash(&mut h);
            ioc_type_str.hash(&mut h);
            let hi = h.finish();
            // Derive a second word by hashing again with a salt.
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            hi.hash(&mut h2);
            b"salt".hash(&mut h2);
            let lo = h2.finish();
            // Set version bits (0100 = v4) and variant bits (10xx).
            let b0 = (hi >> 32) as u32;
            let b1 = (hi & 0xffff) as u16;
            let b2 = (((hi >> 16) & 0x0fff) as u16) | 0x4000; // version 4
            let b3 = ((lo >> 48) as u16 & 0x3fff) | 0x8000;   // variant 10
            let b4 = lo & 0x0000_ffff_ffff_ffff;
            format!("{b0:08x}-{b1:04x}-{b2:04x}-{b3:04x}-{b4:012x}")
        }
        // Generate a bundle UUID from a fixed seed.
        let bundle_uuid = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            b"rustre-bundle".hash(&mut h);
            let hi = h.finish();
            let mut h2 = std::collections::hash_map::DefaultHasher::new();
            hi.hash(&mut h2);
            b"bundle-salt".hash(&mut h2);
            let lo = h2.finish();
            let b0 = (hi >> 32) as u32;
            let b1 = (hi & 0xffff) as u16;
            let b2 = (((hi >> 16) & 0x0fff) as u16) | 0x4000;
            let b3 = ((lo >> 48) as u16 & 0x3fff) | 0x8000;
            let b4 = lo & 0x0000_ffff_ffff_ffff;
            format!("{b0:08x}-{b1:04x}-{b2:04x}-{b3:04x}-{b4:012x}")
        };
        // STIX pattern string literals are single-quoted, so a value containing
        // `'` or `\` must be escaped or it terminates the literal early. Without
        // this, `Indicator::extract_value` in this same crate reads the value
        // back truncated at the first quote — the export is not round-trippable.
        fn escape_stix_literal(value: &str) -> String {
            value.replace('\\', "\\\\").replace('\'', "\\'")
        }

        let mut objects = Vec::with_capacity(iocs.len());
        for ioc in iocs {
            let ioc_uuid = indicator_uuid(&ioc.value, &ioc.ioc_type.to_string());
            let value = escape_stix_literal(&ioc.value);
            let pattern = match ioc.ioc_type {
                IocType::Md5 => format!("[file:hashes.MD5 = '{}']", value),
                IocType::Sha1 => format!("[file:hashes.'SHA-1' = '{}']", value),
                IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{}']", value),
                IocType::Sha512 => format!("[file:hashes.'SHA-512' = '{}']", value),
                IocType::Ip => format!("[ipv4-addr:value = '{}']", value),
                IocType::Domain => format!("[domain-name:value = '{}']", value),
                IocType::Url => format!("[url:value = '{}']", value),
                IocType::Email => format!("[email-addr:value = '{}']", value),
                IocType::Registry => format!("[windows-registry-key:key = '{}']", value),
                IocType::Filename => format!("[file:name = '{}']", value),
                IocType::Mutex => format!("[mutex:name = '{}']", value),
                IocType::Yara => format!("[file:content = '{}']", value),
            };
            let confidence_pct = crate::casts::f64_to_u32_sat((f64::from(ioc.confidence) * 100.0).round());
            objects.push(format!(
                r#"    {{
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--{ioc_uuid}",
      "name": {name},
      "pattern": {pattern_json},
      "pattern_type": "stix",
      "valid_from": "1970-01-01T00:00:00Z",
      "confidence": {confidence_pct},
      "labels": [{source}]
    }}"#,
                name = serde_json::to_string(&ioc.threat_name)
                    .unwrap_or_else(|_| "\"unknown\"".to_string()),
                pattern_json =
                    serde_json::to_string(&pattern).unwrap_or_else(|_| "\"\"".to_string()),
                source = serde_json::to_string(&ioc.source)
                    .unwrap_or_else(|_| "\"unknown\"".to_string()),
            ));
        }

        format!(
            "{{\n  \"type\": \"bundle\",\n  \"spec_version\": \"2.1\",\n  \"id\": \"bundle--{bundle_uuid}\",\n  \"objects\": [\n{}\n  ]\n}}",
            objects.join(",\n")
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreatGroupTracker
// ─────────────────────────────────────────────────────────────────────────────

/// A threat actor group with associated metadata.
#[derive(Debug, Clone)]
pub struct ThreatGroup {
    /// Canonical name (e.g. "APT28").
    pub name: String,
    /// Alternative names / aliases used by other vendors.
    pub aliases: Vec<String>,
    /// MITRE ATT&CK TTP IDs associated with this group (e.g. "T1059").
    pub ttps: Vec<String>,
    /// `IocId`s of indicators attributed to this group.
    pub iocs: Vec<IocId>,
}

impl ThreatGroup {
    /// Construct a new group with no aliases, TTPs, or IOCs.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            aliases: Vec::new(),
            ttps: Vec::new(),
            iocs: Vec::new(),
        }
    }

    /// Builder: add an alias.
    #[must_use]
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    /// Builder: add a TTP identifier.
    #[must_use]
    pub fn with_ttp(mut self, ttp: impl Into<String>) -> Self {
        self.ttps.push(ttp.into());
        self
    }

    /// Associate an `IocId` with this group.
    pub fn link_ioc(&mut self, id: IocId) {
        self.iocs.push(id);
    }
}

/// Registry of known threat actor groups.
///
/// Pre-populated with five well-known groups (names only; no real intelligence
/// data is included to avoid any inadvertent attribution).
#[derive(Debug)]
pub struct ThreatGroupTracker {
    /// Map from canonical group name to `ThreatGroup`.
    pub known_groups: HashMap<String, ThreatGroup>,
}

impl Default for ThreatGroupTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatGroupTracker {
    /// Create a tracker pre-populated with five well-known threat groups.
    #[must_use]
    pub fn new() -> Self {
        let mut known_groups = HashMap::new();

        known_groups.insert(
            "APT28".to_string(),
            ThreatGroup::new("APT28")
                .with_alias("Fancy Bear")
                .with_alias("Sofacy")
                .with_alias("STRONTIUM"),
        );
        known_groups.insert(
            "APT29".to_string(),
            ThreatGroup::new("APT29")
                .with_alias("Cozy Bear")
                .with_alias("The Dukes")
                .with_alias("NOBELIUM"),
        );
        known_groups.insert(
            "Lazarus".to_string(),
            ThreatGroup::new("Lazarus")
                .with_alias("HIDDEN COBRA")
                .with_alias("Guardians of Peace"),
        );
        known_groups.insert(
            "FIN7".to_string(),
            ThreatGroup::new("FIN7")
                .with_alias("Carbanak")
                .with_alias("Navigator Group"),
        );
        known_groups.insert(
            "Sandworm".to_string(),
            ThreatGroup::new("Sandworm")
                .with_alias("Voodoo Bear")
                .with_alias("ELECTRUM")
                .with_alias("TeleBots"),
        );

        Self { known_groups }
    }

    /// Look up a group by its canonical name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ThreatGroup> {
        self.known_groups.get(name)
    }

    /// Mutable access to a group by canonical name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut ThreatGroup> {
        self.known_groups.get_mut(name)
    }

    /// Register a new group (or overwrite an existing entry).
    pub fn insert(&mut self, group: ThreatGroup) {
        self.known_groups.insert(group.name.clone(), group);
    }

    /// Search for a group by name *or* alias (case-insensitive).
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&ThreatGroup> {
        let q = query.to_lowercase();
        self.known_groups
            .values()
            .filter(|g| {
                g.name.to_lowercase().contains(&q)
                    || g.aliases.iter().any(|a| a.to_lowercase().contains(&q))
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests for the new types
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod indicator_db_tests {
    use super::*;

    #[test]
    fn add_and_lookup_ioc() {
        let mut db = ThreatIndicatorDatabase::new();
        let ioc = ThreatIoc::new(IocType::Sha256, "deadbeef", "MalwareX", 0.9, "internal");
        db.add_ioc(ioc);
        let results = db.lookup("deadbeef");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].threat_name, "MalwareX");
    }

    #[test]
    fn lookup_missing_returns_empty() {
        let db = ThreatIndicatorDatabase::new();
        assert!(db.lookup("nothere").is_empty());
    }

    #[test]
    fn multiple_iocs_same_value() {
        let mut db = ThreatIndicatorDatabase::new();
        db.add_ioc(ThreatIoc::new(
            IocType::Ip,
            "1.2.3.4",
            "ThreatA",
            0.7,
            "feedA",
        ));
        db.add_ioc(ThreatIoc::new(
            IocType::Ip,
            "1.2.3.4",
            "ThreatB",
            0.5,
            "feedB",
        ));
        assert_eq!(db.lookup("1.2.3.4").len(), 2);
    }

    #[test]
    fn len_and_is_empty() {
        let mut db = ThreatIndicatorDatabase::new();
        assert!(db.is_empty());
        db.add_ioc(ThreatIoc::new(IocType::Domain, "evil.io", "X", 0.8, "s"));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn confidence_clamped() {
        let ioc = ThreatIoc::new(IocType::Md5, "hash", "T", 1.5, "s");
        assert!((ioc.confidence - 1.0).abs() < f32::EPSILON);
        let ioc2 = ThreatIoc::new(IocType::Md5, "hash", "T", -0.1, "s");
        assert!((ioc2.confidence - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn export_stix_produces_valid_json() {
        let iocs = vec![
            ThreatIoc::new(IocType::Sha256, "aabbcc", "TestMalware", 0.95, "internal"),
            ThreatIoc::new(
                IocType::Domain,
                "bad.example.com",
                "TestMalware",
                0.8,
                "feed",
            ),
        ];
        let stix = ThreatIndicatorDatabase::export_stix(&iocs);
        assert!(stix.contains("bundle"));
        assert!(stix.contains("indicator"));
        assert!(stix.contains("2.1"));
        // Should be parseable as JSON
        let parsed: serde_json::Value = serde_json::from_str(&stix).expect("invalid JSON");
        assert_eq!(parsed["type"], "bundle");
        let objects = parsed["objects"].as_array().unwrap();
        assert_eq!(objects.len(), 2);
    }

    #[test]
    fn export_stix_empty_slice() {
        let stix = ThreatIndicatorDatabase::export_stix(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&stix).expect("invalid JSON");
        assert_eq!(parsed["objects"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn threat_group_tracker_pre_populated() {
        let tracker = ThreatGroupTracker::new();
        assert!(tracker.get("APT28").is_some());
        assert!(tracker.get("APT29").is_some());
        assert!(tracker.get("Lazarus").is_some());
        assert!(tracker.get("FIN7").is_some());
        assert!(tracker.get("Sandworm").is_some());
    }

    #[test]
    fn threat_group_aliases_non_empty() {
        let tracker = ThreatGroupTracker::new();
        assert!(!tracker.get("APT28").unwrap().aliases.is_empty());
    }

    #[test]
    fn threat_group_search_by_alias() {
        let tracker = ThreatGroupTracker::new();
        let results = tracker.search("Fancy Bear");
        assert!(results.iter().any(|g| g.name == "APT28"));
    }

    #[test]
    fn threat_group_link_ioc() {
        let mut tracker = ThreatGroupTracker::new();
        let id = IocId(42);
        tracker.get_mut("Lazarus").unwrap().link_ioc(id);
        assert!(tracker.get("Lazarus").unwrap().iocs.contains(&id));
    }

    #[test]
    fn threat_group_insert_custom() {
        let mut tracker = ThreatGroupTracker::new();
        tracker.insert(ThreatGroup::new("CustomGroup").with_alias("CG"));
        assert!(tracker.get("CustomGroup").is_some());
    }

    #[test]
    fn ioc_type_display() {
        assert_eq!(IocType::Sha256.to_string(), "SHA-256");
        assert_eq!(IocType::Mutex.to_string(), "Mutex");
    }
}
