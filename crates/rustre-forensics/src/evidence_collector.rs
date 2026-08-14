//! Evidence collection framework: typed evidence, chain of custody,
//! evidence database, exporter, and chain-of-custody tracking.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{compute_md5, compute_sha256};
use std::fmt::Write as _;

// ─── EvidenceType ─────────────────────────────────────────────────────────────

/// The semantic type of a piece of digital evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Raw disk image or partition.
    DiskImage,
    /// Memory dump (physical or virtual).
    MemoryDump,
    /// Network packet capture.
    NetworkCapture,
    /// Log file (event log, auth log, etc.).
    LogFile,
    /// Registry hive.
    RegistryHive,
    /// Malware sample or artifact.
    MalwareSample,
    /// Email message.
    Email,
    /// Browser artefact (history, cookies, cache).
    BrowserArtefact,
    /// File system metadata (MFT, FAT, etc.).
    FileSystemMetadata,
    /// Prefetch file.
    Prefetch,
    /// LNK/shortcut file.
    LinkFile,
    /// Shell history file.
    ShellHistory,
    /// Volatile data captured live.
    VolatileData,
    /// Certificate or key material.
    CertificateKey,
    /// Custom / other evidence type.
    Other(String),
}

impl fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DiskImage => "disk_image",
            Self::MemoryDump => "memory_dump",
            Self::NetworkCapture => "network_capture",
            Self::LogFile => "log_file",
            Self::RegistryHive => "registry_hive",
            Self::MalwareSample => "malware_sample",
            Self::Email => "email",
            Self::BrowserArtefact => "browser_artefact",
            Self::FileSystemMetadata => "filesystem_metadata",
            Self::Prefetch => "prefetch",
            Self::LinkFile => "link_file",
            Self::ShellHistory => "shell_history",
            Self::VolatileData => "volatile_data",
            Self::CertificateKey => "certificate_key",
            Self::Other(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

// ─── EvidenceSource ───────────────────────────────────────────────────────────

/// Where the evidence was obtained from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSource {
    pub hostname: String,
    pub ip_address: Option<String>,
    pub os: String,
    pub collected_by: String,
    pub collection_tool: String,
    pub collection_time_ms: u64,
}

impl EvidenceSource {
    /// Create a new source record.
    #[must_use]
    pub fn new(
        hostname: impl Into<String>,
        os: impl Into<String>,
        collected_by: impl Into<String>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            os: os.into(),
            collected_by: collected_by.into(),
            ip_address: None,
            collection_tool: String::new(),
            collection_time_ms: 0,
        }
    }
}

// ─── Evidence ─────────────────────────────────────────────────────────────────

/// A single piece of digital evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique identifier for this evidence item.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Semantic type.
    pub evidence_type: EvidenceType,
    /// Source information.
    pub source: Option<EvidenceSource>,
    /// MD5 hash of the evidence data.
    pub md5: String,
    /// SHA-256 hash of the evidence data.
    pub sha256: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Confidence score (0–100).
    pub confidence: u8,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Arbitrary metadata key-value pairs.
    pub metadata: HashMap<String, String>,
    /// Collection timestamp (Unix ms).
    pub collected_at_ms: u64,
    /// Whether this evidence has been verified (hashes confirmed).
    pub verified: bool,
}

impl Evidence {
    /// Create evidence from raw bytes, computing hashes automatically.
    #[must_use]
    pub fn from_bytes(
        id: impl Into<String>,
        description: impl Into<String>,
        evidence_type: EvidenceType,
        data: &[u8],
        confidence: u8,
    ) -> Self {
        let md5 = compute_md5(data);
        let sha256 = compute_sha256(data);
        Self {
            id: id.into(),
            description: description.into(),
            evidence_type,
            source: None,
            md5,
            sha256,
            size_bytes: data.len() as u64,
            confidence: confidence.min(100),
            tags: vec![],
            metadata: HashMap::new(),
            collected_at_ms: 0,
            verified: false,
        }
    }

    /// Create evidence from known hashes (no raw data).
    #[must_use]
    pub fn from_hashes(
        id: impl Into<String>,
        description: impl Into<String>,
        evidence_type: EvidenceType,
        md5: impl Into<String>,
        sha256: impl Into<String>,
        size_bytes: u64,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            evidence_type,
            source: None,
            md5: md5.into(),
            sha256: sha256.into(),
            size_bytes,
            confidence: 100,
            tags: vec![],
            metadata: HashMap::new(),
            collected_at_ms: 0,
            verified: false,
        }
    }

    /// Verify the evidence against raw bytes.
    #[must_use]
    pub fn verify(&self, data: &[u8]) -> bool {
        compute_md5(data) == self.md5 && compute_sha256(data) == self.sha256
    }

    /// Add a tag.
    pub fn tag(&mut self, t: impl Into<String>) {
        self.tags.push(t.into());
    }

    /// Set a metadata key-value pair.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Mark as verified.
    pub const fn mark_verified(&mut self) {
        self.verified = true;
    }

    /// Returns `true` if confidence meets or exceeds threshold.
    #[must_use]
    pub const fn is_confident(&self, threshold: u8) -> bool {
        self.confidence >= threshold
    }

    /// Return a summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} type={} size={} sha256={}...",
            self.id,
            self.description,
            self.evidence_type,
            self.size_bytes,
            &self.sha256[..16.min(self.sha256.len())]
        )
    }
}

// ─── ChainOfCustodyEntry ──────────────────────────────────────────────────────

/// A single entry in the chain of custody log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyEntry {
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Person or system responsible for this action.
    pub actor: String,
    /// Action taken (e.g. "collected", "transferred", "analyzed", "stored").
    pub action: String,
    /// Optional notes.
    pub notes: Option<String>,
    /// Hash at the time of the action (to detect tampering).
    pub hash_snapshot: Option<String>,
    /// Location of the evidence at this point.
    pub location: Option<String>,
}

impl ChainOfCustodyEntry {
    /// Create a new custody entry.
    #[must_use]
    pub fn new(timestamp_ms: u64, actor: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            timestamp_ms,
            actor: actor.into(),
            action: action.into(),
            notes: None,
            hash_snapshot: None,
            location: None,
        }
    }

    /// Attach a hash snapshot.
    #[must_use]
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.hash_snapshot = Some(hash.into());
        self
    }

    /// Attach notes.
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Attach a location.
    #[must_use]
    pub fn with_location(mut self, loc: impl Into<String>) -> Self {
        self.location = Some(loc.into());
        self
    }
}

// ─── ChainOfCustody ───────────────────────────────────────────────────────────

/// Full chain-of-custody log for an evidence item.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainOfCustody {
    pub evidence_id: String,
    pub entries: Vec<ChainOfCustodyEntry>,
}

impl ChainOfCustody {
    /// Create an empty chain for an evidence item.
    #[must_use]
    pub fn new(evidence_id: impl Into<String>) -> Self {
        Self {
            evidence_id: evidence_id.into(),
            entries: vec![],
        }
    }

    /// Add an entry.
    pub fn add(&mut self, entry: ChainOfCustodyEntry) {
        self.entries.push(entry);
    }

    /// Returns `true` if the chain is unbroken (no gaps in timestamps).
    #[must_use]
    pub fn is_unbroken(&self) -> bool {
        self.entries
            .windows(2)
            .all(|w| w[1].timestamp_ms >= w[0].timestamp_ms)
    }

    /// Return the most recent entry.
    #[must_use]
    pub fn latest(&self) -> Option<&ChainOfCustodyEntry> {
        self.entries.last()
    }

    /// Count entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export as plain text log.
    #[must_use]
    pub fn to_log(&self) -> String {
        let mut out = format!("Chain of Custody — Evidence: {}\n", self.evidence_id);
        for (i, e) in self.entries.iter().enumerate() {
            let _ = writeln!(out, "  [{}] ts={} actor='{}' action='{}'",
                i + 1,
                e.timestamp_ms,
                e.actor,
                e.action);
            if let Some(ref n) = e.notes {
                let _ = writeln!(out, "       notes: {n}");
            }
        }
        out
    }
}

// ─── EvidenceChain ────────────────────────────────────────────────────────────

/// Links a piece of evidence to its full chain of custody.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub evidence: Evidence,
    pub custody: ChainOfCustody,
}

impl EvidenceChain {
    /// Create a new chain.
    #[must_use]
    pub fn new(evidence: Evidence) -> Self {
        let custody = ChainOfCustody::new(evidence.id.clone());
        Self { evidence, custody }
    }

    /// Add a custody action.
    pub fn log_action(&mut self, ts: u64, actor: impl Into<String>, action: impl Into<String>) {
        self.custody.add(
            ChainOfCustodyEntry::new(ts, actor, action).with_hash(self.evidence.sha256.clone()),
        );
    }

    /// Returns `true` if the chain of custody is intact.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.custody.is_unbroken()
    }
}

// ─── EvidenceDatabase ─────────────────────────────────────────────────────────

/// In-memory database of collected evidence items.
#[derive(Debug, Default)]
pub struct EvidenceDatabase {
    items: HashMap<String, EvidenceChain>,
}

impl EvidenceDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an evidence item.
    pub fn insert(&mut self, chain: EvidenceChain) {
        self.items.insert(chain.evidence.id.clone(), chain);
    }

    /// Get an evidence item by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&EvidenceChain> {
        self.items.get(id)
    }

    /// Get a mutable reference.
    #[must_use]
    pub fn get_mut(&mut self, id: &str) -> Option<&mut EvidenceChain> {
        self.items.get_mut(id)
    }

    /// Remove an item.
    pub fn remove(&mut self, id: &str) -> Option<EvidenceChain> {
        self.items.remove(id)
    }

    /// Total count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Return all evidence items sorted by ID.
    #[must_use]
    pub fn all(&self) -> Vec<&EvidenceChain> {
        let mut items: Vec<&EvidenceChain> = self.items.values().collect();
        items.sort_by_key(|c| &c.evidence.id);
        items
    }

    /// Search by SHA-256 hash.
    #[must_use]
    pub fn find_by_sha256(&self, sha256: &str) -> Option<&EvidenceChain> {
        self.items.values().find(|c| c.evidence.sha256 == sha256)
    }

    /// Search by type.
    #[must_use]
    pub fn by_type(&self, et: &EvidenceType) -> Vec<&EvidenceChain> {
        self.items
            .values()
            .filter(|c| &c.evidence.evidence_type == et)
            .collect()
    }

    /// Return all high-confidence items.
    #[must_use]
    pub fn high_confidence(&self, threshold: u8) -> Vec<&EvidenceChain> {
        self.items
            .values()
            .filter(|c| c.evidence.confidence >= threshold)
            .collect()
    }

    /// Return verified items.
    #[must_use]
    pub fn verified(&self) -> Vec<&EvidenceChain> {
        self.items
            .values()
            .filter(|c| c.evidence.verified)
            .collect()
    }
}

// ─── EvidenceCollector ────────────────────────────────────────────────────────

/// Collects, hashes, and stores digital evidence with custody logging.
pub struct EvidenceCollector {
    pub db: EvidenceDatabase,
    id_counter: u64,
    default_analyst: String,
}

impl EvidenceCollector {
    /// Create a new collector.
    #[must_use]
    pub fn new(analyst: impl Into<String>) -> Self {
        Self {
            db: EvidenceDatabase::new(),
            id_counter: 0,
            default_analyst: analyst.into(),
        }
    }

    /// Generate a unique evidence ID.
    #[must_use]
    pub fn next_id(&mut self) -> String {
        self.id_counter += 1;
        format!("EV-{:06}", self.id_counter)
    }

    /// Collect evidence from raw bytes.
    pub fn collect_bytes(
        &mut self,
        description: impl Into<String>,
        evidence_type: EvidenceType,
        data: &[u8],
        ts_ms: u64,
    ) -> String {
        let id = self.next_id();
        let evidence = Evidence::from_bytes(&id, description, evidence_type, data, 100);
        let mut chain = EvidenceChain::new(evidence);
        chain.log_action(ts_ms, &self.default_analyst, "collected");
        self.db.insert(chain);
        id
    }

    /// Collect evidence from pre-computed hashes (no raw data).
    pub fn collect_hashes(
        &mut self,
        description: impl Into<String>,
        evidence_type: EvidenceType,
        md5: impl Into<String>,
        sha256: impl Into<String>,
        size_bytes: u64,
        ts_ms: u64,
    ) -> String {
        let id = self.next_id();
        let evidence =
            Evidence::from_hashes(&id, description, evidence_type, md5, sha256, size_bytes);
        let mut chain = EvidenceChain::new(evidence);
        chain.log_action(ts_ms, &self.default_analyst, "collected_from_hashes");
        self.db.insert(chain);
        id
    }

    /// Verify an evidence item by re-hashing raw bytes.
    #[must_use]
    pub fn verify(&self, id: &str, data: &[u8]) -> bool {
        self.db.get(id).is_some_and(|c| c.evidence.verify(data))
    }

    /// Log a transfer action for an evidence item.
    pub fn log_transfer(&mut self, id: &str, ts_ms: u64, recipient: impl Into<String>) {
        if let Some(chain) = self.db.get_mut(id) {
            chain.log_action(
                ts_ms,
                self.default_analyst.clone(),
                format!("transferred to {}", recipient.into()),
            );
        }
    }

    /// Mark an evidence item as verified.
    pub fn mark_verified(&mut self, id: &str) {
        if let Some(chain) = self.db.get_mut(id) {
            chain.evidence.mark_verified();
        }
    }

    /// Total evidence collected.
    #[must_use]
    pub fn count(&self) -> usize {
        self.db.len()
    }
}

// ─── EvidenceExporter ─────────────────────────────────────────────────────────

/// Exports evidence collections to various formats.
#[derive(Debug, Clone, Default)]
pub struct EvidenceExporter;

impl EvidenceExporter {
    /// Create a new exporter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Export evidence list to JSON.
    #[must_use]
    pub fn to_json(&self, db: &EvidenceDatabase) -> String {
        let items: Vec<_> = db
            .all()
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.evidence.id,
                    "description": c.evidence.description,
                    "type": c.evidence.evidence_type.to_string(),
                    "sha256": c.evidence.sha256,
                    "md5": c.evidence.md5,
                    "size_bytes": c.evidence.size_bytes,
                    "confidence": c.evidence.confidence,
                    "verified": c.evidence.verified,
                    "custody_entries": c.custody.len(),
                })
            })
            .collect();
        serde_json::to_string_pretty(&items).unwrap_or_default()
    }

    /// Export evidence list to CSV.
    #[must_use]
    pub fn to_csv(&self, db: &EvidenceDatabase) -> String {
        let mut out =
            String::from("id,type,description,sha256,md5,size_bytes,confidence,verified\n");
        for c in db.all() {
            let _ = writeln!(out, "{},{},{},{},{},{},{},{}",
                c.evidence.id,
                c.evidence.evidence_type,
                // The comma was already being substituted here; a CR or LF was
                // not, and it ends the record early — the remaining columns of
                // that row become a new row with the wrong headings. Evidence
                // descriptions are free text, so line breaks are ordinary.
                c.evidence.description.replace(',', ";").replace(['\r', '\n'], " "),
                c.evidence.sha256,
                c.evidence.md5,
                c.evidence.size_bytes,
                c.evidence.confidence,
                c.evidence.verified);
        }
        out
    }

    /// Export a single chain-of-custody log as plain text.
    #[must_use]
    pub fn chain_log(&self, chain: &EvidenceChain) -> String {
        chain.custody.to_log()
    }

    /// Export a DFIR summary report.
    #[must_use]
    pub fn dfir_summary(&self, db: &EvidenceDatabase, case_id: &str) -> String {
        let mut out = format!("# DFIR Evidence Summary — Case {case_id}\n\n");
        let _ = writeln!(out, "Total items: {}", db.len());
        let _ = writeln!(out, "Verified items: {}", db.verified().len());
        let _ = writeln!(out, "High-confidence items (≥80): {}\n",
            db.high_confidence(80).len());
        out.push_str("## Evidence Inventory\n\n");
        for c in db.all() {
            let _ = writeln!(out, "- {}", c.evidence.summary());
        }
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> Vec<u8> {
        b"hello world forensics test data".to_vec()
    }

    // EvidenceType
    #[test]
    fn test_evidence_type_display() {
        assert_eq!(EvidenceType::MemoryDump.to_string(), "memory_dump");
    }
    #[test]
    fn test_evidence_type_other() {
        assert_eq!(EvidenceType::Other("foo".into()).to_string(), "foo");
    }

    // Evidence
    #[test]
    fn test_evidence_from_bytes() {
        let e = Evidence::from_bytes(
            "EV-001",
            "test",
            EvidenceType::MemoryDump,
            &sample_data(),
            90,
        );
        assert_eq!(e.id, "EV-001");
        assert!(!e.sha256.is_empty());
        assert!(!e.md5.is_empty());
        assert_eq!(e.size_bytes, sample_data().len() as u64);
    }
    #[test]
    fn test_evidence_verify_ok() {
        let data = sample_data();
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &data, 100);
        assert!(e.verify(&data));
    }
    #[test]
    fn test_evidence_verify_fail() {
        let data = sample_data();
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &data, 100);
        assert!(!e.verify(b"different data"));
    }
    #[test]
    fn test_evidence_from_hashes() {
        let e = Evidence::from_hashes(
            "EV-002",
            "hash only",
            EvidenceType::DiskImage,
            "abc",
            "def123",
            1024,
        );
        assert_eq!(e.md5, "abc");
        assert_eq!(e.sha256, "def123");
    }
    #[test]
    fn test_evidence_tag_and_meta() {
        let mut e =
            Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 80);
        e.tag("malware");
        e.set_meta("case", "C-001");
        assert!(e.tags.contains(&"malware".to_string()));
        assert_eq!(e.metadata.get("case"), Some(&"C-001".to_string()));
    }
    #[test]
    fn test_evidence_mark_verified() {
        let mut e =
            Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 80);
        assert!(!e.verified);
        e.mark_verified();
        assert!(e.verified);
    }
    #[test]
    fn test_evidence_confidence() {
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 85);
        assert!(e.is_confident(80));
        assert!(!e.is_confident(90));
    }
    #[test]
    fn test_evidence_summary_nonempty() {
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        assert!(!e.summary().is_empty());
    }

    // ChainOfCustodyEntry
    #[test]
    fn test_chain_entry_new() {
        let e = ChainOfCustodyEntry::new(1000, "analyst", "collected");
        assert_eq!(e.actor, "analyst");
        assert_eq!(e.action, "collected");
    }
    #[test]
    fn test_chain_entry_with_hash() {
        let e = ChainOfCustodyEntry::new(1000, "a", "collected").with_hash("sha256abc");
        assert_eq!(e.hash_snapshot, Some("sha256abc".to_string()));
    }
    #[test]
    fn test_chain_entry_with_notes() {
        let e = ChainOfCustodyEntry::new(1000, "a", "collected").with_notes("test note");
        assert!(e.notes.is_some());
    }

    // ChainOfCustody
    #[test]
    fn test_chain_new_empty() {
        let c = ChainOfCustody::new("EV-001");
        assert!(c.is_empty());
    }
    #[test]
    fn test_chain_add_and_len() {
        let mut c = ChainOfCustody::new("EV-001");
        c.add(ChainOfCustodyEntry::new(1000, "a", "collected"));
        assert_eq!(c.len(), 1);
    }
    #[test]
    fn test_chain_is_unbroken() {
        let mut c = ChainOfCustody::new("EV-001");
        c.add(ChainOfCustodyEntry::new(1000, "a", "collected"));
        c.add(ChainOfCustodyEntry::new(2000, "b", "transferred"));
        assert!(c.is_unbroken());
    }
    #[test]
    fn test_chain_broken() {
        let mut c = ChainOfCustody::new("EV-001");
        c.add(ChainOfCustodyEntry::new(2000, "a", "collected"));
        c.add(ChainOfCustodyEntry::new(1000, "b", "transferred"));
        assert!(!c.is_unbroken());
    }
    #[test]
    fn test_chain_latest() {
        let mut c = ChainOfCustody::new("EV-001");
        c.add(ChainOfCustodyEntry::new(1000, "a", "collected"));
        c.add(ChainOfCustodyEntry::new(2000, "b", "analyzed"));
        assert_eq!(c.latest().unwrap().action, "analyzed");
    }
    #[test]
    fn test_chain_to_log() {
        let mut c = ChainOfCustody::new("EV-001");
        c.add(ChainOfCustodyEntry::new(1000, "a", "collected"));
        let log = c.to_log();
        assert!(log.contains("EV-001"));
    }

    // EvidenceChain
    #[test]
    fn test_evidence_chain_new() {
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        let chain = EvidenceChain::new(e);
        assert_eq!(chain.evidence.id, "EV-001");
    }
    #[test]
    fn test_evidence_chain_log_action() {
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        let mut chain = EvidenceChain::new(e);
        chain.log_action(1000, "analyst", "collected");
        assert_eq!(chain.custody.len(), 1);
    }
    #[test]
    fn test_evidence_chain_is_intact() {
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        let mut chain = EvidenceChain::new(e);
        chain.log_action(1000, "a", "collected");
        chain.log_action(2000, "b", "analyzed");
        assert!(chain.is_intact());
    }

    // EvidenceDatabase
    #[test]
    fn test_db_insert_and_get() {
        let mut db = EvidenceDatabase::new();
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        db.insert(EvidenceChain::new(e));
        assert!(db.get("EV-001").is_some());
    }
    #[test]
    fn test_db_remove() {
        let mut db = EvidenceDatabase::new();
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        db.insert(EvidenceChain::new(e));
        assert!(db.remove("EV-001").is_some());
        assert!(db.is_empty());
    }
    #[test]
    fn test_db_by_type() {
        let mut db = EvidenceDatabase::new();
        let e1 = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        let e2 = Evidence::from_bytes(
            "EV-002",
            "test",
            EvidenceType::MemoryDump,
            &sample_data(),
            90,
        );
        db.insert(EvidenceChain::new(e1));
        db.insert(EvidenceChain::new(e2));
        assert_eq!(db.by_type(&EvidenceType::LogFile).len(), 1);
    }
    /// One evidence item must occupy exactly one CSV row. Descriptions are free
    /// text written by an analyst, so commas and line breaks are ordinary; the
    /// comma was already handled, a newline used to start a bogus second row.
    #[test]
    fn test_csv_row_per_evidence_survives_newlines_in_description() {
        let mut db = EvidenceDatabase::new();
        let e = Evidence::from_bytes(
            "EV-001",
            "found in memory,\nsecond line\rthird",
            EvidenceType::LogFile,
            &sample_data(),
            90,
        );
        db.insert(EvidenceChain::new(e));

        let csv = EvidenceExporter::new().to_csv(&db);
        // Header plus exactly one record.
        assert_eq!(csv.lines().count(), 2, "evidence spilled across rows: {csv:?}");
        let header_cols = csv.lines().next().unwrap().split(',').count();
        let row_cols = csv.lines().nth(1).unwrap().split(',').count();
        assert_eq!(row_cols, header_cols, "row does not line up with the header: {csv:?}");
    }

    #[test]
    fn test_db_find_by_sha256() {
        let data = sample_data();
        let sha = compute_sha256(&data);
        let mut db = EvidenceDatabase::new();
        let e = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &data, 90);
        db.insert(EvidenceChain::new(e));
        assert!(db.find_by_sha256(&sha).is_some());
    }
    #[test]
    fn test_db_high_confidence() {
        let mut db = EvidenceDatabase::new();
        let e1 = Evidence::from_bytes("EV-001", "test", EvidenceType::LogFile, &sample_data(), 90);
        let e2 = Evidence::from_bytes("EV-002", "test", EvidenceType::LogFile, b"x", 40);
        db.insert(EvidenceChain::new(e1));
        db.insert(EvidenceChain::new(e2));
        assert_eq!(db.high_confidence(80).len(), 1);
    }

    // EvidenceCollector
    #[test]
    fn test_collector_collect_bytes() {
        let mut c = EvidenceCollector::new("analyst");
        let id = c.collect_bytes("test", EvidenceType::LogFile, &sample_data(), 1000);
        assert!(c.db.get(&id).is_some());
    }
    #[test]
    fn test_collector_collect_hashes() {
        let mut c = EvidenceCollector::new("analyst");
        let id = c.collect_hashes(
            "test",
            EvidenceType::DiskImage,
            "abc",
            "sha256def",
            4096,
            1000,
        );
        assert!(c.db.get(&id).is_some());
    }
    #[test]
    fn test_collector_verify() {
        let data = sample_data();
        let mut c = EvidenceCollector::new("analyst");
        let id = c.collect_bytes("test", EvidenceType::LogFile, &data, 1000);
        assert!(c.verify(&id, &data));
    }
    #[test]
    fn test_collector_count() {
        let mut c = EvidenceCollector::new("analyst");
        c.collect_bytes("a", EvidenceType::LogFile, &sample_data(), 1000);
        c.collect_bytes("b", EvidenceType::LogFile, &sample_data(), 2000);
        assert_eq!(c.count(), 2);
    }
    #[test]
    fn test_collector_mark_verified() {
        let mut c = EvidenceCollector::new("analyst");
        let id = c.collect_bytes("test", EvidenceType::LogFile, &sample_data(), 1000);
        c.mark_verified(&id);
        assert!(c.db.get(&id).unwrap().evidence.verified);
    }

    // EvidenceExporter
    #[test]
    fn test_exporter_to_json() {
        let mut c = EvidenceCollector::new("analyst");
        c.collect_bytes("test", EvidenceType::LogFile, &sample_data(), 1000);
        let exporter = EvidenceExporter::new();
        let json = exporter.to_json(&c.db);
        assert!(json.contains("EV-"));
    }
    #[test]
    fn test_exporter_to_csv() {
        let mut c = EvidenceCollector::new("analyst");
        c.collect_bytes("test", EvidenceType::LogFile, &sample_data(), 1000);
        let exporter = EvidenceExporter::new();
        let csv = exporter.to_csv(&c.db);
        assert!(csv.contains("id,type"));
    }
    #[test]
    fn test_exporter_dfir_summary() {
        let mut c = EvidenceCollector::new("analyst");
        c.collect_bytes("test", EvidenceType::LogFile, &sample_data(), 1000);
        let exporter = EvidenceExporter::new();
        let summary = exporter.dfir_summary(&c.db, "CASE-001");
        assert!(summary.contains("CASE-001"));
    }
}
