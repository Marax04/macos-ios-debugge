//! Forensic artifact store: typed artifacts with confidence scores,
//! timeline integration, query/filter operations, and export.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{EvidenceHash, HashAlgorithm};
use std::fmt::Write as _;

/// Convert a [0.0, 1.0] confidence score to a clamped 0..=100 byte.
fn clamp_confidence_to_u8(c: f32) -> u8 {
    if c.is_nan() {
        return 0;
    }
    // Iterate through 0..=100 to find the closest integer without using a
    // floating-point-to-integer cast (which trips clippy::cast_sign_loss /
    // cast_possible_truncation).
    let scaled = (c * 100.0).clamp(0.0, 100.0);
    let mut best: u8 = 0;
    for i in 0u8..=100 {
        if f32::from(i16::from(i)) <= scaled {
            best = i;
        } else {
            break;
        }
    }
    best
}

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone)]
pub enum ArtifactStoreError {
    #[error("artifact '{0}' already exists")]
    Duplicate(String),
    #[error("artifact '{0}' not found")]
    NotFound(String),
    #[error("export failed: {0}")]
    ExportFailed(String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("invalid query: {0}")]
    InvalidQuery(String),
}

// ─── ArtifactType ─────────────────────────────────────────────────────────────

/// Classification of a forensic artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    Process,
    File,
    Registry,
    Network,
    Memory,
    Credential,
    Certificate,
    Prefetch,
    EventLog,
    ShellBag,
    JumpList,
    BrowserHistory,
    WifiProfile,
    RecentDoc,
    AmCache,
    Shimcache,
    Other(String),
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Process => write!(f, "process"),
            Self::File => write!(f, "file"),
            Self::Registry => write!(f, "registry"),
            Self::Network => write!(f, "network"),
            Self::Memory => write!(f, "memory"),
            Self::Credential => write!(f, "credential"),
            Self::Certificate => write!(f, "certificate"),
            Self::Prefetch => write!(f, "prefetch"),
            Self::EventLog => write!(f, "event_log"),
            Self::ShellBag => write!(f, "shellbag"),
            Self::JumpList => write!(f, "jumplist"),
            Self::BrowserHistory => write!(f, "browser_history"),
            Self::WifiProfile => write!(f, "wifi_profile"),
            Self::RecentDoc => write!(f, "recent_doc"),
            Self::AmCache => write!(f, "amcache"),
            Self::Shimcache => write!(f, "shimcache"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ─── ForensicArtifact ─────────────────────────────────────────────────────────

/// A single forensic artifact collected from an OS or binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicArtifact {
    /// Unique identifier.
    pub id: String,
    /// Semantic type.
    pub artifact_type: ArtifactType,
    /// Where the artifact came from (e.g. process name, registry hive, log file).
    pub source: String,
    /// Confidence in the artifact's accuracy [0.0, 1.0].
    pub confidence: f32,
    /// Collection timestamp (ms since epoch).
    pub timestamp: u64,
    /// Raw artifact data (may be empty if `metadata` carries all information).
    pub data: Vec<u8>,
    /// Key/value metadata describing the artifact.
    pub metadata: HashMap<String, String>,
    /// Hashes of `data` if populated.
    pub hashes: Vec<EvidenceHash>,
    /// Analyst tags.
    pub tags: Vec<String>,
    /// MITRE ATT&CK technique IDs this artifact is evidence for.
    pub technique_ids: Vec<String>,
    /// Whether this artifact has been verified by a second analyst.
    pub verified: bool,
}

impl ForensicArtifact {
    /// Create a new artifact without data.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        artifact_type: ArtifactType,
        source: impl Into<String>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id: id.into(),
            artifact_type,
            source: source.into(),
            confidence: 1.0,
            timestamp: now,
            data: Vec::new(),
            metadata: HashMap::new(),
            hashes: Vec::new(),
            tags: Vec::new(),
            technique_ids: Vec::new(),
            verified: false,
        }
    }

    /// Create an artifact and compute hashes from the provided data.
    #[must_use]
    pub fn with_data(
        id: impl Into<String>,
        artifact_type: ArtifactType,
        source: impl Into<String>,
        data: Vec<u8>,
    ) -> Self {
        let mut art = Self::new(id, artifact_type, source);
        art.set_data(data);
        art
    }

    /// Set the data field and recompute hashes.
    pub fn set_data(&mut self, data: Vec<u8>) {
        let md5 = EvidenceHash::compute(&data, HashAlgorithm::Md5);
        let sha256 = EvidenceHash::compute(&data, HashAlgorithm::Sha256);
        self.hashes = vec![md5, sha256];
        self.data = data;
    }

    /// Add a metadata key/value pair.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get a metadata value by key.
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }

    /// Add an analyst tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Add a MITRE ATT&CK technique ID.
    pub fn add_technique(&mut self, id: impl Into<String>) {
        self.technique_ids.push(id.into());
    }

    /// Returns `true` if the artifact has high confidence (>= 0.8).
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }

    /// Returns the SHA-256 hex string of the data, if computed.
    #[must_use]
    pub fn sha256_hex(&self) -> Option<&str> {
        self.hashes
            .iter()
            .find(|h| matches!(h.algorithm, HashAlgorithm::Sha256))
            .map(|h| h.value.as_str())
    }

    /// Builder: set confidence.
    #[must_use]
    pub const fn with_confidence(mut self, confidence: f32) -> Self {
        // NaN-safe clamp: `f32::clamp` propagates NaN and `is_nan()` is not
        // available in a const fn. A NaN confidence would lose every comparison
        // it takes part in, so the artifact would drop out of every ranking.
        self.confidence = if confidence >= 1.0 {
            1.0
        } else if confidence > 0.0 {
            confidence
        } else {
            0.0
        };
        self
    }

    /// Builder: add tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Builder: add technique ID.
    #[must_use]
    pub fn technique(mut self, id: impl Into<String>) -> Self {
        self.technique_ids.push(id.into());
        self
    }
}

// ─── ArtifactQuery ────────────────────────────────────────────────────────────

/// A query for filtering artifacts in the store.
#[derive(Debug, Clone, Default)]
pub struct ArtifactQuery {
    /// Filter by artifact type.
    pub artifact_type: Option<ArtifactType>,
    /// Filter by source substring.
    pub source_contains: Option<String>,
    /// Minimum confidence [0.0, 1.0].
    pub min_confidence: Option<f32>,
    /// Filter by tag.
    pub tag: Option<String>,
    /// Filter by technique ID.
    pub technique_id: Option<String>,
    /// Timestamp range (start, end) in ms.
    pub timestamp_range: Option<(u64, u64)>,
    /// Maximum results to return.
    pub limit: Option<usize>,
    /// Sort by field.
    pub sort_by: QuerySortField,
    /// Sort descending.
    pub sort_desc: bool,
}

/// Field to sort query results by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum QuerySortField {
    #[default]
    Timestamp,
    Confidence,
    Source,
    Type,
}

impl ArtifactQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn of_type(mut self, t: ArtifactType) -> Self {
        self.artifact_type = Some(t);
        self
    }

    #[must_use]
    pub fn from_source(mut self, s: impl Into<String>) -> Self {
        self.source_contains = Some(s.into());
        self
    }

    #[must_use]
    pub const fn min_confidence(mut self, c: f32) -> Self {
        self.min_confidence = Some(c);
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    #[must_use]
    pub fn with_technique(mut self, id: impl Into<String>) -> Self {
        self.technique_id = Some(id.into());
        self
    }

    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
}

// ─── ExportFormat ─────────────────────────────────────────────────────────────

/// Format for exporting artifacts from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    /// STIX 2.1 JSON bundle (simplified).
    Stix,
}

// ─── ArtifactStore ────────────────────────────────────────────────────────────

/// Thread-safe store for forensic artifacts with query and export capabilities.
pub struct ArtifactStore {
    artifacts: std::sync::RwLock<HashMap<String, ForensicArtifact>>,
    /// Collection name / case ID.
    pub name: String,
    /// Optional description.
    pub description: String,
    /// Maximum number of artifacts the store holds (0 = unlimited).
    capacity: usize,
}

impl ArtifactStore {
    /// Create a new store.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            artifacts: std::sync::RwLock::new(HashMap::new()),
            name: name.into(),
            description: String::new(),
            capacity: 0,
        }
    }

    /// Create a store with a maximum capacity.
    #[must_use]
    pub const fn with_capacity(mut self, cap: usize) -> Self {
        self.capacity = cap;
        self
    }

    // ── Mutation ─────────────────────────────────────────────────────────────

    /// Store an artifact. Returns `Ok(id)` on success.
    ///
    /// # Errors
    /// Returns `ArtifactStoreError::Duplicate` if an artifact with the same ID
    /// already exists.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn store(&self, artifact: ForensicArtifact) -> Result<String, ArtifactStoreError> {
        let mut map = self.artifacts.write().unwrap();
        if map.contains_key(&artifact.id) {
            return Err(ArtifactStoreError::Duplicate(artifact.id));
        }
        if self.capacity > 0 && map.len() >= self.capacity {
            // Evict oldest artifact.
            // `artifacts` is a HashMap and timestamps tie easily (coarse clock,
            // bursts of ingestion), so without a tie-break on the id the
            // artifact evicted differs between runs on identical input.
            let oldest_key = map
                .values()
                .min_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.id.cmp(&b.id)))
                .map(|a| a.id.clone());
            if let Some(k) = oldest_key {
                map.remove(&k);
            }
        }
        let id = artifact.id.clone();
        map.insert(id.clone(), artifact);
        drop(map);
        Ok(id)
    }

    /// Store or overwrite an artifact.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn upsert(&self, artifact: ForensicArtifact) -> String {
        let id = artifact.id.clone();
        self.artifacts.write().unwrap().insert(id.clone(), artifact);
        id
    }

    /// Remove an artifact by ID.
    ///
    /// # Errors
    /// Returns `ArtifactStoreError::NotFound` if the ID is unknown.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn remove(&self, id: &str) -> Result<ForensicArtifact, ArtifactStoreError> {
        self.artifacts
            .write().unwrap()
            .remove(id)
            .ok_or_else(|| ArtifactStoreError::NotFound(id.to_string()))
    }

    /// Mark an artifact as verified.
    ///
    /// # Errors
    /// Returns `ArtifactStoreError::NotFound` if the ID is unknown.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn verify(&self, id: &str) -> Result<(), ArtifactStoreError> {
        let mut map = self.artifacts.write().unwrap();
        let art = map
            .get_mut(id)
            .ok_or_else(|| ArtifactStoreError::NotFound(id.to_string()))?;
        art.verified = true;
        drop(map);
        Ok(())
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Get an artifact by ID.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<ForensicArtifact> {
        self.artifacts.read().unwrap().get(id).cloned()
    }

    /// Run a query and return matching artifacts.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn query(&self, q: &ArtifactQuery) -> Vec<ForensicArtifact> {
        let map_guard = self.artifacts.read().unwrap();
        let mut results: Vec<ForensicArtifact> = map_guard
            .values()
            .filter(|art| {
                if let Some(ref t) = q.artifact_type
                    && &art.artifact_type != t {
                        return false;
                    }
                if let Some(ref s) = q.source_contains
                    && !art.source.contains(s.as_str()) {
                        return false;
                    }
                if let Some(min_c) = q.min_confidence
                    && art.confidence < min_c {
                        return false;
                    }
                if let Some(ref tag) = q.tag
                    && !art.tags.iter().any(|t| t == tag) {
                        return false;
                    }
                if let Some(ref tid) = q.technique_id
                    && !art.technique_ids.iter().any(|t| t == tid) {
                        return false;
                    }
                if let Some((start, end)) = q.timestamp_range
                    && (art.timestamp < start || art.timestamp > end) {
                        return false;
                    }
                true
            })
            .cloned()
            .collect();
        drop(map_guard);

        // Sort.
        match q.sort_by {
            QuerySortField::Timestamp => results.sort_by_key(|a| a.timestamp),
            QuerySortField::Confidence => {
                results.sort_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap());
            }
            QuerySortField::Source => results.sort_by(|a, b| a.source.cmp(&b.source)),
            QuerySortField::Type => {
                results.sort_by_key(|a| a.artifact_type.to_string());
            }
        }
        if q.sort_desc {
            results.reverse();
        }
        if let Some(lim) = q.limit {
            results.truncate(lim);
        }
        results
    }

    /// Return all artifacts grouped by type.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn by_type(&self) -> HashMap<String, Vec<ForensicArtifact>> {
        let map = self.artifacts.read().unwrap();
        let mut grouped: HashMap<String, Vec<ForensicArtifact>> = HashMap::new();
        for art in map.values() {
            grouped
                .entry(art.artifact_type.to_string())
                .or_default()
                .push(art.clone());
        }
        drop(map);
        grouped
    }

    /// Return count of artifacts by type.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn type_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for art in self.artifacts.read().unwrap().values() {
            *counts.entry(art.artifact_type.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Return all artifacts with confidence >= threshold.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn high_confidence(&self, threshold: f32) -> Vec<ForensicArtifact> {
        self.artifacts
            .read().unwrap()
            .values()
            .filter(|a| a.confidence >= threshold)
            .cloned()
            .collect()
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Total artifact count.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn count(&self) -> usize {
        self.artifacts.read().unwrap().len()
    }

    /// Returns `true` if the store is empty.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.artifacts.read().unwrap().is_empty()
    }

    /// Average confidence across all artifacts.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn avg_confidence(&self) -> f32 {
        let map = self.artifacts.read().unwrap();
        if map.is_empty() {
            return 0.0;
        }
        let len_f32 = u16::try_from(map.len()).map_or(f32::INFINITY, f32::from);
        map.values().map(|a| a.confidence).sum::<f32>() / len_f32
    }

    // ── Export ────────────────────────────────────────────────────────────────

    /// Export all artifacts (or a subset) to the given format.
    ///
    /// # Errors
    /// Returns `ArtifactStoreError::Serialization` on failure.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn export(
        &self,
        format: &ExportFormat,
        ids: Option<&[&str]>,
    ) -> Result<String, ArtifactStoreError> {
        let owned_artifacts: Vec<ForensicArtifact> = {
            let map = self.artifacts.read().unwrap();
            ids.map_or_else(
                || map.values().cloned().collect(),
                |id_list| id_list.iter().filter_map(|id| map.get(*id).cloned()).collect(),
            )
        };
        let artifacts: Vec<&ForensicArtifact> = owned_artifacts.iter().collect();

        match format {
            ExportFormat::Json => serde_json::to_string_pretty(&artifacts)
                .map_err(|e| ArtifactStoreError::Serialization(e.to_string())),

            ExportFormat::Csv => {
                let mut out = String::from(
                    "id,type,source,confidence,timestamp,verified,tags,techniques\n",
                );
                for art in &artifacts {
                    let _ = writeln!(out, "{},{},{},{:.2},{},{},\"{}\",\"{}\"",
                        csv_escape(&art.id),
                        art.artifact_type,
                        csv_escape(&art.source),
                        art.confidence,
                        art.timestamp,
                        art.verified,
                        art.tags.join(";"),
                        art.technique_ids.join(";"));
                }
                Ok(out)
            }

            ExportFormat::Stix => {
                let objects: Vec<serde_json::Value> = artifacts
                    .iter()
                    .map(|art| {
                        serde_json::json!({
                            "type": "observed-data",
                            "spec_version": "2.1",
                            "id": format!("observed-data--{}", art.id),
                            "confidence": clamp_confidence_to_u8(art.confidence),
                            "created": art.timestamp,
                            "modified": art.timestamp,
                            "first_observed": art.timestamp,
                            "last_observed": art.timestamp,
                            "number_observed": 1,
                            "object_refs": [],
                            "extensions": {
                                "forensic-artifact": {
                                    "artifact_type": art.artifact_type.to_string(),
                                    "source": art.source,
                                    "tags": art.tags,
                                    "techniques": art.technique_ids,
                                }
                            }
                        })
                    })
                    .collect();
                let bundle = serde_json::json!({
                    "type": "bundle",
                    "spec_version": "2.1",
                    "id": format!("bundle--{}", uuid_simple()),
                    "objects": objects,
                });
                serde_json::to_string_pretty(&bundle)
                    .map_err(|e| ArtifactStoreError::Serialization(e.to_string()))
            }
        }
    }

    /// Clear all artifacts from the store.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn clear(&self) {
        self.artifacts.write().unwrap().clear();
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn uuid_simple() -> String {
    // Derive a pseudo-UUID by XOR-folding the SHA-256 of a combination of
    // the current time (nanoseconds) and the address of a stack variable, so
    // that two calls in the same nanosecond still produce distinct values.
    // This is NOT cryptographically random but is sufficient for a STIX bundle
    // identifier that only needs to be locally unique.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    // Mix in a stack address as an entropy source to differentiate rapid calls.
    let stack_addr = &raw const ts as u64;
    let seed = ts ^ stack_addr ^ (ts.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    // Produce 32 hex chars by spreading the 64-bit seed across 128 bits using
    // a simple hash-mix so the output resembles a UUID format.
    let lo = seed;
    let hi = seed
        .wrapping_mul(0x6c62_272e_07bb_0142)
        .wrapping_add(0x62b8_2175_6295_c58d);
    format!("{hi:016x}{lo:016x}")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_artifact(id: &str, kind: ArtifactType, source: &str, confidence: f32) -> ForensicArtifact {
        let mut a = ForensicArtifact::new(id, kind, source);
        a.confidence = confidence;
        a
    }

    fn populated_store() -> ArtifactStore {
        let store = ArtifactStore::new("test-case");
        store.upsert(make_artifact("art-1", ArtifactType::Process, "winlogon.exe", 0.9));
        store.upsert(make_artifact("art-2", ArtifactType::Registry, "HKCU\\Run", 0.85));
        store.upsert(make_artifact("art-3", ArtifactType::Network, "185.220.101.1:443", 0.95));
        store.upsert(
            make_artifact("art-4", ArtifactType::File, "C:\\Windows\\Temp\\x.exe", 0.7)
                .tag("malware")
                .technique("T1059"),
        );
        store
    }

    #[test]
    fn test_store_and_get() {
        let store = ArtifactStore::new("case-1");
        let art = make_artifact("a1", ArtifactType::Process, "svchost.exe", 0.9);
        store.store(art).unwrap();
        let retrieved = store.get("a1").unwrap();
        assert_eq!(retrieved.id, "a1");
    }

    #[test]
    fn test_store_duplicate_error() {
        let store = ArtifactStore::new("case-1");
        let art = make_artifact("dup", ArtifactType::File, "x", 0.5);
        store.store(art.clone()).unwrap();
        let err = store.store(art).unwrap_err();
        assert!(matches!(err, ArtifactStoreError::Duplicate(_)));
    }

    #[test]
    fn test_upsert_overwrites() {
        let store = ArtifactStore::new("case-1");
        store.upsert(make_artifact("x", ArtifactType::File, "old", 0.5));
        store.upsert(make_artifact("x", ArtifactType::File, "new", 0.9));
        let a = store.get("x").unwrap();
        assert_eq!(a.source, "new");
    }

    #[test]
    fn test_remove_existing() {
        let store = ArtifactStore::new("case-1");
        store.upsert(make_artifact("r1", ArtifactType::Memory, "dump", 0.8));
        let removed = store.remove("r1").unwrap();
        assert_eq!(removed.id, "r1");
        assert!(store.get("r1").is_none());
    }

    #[test]
    fn test_remove_missing_error() {
        let store = ArtifactStore::new("case-1");
        let err = store.remove("ghost").unwrap_err();
        assert!(matches!(err, ArtifactStoreError::NotFound(_)));
    }

    #[test]
    fn test_verify() {
        let store = ArtifactStore::new("case-1");
        store.upsert(make_artifact("v1", ArtifactType::Credential, "lsass", 0.9));
        store.verify("v1").unwrap();
        assert!(store.get("v1").unwrap().verified);
    }

    #[test]
    fn test_verify_missing() {
        let store = ArtifactStore::new("case-1");
        assert!(store.verify("ghost").is_err());
    }

    #[test]
    fn test_query_by_type() {
        let store = populated_store();
        let q = ArtifactQuery::new().of_type(ArtifactType::Network);
        let results = store.query(&q);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].artifact_type, ArtifactType::Network));
    }

    #[test]
    fn test_query_min_confidence() {
        let store = populated_store();
        let q = ArtifactQuery::new().min_confidence(0.9);
        let results = store.query(&q);
        assert!(results.iter().all(|a| a.confidence >= 0.9));
    }

    #[test]
    fn test_query_by_tag() {
        let store = populated_store();
        let q = ArtifactQuery::new().with_tag("malware");
        let results = store.query(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "art-4");
    }

    #[test]
    fn test_query_by_technique() {
        let store = populated_store();
        let q = ArtifactQuery::new().with_technique("T1059");
        let results = store.query(&q);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_query_limit() {
        let store = populated_store();
        let q = ArtifactQuery::new().limit(2);
        let results = store.query(&q);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_source_contains() {
        let store = populated_store();
        let q = ArtifactQuery::new().from_source("HKCU");
        let results = store.query(&q);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_type_counts() {
        let store = populated_store();
        let counts = store.type_counts();
        assert_eq!(*counts.get("process").unwrap_or(&0), 1);
        assert_eq!(*counts.get("network").unwrap_or(&0), 1);
    }

    #[test]
    fn test_by_type_grouping() {
        let store = populated_store();
        let grouped = store.by_type();
        assert!(grouped.contains_key("process"));
        assert!(grouped.contains_key("registry"));
    }

    #[test]
    fn test_high_confidence() {
        let store = populated_store();
        let hc = store.high_confidence(0.9);
        assert!(hc.iter().all(|a| a.confidence >= 0.9));
    }

    #[test]
    fn test_count_and_is_empty() {
        let store = ArtifactStore::new("empty");
        assert!(store.is_empty());
        store.upsert(make_artifact("x", ArtifactType::File, "f", 0.5));
        assert_eq!(store.count(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn test_avg_confidence() {
        let store = ArtifactStore::new("c");
        store.upsert(make_artifact("a", ArtifactType::File, "f", 0.6));
        store.upsert(make_artifact("b", ArtifactType::File, "g", 0.8));
        let avg = store.avg_confidence();
        assert!((avg - 0.7).abs() < 0.01);
    }

    #[test]
    fn test_export_json() {
        let store = populated_store();
        let json = store.export(&ExportFormat::Json, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn test_export_csv() {
        let store = populated_store();
        let csv = store.export(&ExportFormat::Csv, None).unwrap();
        assert!(csv.starts_with("id,type"));
        // One header + 4 data rows.
        assert_eq!(csv.lines().count(), 5);
    }

    #[test]
    fn test_export_stix() {
        let store = populated_store();
        let stix = store.export(&ExportFormat::Stix, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&stix).unwrap();
        assert_eq!(parsed["type"], "bundle");
    }

    #[test]
    fn test_export_specific_ids() {
        let store = populated_store();
        let json = store.export(&ExportFormat::Json, Some(&["art-1", "art-2"])).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_clear() {
        let store = populated_store();
        assert!(!store.is_empty());
        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn test_artifact_with_data_hashes() {
        let art = ForensicArtifact::with_data(
            "h1",
            ArtifactType::Memory,
            "lsass",
            b"test payload".to_vec(),
        );
        assert!(!art.hashes.is_empty());
        assert!(art.sha256_hex().is_some());
    }

    #[test]
    fn test_artifact_builder_chain() {
        let art = ForensicArtifact::new("b1", ArtifactType::Process, "explorer")
            .with_confidence(0.75)
            .tag("suspicious")
            .technique("T1055");
        assert!((art.confidence - 0.75).abs() < 0.001);
        assert!(art.tags.contains(&"suspicious".to_string()));
        assert!(art.technique_ids.contains(&"T1055".to_string()));
    }

    #[test]
    fn test_capacity_eviction() {
        let store = ArtifactStore::new("small").with_capacity(2);
        store.store(make_artifact("e1", ArtifactType::File, "f1", 0.5)).unwrap();
        store.store(make_artifact("e2", ArtifactType::File, "f2", 0.5)).unwrap();
        // This should evict one of the older entries.
        store.store(make_artifact("e3", ArtifactType::File, "f3", 0.5)).unwrap();
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn test_artifact_type_display() {
        assert_eq!(ArtifactType::Process.to_string(), "process");
        assert_eq!(ArtifactType::Registry.to_string(), "registry");
        assert_eq!(ArtifactType::Other("custom".into()).to_string(), "custom");
    }
}
