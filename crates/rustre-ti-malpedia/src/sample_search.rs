//! Sample search and related-sample analysis for the Malpedia database.
//!
//! Provides hash-based lookup, cluster analysis, and sample metadata queries
//! against the in-memory / `SQLite` Malpedia cache.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::models::{MalpediaFamily, MalpediaSample};

// ---------------------------------------------------------------------------
// SampleMatch
// ---------------------------------------------------------------------------

/// The result of a sample hash lookup across the Malpedia database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleMatch {
    /// The queried SHA-256 hash.
    pub query_hash: String,
    /// The family this sample belongs to.
    pub family_name: String,
    /// The full sample record.
    pub sample: MalpediaSample,
    /// Confidence in [0, 100] that this match is correct.
    pub confidence: u8,
    /// Whether the match is exact (hash equality) or fuzzy (ssdeep similarity).
    pub is_exact: bool,
}

impl SampleMatch {
    /// Create an exact hash match.
    #[must_use]
    pub const fn exact(query_hash: String, family_name: String, sample: MalpediaSample) -> Self {
        Self {
            query_hash,
            family_name,
            sample,
            confidence: 100,
            is_exact: true,
        }
    }

    /// Create a fuzzy match with explicit confidence.
    #[must_use]
    pub const fn fuzzy(
        query_hash: String,
        family_name: String,
        sample: MalpediaSample,
        confidence: u8,
    ) -> Self {
        Self {
            query_hash,
            family_name,
            sample,
            confidence,
            is_exact: false,
        }
    }
}

impl fmt::Display for SampleMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} [{}, confidence={}{}]",
            self.query_hash,
            self.family_name,
            self.sample.status,
            self.confidence,
            if self.is_exact { ", exact" } else { ", fuzzy" },
        )
    }
}

// ---------------------------------------------------------------------------
// SampleDatabase
// ---------------------------------------------------------------------------

/// In-memory sample index for fast hash lookups.
#[derive(Debug, Default)]
pub struct SampleDatabase {
    /// sha256 (lower-case) → (`family_name`, sample)
    exact_index: HashMap<String, (String, MalpediaSample)>,
    /// `family_name` → list of sample sha256 hashes
    family_index: HashMap<String, Vec<String>>,
}

impl SampleDatabase {
    /// Create an empty sample database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Index all samples from a `MalpediaFamily`.
    pub fn index_family(&mut self, family: &MalpediaFamily) {
        for sample in &family.samples {
            let key = sample.sha256.to_lowercase();
            self.exact_index
                .insert(key.clone(), (family.malpedia_name.clone(), sample.clone()));
            self.family_index
                .entry(family.malpedia_name.clone())
                .or_default()
                .push(key);
        }
    }

    /// Look up a sample by exact SHA-256 hash.
    #[must_use]
    pub fn lookup_exact(&self, sha256: &str) -> Option<SampleMatch> {
        let key = sha256.to_lowercase();
        self.exact_index.get(&key).map(|(family_name, sample)| {
            SampleMatch::exact(sha256.to_string(), family_name.clone(), sample.clone())
        })
    }

    /// Return all samples for a given family name.
    #[must_use]
    pub fn samples_for_family(&self, family_name: &str) -> Vec<String> {
        self.family_index
            .get(family_name)
            .cloned()
            .unwrap_or_default()
    }

    /// Total number of indexed samples.
    #[must_use]
    pub fn total_samples(&self) -> usize {
        self.exact_index.len()
    }

    /// Total number of indexed families.
    #[must_use]
    pub fn total_families(&self) -> usize {
        self.family_index.len()
    }

    /// Return all families that have at least one sample.
    #[must_use]
    pub fn non_empty_families(&self) -> Vec<&str> {
        self.family_index
            .iter()
            .filter(|(_, hashes)| !hashes.is_empty())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Search for samples whose hash contains the given substring.
    #[must_use]
    pub fn search_by_hash_prefix(&self, prefix: &str) -> Vec<SampleMatch> {
        let lc = prefix.to_lowercase();
        self.exact_index
            .iter()
            .filter(|(k, _)| k.starts_with(&lc))
            .map(|(k, (family, sample))| {
                SampleMatch::exact(k.clone(), family.clone(), sample.clone())
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ClusterReport
// ---------------------------------------------------------------------------

/// Summary statistics for a cluster of related samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterReport {
    /// Cluster identifier (typically the most common family name).
    pub cluster_id: String,
    /// Families represented in this cluster.
    pub families: Vec<String>,
    /// Total number of samples in the cluster.
    pub sample_count: usize,
    /// Fraction of samples that are "active" (not deprecated).
    pub active_fraction: f64,
    /// Oldest first-seen timestamp in the cluster.
    pub earliest_seen: Option<u64>,
    /// Most recent last-seen timestamp in the cluster.
    pub latest_seen: Option<u64>,
}

impl ClusterReport {
    /// Create a report by aggregating families.
    #[must_use]
    pub fn from_families(cluster_id: String, families: &[MalpediaFamily]) -> Self {
        let family_names: Vec<String> = families.iter().map(|f| f.malpedia_name.clone()).collect();
        let total: usize = families.iter().map(|f| f.samples.len()).sum();
        let active: usize = families
            .iter()
            .flat_map(|f| &f.samples)
            .filter(|s| s.is_active())
            .count();
        let active_fraction = if total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(active).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        };

        Self {
            cluster_id,
            families: family_names,
            sample_count: total,
            active_fraction,
            earliest_seen: None,
            latest_seen: None,
        }
    }

    /// Return `true` if the majority of samples are active.
    #[must_use]
    pub fn is_predominantly_active(&self) -> bool {
        self.active_fraction > 0.5
    }
}

impl fmt::Display for ClusterReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cluster '{}': {} families, {} samples, {:.0}% active",
            self.cluster_id,
            self.families.len(),
            self.sample_count,
            self.active_fraction * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// RelatedSampleSearch
// ---------------------------------------------------------------------------

/// Finds samples related to a query hash through shared family membership.
pub struct RelatedSampleSearch<'a> {
    db: &'a SampleDatabase,
}

impl<'a> RelatedSampleSearch<'a> {
    /// Create a related-sample searcher over `db`.
    #[must_use]
    pub const fn new(db: &'a SampleDatabase) -> Self {
        Self { db }
    }

    /// Find all samples in the same family as the given hash.
    ///
    /// Returns an empty `Vec` if the hash is not in the database.
    #[must_use]
    pub fn related_by_family(&self, sha256: &str) -> Vec<String> {
        match self.db.lookup_exact(sha256) {
            Some(m) => self.db.samples_for_family(&m.family_name),
            None => Vec::new(),
        }
    }

    /// Return the family name for a given hash if it exists.
    #[must_use]
    pub fn family_of(&self, sha256: &str) -> Option<String> {
        self.db.lookup_exact(sha256).map(|m| m.family_name)
    }
}

// ---------------------------------------------------------------------------
// SampleMetadata
// ---------------------------------------------------------------------------

/// Extended metadata about a Malpedia sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleMetadata {
    /// SHA-256 hash.
    pub sha256: String,
    /// Malpedia family name.
    pub family: String,
    /// Version string from Malpedia.
    pub version: String,
    /// Status string (e.g. `active`, `deprecated`).
    pub status: String,
    /// File type hint.
    pub file_type: Option<String>,
    /// Architecture hint (e.g. `x86`, `x64`, `arm`).
    pub architecture: Option<String>,
    /// Compile timestamp (Unix).
    pub compile_time: Option<u64>,
    /// Import hashes (imphash).
    pub imphash: Option<String>,
    /// Packer / protector name, if any.
    pub packer: Option<String>,
    /// Tags for classification.
    pub tags: Vec<String>,
    /// YARA rule names that match this sample.
    pub matched_rules: Vec<String>,
}

impl SampleMetadata {
    /// Construct metadata from a [`MalpediaSample`] and family name.
    #[must_use]
    pub fn from_sample(sample: &MalpediaSample, family: impl Into<String>) -> Self {
        Self {
            sha256: sample.sha256.clone(),
            family: family.into(),
            version: sample.version.clone(),
            status: sample.status.clone(),
            file_type: None,
            architecture: None,
            compile_time: None,
            imphash: None,
            packer: None,
            tags: Vec::new(),
            matched_rules: Vec::new(),
        }
    }

    /// Return `true` if this sample is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.eq_ignore_ascii_case("active")
    }

    /// Return `true` if a packer was detected.
    #[must_use]
    pub const fn is_packed(&self) -> bool {
        self.packer.is_some()
    }
}

impl fmt::Display for SampleMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] v{} ({})",
            self.sha256, self.family, self.version, self.status
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{MalpediaFamily, MalpediaSample};

    fn make_sample(sha: &str) -> MalpediaSample {
        MalpediaSample::new(sha, "active", "1.0")
    }

    fn make_family(name: &str, hashes: &[&str]) -> MalpediaFamily {
        let mut f = MalpediaFamily::new(name, name);
        for h in hashes {
            f.samples.push(make_sample(h));
        }
        f
    }

    #[test]
    fn test_sample_database_lookup_exact() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.emotet", &["DEADBEEF", "CAFEBABE"]));
        let m = db.lookup_exact("deadbeef").unwrap();
        assert_eq!(m.family_name, "win.emotet");
        assert!(m.is_exact);
        assert_eq!(m.confidence, 100);
    }

    #[test]
    fn test_sample_database_lookup_missing() {
        let db = SampleDatabase::new();
        assert!(db.lookup_exact("nothere").is_none());
    }

    #[test]
    fn test_sample_database_case_insensitive() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.emotet", &["AbCdEf"]));
        assert!(db.lookup_exact("ABCDEF").is_some());
        assert!(db.lookup_exact("abcdef").is_some());
    }

    #[test]
    fn test_sample_database_total_samples() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.a", &["hash1", "hash2"]));
        db.index_family(&make_family("win.b", &["hash3"]));
        assert_eq!(db.total_samples(), 3);
    }

    #[test]
    fn test_sample_database_total_families() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.a", &["hash1"]));
        db.index_family(&make_family("win.b", &["hash2"]));
        assert_eq!(db.total_families(), 2);
    }

    #[test]
    fn test_samples_for_family() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.emotet", &["aaa", "bbb"]));
        let hashes = db.samples_for_family("win.emotet");
        assert_eq!(hashes.len(), 2);
    }

    #[test]
    fn test_samples_for_unknown_family() {
        let db = SampleDatabase::new();
        assert!(db.samples_for_family("win.unknown").is_empty());
    }

    #[test]
    fn test_non_empty_families() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.a", &["h1"]));
        let ne = db.non_empty_families();
        assert!(ne.contains(&"win.a"));
    }

    #[test]
    fn test_search_by_hash_prefix() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family(
            "win.x",
            &["abcdef1234", "abcdef5678", "deadbeef"],
        ));
        let results = db.search_by_hash_prefix("abcdef");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_by_hash_prefix_empty() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.x", &["abc123"]));
        let results = db.search_by_hash_prefix("xyz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_related_sample_search_by_family() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.emotet", &["aaa", "bbb", "ccc"]));
        let search = RelatedSampleSearch::new(&db);
        let related = search.related_by_family("aaa");
        assert_eq!(related.len(), 3);
    }

    #[test]
    fn test_related_sample_search_missing_hash() {
        let db = SampleDatabase::new();
        let search = RelatedSampleSearch::new(&db);
        assert!(search.related_by_family("nothere").is_empty());
    }

    #[test]
    fn test_related_sample_family_of() {
        let mut db = SampleDatabase::new();
        db.index_family(&make_family("win.emotet", &["hash1"]));
        let search = RelatedSampleSearch::new(&db);
        assert_eq!(search.family_of("hash1").as_deref(), Some("win.emotet"));
        assert!(search.family_of("unknown").is_none());
    }

    #[test]
    fn test_sample_match_display() {
        let sample = make_sample("deadbeef");
        let m = SampleMatch::exact("deadbeef".to_string(), "win.emotet".to_string(), sample);
        let s = m.to_string();
        assert!(s.contains("deadbeef"));
        assert!(s.contains("win.emotet"));
        assert!(s.contains("exact"));
    }

    #[test]
    fn test_sample_match_fuzzy() {
        let sample = make_sample("abc");
        let m = SampleMatch::fuzzy("abc".to_string(), "win.test".to_string(), sample, 75);
        assert!(!m.is_exact);
        assert_eq!(m.confidence, 75);
    }

    #[test]
    fn test_cluster_report_from_families() {
        let fam = make_family("win.emotet", &["h1", "h2", "h3"]);
        let report = ClusterReport::from_families("emotet_cluster".to_string(), &[fam]);
        assert_eq!(report.sample_count, 3);
        assert!(report.active_fraction > 0.9);
        assert!(report.is_predominantly_active());
    }

    #[test]
    fn test_cluster_report_display() {
        let fam = make_family("win.x", &["h1"]);
        let r = ClusterReport::from_families("cluster1".to_string(), &[fam]);
        let s = r.to_string();
        assert!(s.contains("cluster1"));
    }

    #[test]
    fn test_cluster_report_empty() {
        let r = ClusterReport::from_families("empty".to_string(), &[]);
        assert_eq!(r.sample_count, 0);
        assert!((r.active_fraction).abs() < f64::EPSILON);
        assert!(!r.is_predominantly_active());
    }

    #[test]
    fn test_sample_metadata_from_sample() {
        let s = make_sample("deadbeef");
        let m = SampleMetadata::from_sample(&s, "win.test");
        assert_eq!(m.sha256, "deadbeef");
        assert_eq!(m.family, "win.test");
        assert!(m.is_active());
        assert!(!m.is_packed());
    }

    #[test]
    fn test_sample_metadata_packer() {
        let s = make_sample("abc");
        let mut m = SampleMetadata::from_sample(&s, "win.test");
        m.packer = Some("UPX".to_string());
        assert!(m.is_packed());
    }

    #[test]
    fn test_sample_metadata_display() {
        let s = make_sample("deadbeef");
        let m = SampleMetadata::from_sample(&s, "win.test");
        let out = m.to_string();
        assert!(out.contains("deadbeef"));
        assert!(out.contains("win.test"));
    }

    #[test]
    fn test_sample_metadata_serialization() {
        let s = make_sample("aabbccdd");
        let m = SampleMetadata::from_sample(&s, "win.a");
        let json = serde_json::to_string(&m).unwrap();
        let decoded: SampleMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sha256, "aabbccdd");
    }

    #[test]
    fn test_sample_match_serialization() {
        let s = make_sample("abc");
        let m = SampleMatch::exact("abc".to_string(), "win.a".to_string(), s);
        let json = serde_json::to_string(&m).unwrap();
        let decoded: SampleMatch = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_exact);
        assert_eq!(decoded.confidence, 100);
    }
}
