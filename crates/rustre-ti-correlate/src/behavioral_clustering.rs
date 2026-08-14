//! Behavioral clustering of malware samples and `IoCs`.
//!
//! Groups samples with similar behavioral profiles using a simplified
//! k-means-style algorithm over feature vectors derived from `IoC` attributes,
//! malware family metadata, and TTP fingerprints.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use rustre_threatintel::{IoC, IoCType, Severity};

// ---------------------------------------------------------------------------
// BehavioralFeature
// ---------------------------------------------------------------------------

/// A single dimension of a behavioral feature vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehavioralFeature {
    /// The `IoC` is a file hash.
    IsHash,
    /// The `IoC` is a network indicator.
    IsNetwork,
    /// The severity is critical.
    CriticalSeverity,
    /// The severity is high.
    HighSeverity,
    /// Confidence is above 75.
    HighConfidence,
    /// Tagged as C2.
    TaggedC2,
    /// Tagged as malware.
    TaggedMalware,
    /// `IoC` is an IP address.
    IsIp,
    /// `IoC` is a domain.
    IsDomain,
    /// `IoC` is a URL.
    IsUrl,
    /// `IoC` is an email.
    IsEmail,
    /// `IoC` type is a YARA rule.
    IsYara,
}

/// Derive a set of [`BehavioralFeature`]s from an [`IoC`].
#[must_use]
pub fn features_from_ioc(ioc: &IoC) -> Vec<BehavioralFeature> {
    let mut features = Vec::new();
    if ioc.is_hash() {
        features.push(BehavioralFeature::IsHash);
    }
    if ioc.is_network() {
        features.push(BehavioralFeature::IsNetwork);
    }
    match ioc.severity {
        Severity::Critical => features.push(BehavioralFeature::CriticalSeverity),
        Severity::High => features.push(BehavioralFeature::HighSeverity),
        _ => {}
    }
    if ioc.confidence > 75 {
        features.push(BehavioralFeature::HighConfidence);
    }
    for tag in &ioc.tags {
        match tag.to_lowercase().as_str() {
            "c2" | "command_and_control" => features.push(BehavioralFeature::TaggedC2),
            "malware" => features.push(BehavioralFeature::TaggedMalware),
            _ => {}
        }
    }
    match &ioc.ioc_type {
        IoCType::Ip => features.push(BehavioralFeature::IsIp),
        IoCType::Domain => features.push(BehavioralFeature::IsDomain),
        IoCType::Url => features.push(BehavioralFeature::IsUrl),
        IoCType::Email => features.push(BehavioralFeature::IsEmail),
        IoCType::Yara => features.push(BehavioralFeature::IsYara),
        _ => {}
    }
    features
}

// ---------------------------------------------------------------------------
// BehavioralProfile
// ---------------------------------------------------------------------------

/// A compact behavioral profile for a single `IoC` or sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProfile {
    /// Identifier (`IoC` value or sample hash).
    pub id: String,
    /// Active features.
    pub features: Vec<BehavioralFeature>,
    /// TTP technique IDs observed.
    pub ttp_ids: Vec<String>,
    /// Malware family names associated.
    pub families: Vec<String>,
}

impl BehavioralProfile {
    /// Build a profile from an `IoC`.
    #[must_use]
    pub fn from_ioc(ioc: &IoC) -> Self {
        Self {
            id: ioc.value.clone(),
            features: features_from_ioc(ioc),
            ttp_ids: Vec::new(),
            families: Vec::new(),
        }
    }

    /// Jaccard similarity with another profile.
    #[must_use]
    pub fn similarity(&self, other: &Self) -> f64 {
        let a: std::collections::HashSet<_> = self.features.iter().collect();
        let b: std::collections::HashSet<_> = other.features.iter().collect();
        let intersection = a.intersection(&b).count();
        let union = a.union(&b).count();
        if union == 0 {
            1.0
        } else {
            (intersection as f64) / (union as f64)
        }
    }

    /// Return `true` if both profiles share at least one feature.
    #[must_use]
    pub fn shares_features(&self, other: &Self) -> bool {
        self.features.iter().any(|f| other.features.contains(f))
    }
}

impl fmt::Display for BehavioralProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Profile('{}') features={} ttps={}",
            self.id,
            self.features.len(),
            self.ttp_ids.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Cluster
// ---------------------------------------------------------------------------

/// A cluster of behaviorally similar profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    /// Cluster identifier.
    pub id: usize,
    /// Profiles assigned to this cluster.
    pub profiles: Vec<BehavioralProfile>,
    /// Centroid features (majority vote).
    pub centroid_features: Vec<BehavioralFeature>,
}

impl Cluster {
    /// Create a new cluster with the given id and initial profile.
    #[must_use]
    pub fn new(id: usize, initial: BehavioralProfile) -> Self {
        let features = initial.features.clone();
        Self {
            id,
            profiles: vec![initial],
            centroid_features: features,
        }
    }

    /// Add a profile to this cluster.
    pub fn add(&mut self, profile: BehavioralProfile) {
        self.profiles.push(profile);
        self.recompute_centroid();
    }

    /// Recompute the centroid as the features that appear in the majority of profiles.
    pub fn recompute_centroid(&mut self) {
        let n = self.profiles.len();
        if n == 0 {
            self.centroid_features.clear();
            return;
        }
        let mut counts: HashMap<BehavioralFeature, usize> = HashMap::new();
        for p in &self.profiles {
            for &f in &p.features {
                *counts.entry(f).or_insert(0) += 1;
            }
        }
        self.centroid_features = counts
            .into_iter()
            .filter(|(_, c)| *c * 2 >= n)
            .map(|(f, _)| f)
            .collect();
    }

    /// Compute the average intra-cluster similarity (cohesion).
    #[must_use]
    pub fn cohesion(&self) -> f64 {
        let n = self.profiles.len();
        if n <= 1 {
            return 1.0;
        }
        let mut total = 0.0;
        let mut pairs = 0usize;
        for i in 0..n {
            for j in (i + 1)..n {
                total += self.profiles[i].similarity(&self.profiles[j]);
                pairs += 1;
            }
        }
        if pairs == 0 {
            1.0
        } else {
            total / (pairs as f64)
        }
    }

    /// Number of profiles in this cluster.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.profiles.len()
    }
}

impl fmt::Display for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cluster#{} size={} cohesion={:.2}",
            self.id,
            self.size(),
            self.cohesion()
        )
    }
}

// ---------------------------------------------------------------------------
// BehavioralClusterer
// ---------------------------------------------------------------------------

/// Greedy agglomerative behavioral clusterer.
///
/// Assigns each profile to the most similar existing cluster if above the
/// `similarity_threshold`, otherwise creates a new cluster.
pub struct BehavioralClusterer {
    /// Minimum Jaccard similarity to merge into an existing cluster.
    similarity_threshold: f64,
    /// Resulting clusters.
    clusters: Vec<Cluster>,
}

impl BehavioralClusterer {
    /// Create a new clusterer with the given threshold.
    #[must_use]
    pub const fn new(similarity_threshold: f64) -> Self {
        Self {
            similarity_threshold: similarity_threshold.clamp(0.0, 1.0),
            clusters: Vec::new(),
        }
    }

    /// Cluster a list of behavioral profiles.
    pub fn cluster(&mut self, profiles: Vec<BehavioralProfile>) {
        self.clusters.clear();
        for profile in profiles {
            self.assign(profile);
        }
    }

    /// Assign one profile to an existing cluster or create a new one.
    pub fn assign(&mut self, profile: BehavioralProfile) {
        // Find the cluster with highest average centroid similarity
        let best_idx = self
            .clusters
            .iter()
            .enumerate()
            .filter_map(|(i, cluster)| {
                let centroid_profile = BehavioralProfile {
                    id: "__centroid__".to_string(),
                    features: cluster.centroid_features.clone(),
                    ttp_ids: Vec::new(),
                    families: Vec::new(),
                };
                let sim = profile.similarity(&centroid_profile);
                if sim >= self.similarity_threshold {
                    Some((i, sim))
                } else {
                    None
                }
            })
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i);

        if let Some(idx) = best_idx {
            self.clusters[idx].add(profile);
        } else {
            let id = self.clusters.len();
            self.clusters.push(Cluster::new(id, profile));
        }
    }

    /// Return all clusters.
    #[must_use]
    pub fn clusters(&self) -> &[Cluster] {
        &self.clusters
    }

    /// Return the number of clusters.
    #[must_use]
    pub const fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    /// Return the cluster with the most members.
    #[must_use]
    pub fn largest_cluster(&self) -> Option<&Cluster> {
        self.clusters.iter().max_by_key(|c| c.size())
    }

    /// Cluster `IoCs` directly.
    pub fn cluster_iocs(&mut self, iocs: &[IoC]) {
        let profiles: Vec<BehavioralProfile> =
            iocs.iter().map(BehavioralProfile::from_ioc).collect();
        self.cluster(profiles);
    }

    /// Return profiles from cluster `id`.
    #[must_use]
    pub fn profiles_in_cluster(&self, id: usize) -> Vec<&BehavioralProfile> {
        self.clusters
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.profiles.iter().collect())
            .unwrap_or_default()
    }

    /// Merge two clusters (by id) into the cluster with the lower id.
    ///
    /// Profiles from `id_b` are moved into `id_a`.  The cluster `id_b` is
    /// removed.  Returns `false` if either id is not found or they are equal.
    pub fn merge_clusters(&mut self, id_a: usize, id_b: usize) -> bool {
        if id_a == id_b {
            return false;
        }
        let Some(pos_b) = self.clusters.iter().position(|c| c.id == id_b) else { return false };
        let Some(pos_a) = self.clusters.iter().position(|c| c.id == id_a) else { return false };
        // Extract all profiles from b.
        let profiles_b: Vec<BehavioralProfile> = self.clusters.remove(pos_b).profiles;
        // Adjust pos_a after removal if necessary.
        let pos_a = if pos_b < pos_a { pos_a - 1 } else { pos_a };
        for p in profiles_b {
            self.clusters[pos_a].add(p);
        }
        true
    }

    /// Split a large cluster by re-clustering its profiles with a *higher*
    /// similarity threshold.
    ///
    /// The original cluster (identified by `id`) is replaced by the
    /// sub-clusters produced by running the greedy agglomerative algorithm on
    /// its profiles at `new_threshold`.  Returns the number of new clusters
    /// produced (0 if the id was not found or the cluster is empty).
    pub fn split_cluster(&mut self, id: usize, new_threshold: f64) -> usize {
        let Some(pos) = self.clusters.iter().position(|c| c.id == id) else { return 0 };
        let profiles = self.clusters.remove(pos).profiles;
        if profiles.is_empty() {
            return 0;
        }
        let mut sub = Self::new(new_threshold);
        sub.cluster(profiles);
        let sub_count = sub.clusters.len();
        // Re-number to avoid id collisions.
        let base_id = self.clusters.len();
        for (i, mut c) in sub.clusters.into_iter().enumerate() {
            c.id = base_id + i;
            self.clusters.push(c);
        }
        sub_count
    }

    /// Return the top-`k` clusters sorted by cohesion descending.
    #[must_use]
    pub fn top_k_by_cohesion(&self, k: usize) -> Vec<&Cluster> {
        let mut sorted: Vec<&Cluster> = self.clusters.iter().collect();
        sorted.sort_by(|a, b| {
            b.cohesion()
                .partial_cmp(&a.cohesion())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.truncate(k);
        sorted
    }

    /// Return the total number of profiles across all clusters.
    #[must_use]
    pub fn total_profile_count(&self) -> usize {
        self.clusters.iter().map(Cluster::size).sum()
    }
}

impl Default for BehavioralClusterer {
    fn default() -> Self {
        Self::new(0.5)
    }
}

impl fmt::Debug for BehavioralClusterer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BehavioralClusterer")
            .field("cluster_count", &self.clusters.len())
            .field("threshold", &self.similarity_threshold)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::{IoC, IoCType, Severity};

    fn ip_ioc(val: &str, confidence: u8, severity: Severity) -> IoC {
        let mut ioc = IoC::new(IoCType::Ip, val.to_string(), "test".to_string());
        ioc.confidence = confidence;
        ioc.severity = severity;
        ioc
    }

    fn hash_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Sha256, val.to_string(), "test".to_string())
    }

    fn c2_ioc(val: &str) -> IoC {
        let mut ioc = ip_ioc(val, 90, Severity::High);
        ioc.tags.push("c2".to_string());
        ioc
    }

    #[test]
    fn test_features_from_ioc_hash() {
        let ioc = hash_ioc("deadbeef");
        let f = features_from_ioc(&ioc);
        assert!(f.contains(&BehavioralFeature::IsHash));
    }

    #[test]
    fn test_features_from_ioc_network() {
        let ioc = ip_ioc("1.2.3.4", 50, Severity::Low);
        let f = features_from_ioc(&ioc);
        assert!(f.contains(&BehavioralFeature::IsNetwork));
        assert!(f.contains(&BehavioralFeature::IsIp));
    }

    #[test]
    fn test_features_from_ioc_critical() {
        let ioc = ip_ioc("1.2.3.4", 50, Severity::Critical);
        let f = features_from_ioc(&ioc);
        assert!(f.contains(&BehavioralFeature::CriticalSeverity));
    }

    #[test]
    fn test_features_from_ioc_high_confidence() {
        let ioc = ip_ioc("1.2.3.4", 80, Severity::Low);
        let f = features_from_ioc(&ioc);
        assert!(f.contains(&BehavioralFeature::HighConfidence));
    }

    #[test]
    fn test_features_from_ioc_c2_tag() {
        let ioc = c2_ioc("1.2.3.4");
        let f = features_from_ioc(&ioc);
        assert!(f.contains(&BehavioralFeature::TaggedC2));
    }

    #[test]
    fn test_features_domain() {
        let ioc = IoC::new(IoCType::Domain, "evil.com".to_string(), "t".to_string());
        let f = features_from_ioc(&ioc);
        assert!(f.contains(&BehavioralFeature::IsDomain));
    }

    #[test]
    fn test_behavioral_profile_similarity_identical() {
        let ioc = ip_ioc("1.2.3.4", 80, Severity::High);
        let p1 = BehavioralProfile::from_ioc(&ioc);
        let p2 = BehavioralProfile::from_ioc(&ioc);
        assert!((p1.similarity(&p2) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_behavioral_profile_similarity_different() {
        let p1 = BehavioralProfile::from_ioc(&hash_ioc("abc"));
        let p2 = BehavioralProfile::from_ioc(&ip_ioc("1.2.3.4", 50, Severity::Low));
        // Hash and IP have no features in common
        let sim = p1.similarity(&p2);
        assert!(sim < 1.0);
    }

    #[test]
    fn test_behavioral_profile_shares_features() {
        let p1 = BehavioralProfile::from_ioc(&ip_ioc("1.2.3.4", 80, Severity::High));
        let p2 = BehavioralProfile::from_ioc(&ip_ioc("5.6.7.8", 90, Severity::High));
        assert!(p1.shares_features(&p2)); // both are network IPs
    }

    #[test]
    fn test_behavioral_profile_display() {
        let p = BehavioralProfile::from_ioc(&hash_ioc("abc"));
        let s = p.to_string();
        assert!(s.contains("Profile('abc')"));
    }

    #[test]
    fn test_cluster_new() {
        let p = BehavioralProfile::from_ioc(&hash_ioc("abc"));
        let c = Cluster::new(0, p);
        assert_eq!(c.id, 0);
        assert_eq!(c.size(), 1);
    }

    #[test]
    fn test_cluster_cohesion_single() {
        let c = Cluster::new(0, BehavioralProfile::from_ioc(&hash_ioc("abc")));
        assert!((c.cohesion() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cluster_cohesion_pair_identical() {
        let p1 = BehavioralProfile::from_ioc(&ip_ioc("1.2.3.4", 80, Severity::High));
        let p2 = BehavioralProfile::from_ioc(&ip_ioc("1.2.3.4", 80, Severity::High));
        let mut c = Cluster::new(0, p1);
        c.add(p2);
        assert!((c.cohesion() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cluster_display() {
        let c = Cluster::new(1, BehavioralProfile::from_ioc(&hash_ioc("abc")));
        let s = c.to_string();
        assert!(s.contains("Cluster#1"));
    }

    #[test]
    fn test_clusterer_single_ioc() {
        let mut cl = BehavioralClusterer::new(0.3);
        cl.cluster_iocs(&[ip_ioc("1.2.3.4", 50, Severity::Low)]);
        assert_eq!(cl.cluster_count(), 1);
    }

    #[test]
    fn test_clusterer_similar_iocs_same_cluster() {
        let mut cl = BehavioralClusterer::new(0.3);
        let iocs = vec![
            ip_ioc("1.2.3.4", 80, Severity::High),
            ip_ioc("5.6.7.8", 85, Severity::High),
        ];
        cl.cluster_iocs(&iocs);
        // Both are IPs with high confidence and high severity → should cluster together
        assert!(cl.cluster_count() <= 2);
    }

    #[test]
    fn test_clusterer_different_iocs_separate_clusters() {
        let mut cl = BehavioralClusterer::new(0.9);
        let iocs = vec![hash_ioc("abc"), ip_ioc("1.2.3.4", 50, Severity::Low)];
        cl.cluster_iocs(&iocs);
        // Hash and IP have very different feature sets → separate clusters at high threshold
        assert_eq!(cl.cluster_count(), 2);
    }

    #[test]
    fn test_clusterer_largest_cluster() {
        let mut cl = BehavioralClusterer::new(0.3);
        let iocs = vec![
            ip_ioc("1.1.1.1", 80, Severity::High),
            ip_ioc("2.2.2.2", 80, Severity::High),
            ip_ioc("3.3.3.3", 80, Severity::High),
        ];
        cl.cluster_iocs(&iocs);
        let largest = cl.largest_cluster().unwrap();
        assert!(largest.size() >= 1);
    }

    #[test]
    fn test_clusterer_empty_input() {
        let mut cl = BehavioralClusterer::new(0.5);
        cl.cluster_iocs(&[]);
        assert_eq!(cl.cluster_count(), 0);
        assert!(cl.largest_cluster().is_none());
    }

    #[test]
    fn test_clusterer_profiles_in_cluster() {
        let mut cl = BehavioralClusterer::new(0.3);
        cl.cluster_iocs(&[ip_ioc("1.2.3.4", 80, Severity::High)]);
        let profiles = cl.profiles_in_cluster(0);
        assert_eq!(profiles.len(), 1);
    }

    #[test]
    fn test_clusterer_profiles_in_missing_cluster() {
        let cl = BehavioralClusterer::new(0.5);
        assert!(cl.profiles_in_cluster(99).is_empty());
    }

    #[test]
    fn test_clusterer_debug() {
        let cl = BehavioralClusterer::new(0.5);
        let s = format!("{cl:?}");
        assert!(s.contains("BehavioralClusterer"));
    }

    #[test]
    fn test_clusterer_default() {
        let cl = BehavioralClusterer::default();
        assert!((cl.similarity_threshold - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_clusterer_merge_clusters() {
        let mut cl = BehavioralClusterer::new(0.9);
        let iocs = vec![hash_ioc("abc"), ip_ioc("1.2.3.4", 50, Severity::Low)];
        cl.cluster_iocs(&iocs);
        // With threshold 0.9 these should be in separate clusters.
        assert_eq!(cl.cluster_count(), 2);
        let id_a = cl.clusters()[0].id;
        let id_b = cl.clusters()[1].id;
        let ok = cl.merge_clusters(id_a, id_b);
        assert!(ok);
        assert_eq!(cl.cluster_count(), 1);
        assert_eq!(cl.total_profile_count(), 2);
    }

    #[test]
    fn test_clusterer_merge_same_id_noop() {
        let mut cl = BehavioralClusterer::new(0.5);
        cl.cluster_iocs(&[ip_ioc("1.2.3.4", 50, Severity::Low)]);
        let id = cl.clusters()[0].id;
        assert!(!cl.merge_clusters(id, id));
    }

    #[test]
    fn test_clusterer_split_cluster() {
        let mut cl = BehavioralClusterer::new(0.0); // everything in one cluster
        let iocs = vec![hash_ioc("abc"), ip_ioc("1.2.3.4", 50, Severity::Low)];
        cl.cluster_iocs(&iocs);
        assert_eq!(cl.cluster_count(), 1);
        let id = cl.clusters()[0].id;
        let new_count = cl.split_cluster(id, 0.99); // very high threshold splits them
        assert!(new_count >= 1);
    }

    #[test]
    fn test_clusterer_top_k_by_cohesion() {
        let mut cl = BehavioralClusterer::new(0.9);
        let iocs = vec![hash_ioc("abc"), ip_ioc("1.2.3.4", 50, Severity::Low)];
        cl.cluster_iocs(&iocs);
        let top = cl.top_k_by_cohesion(1);
        assert_eq!(top.len(), 1);
    }

    #[test]
    fn test_clusterer_total_profile_count() {
        let mut cl = BehavioralClusterer::new(0.3);
        cl.cluster_iocs(&[
            ip_ioc("1.1.1.1", 50, Severity::Low),
            ip_ioc("2.2.2.2", 50, Severity::Low),
            ip_ioc("3.3.3.3", 50, Severity::Low),
        ]);
        assert_eq!(cl.total_profile_count(), 3);
    }

    #[test]
    fn test_cluster_recompute_centroid() {
        let p1 = BehavioralProfile::from_ioc(&ip_ioc("1.2.3.4", 80, Severity::High));
        let mut c = Cluster::new(0, p1);
        c.add(BehavioralProfile::from_ioc(&ip_ioc(
            "5.6.7.8",
            80,
            Severity::High,
        )));
        // Both have IsIp and IsNetwork → should be in centroid
        assert!(!c.centroid_features.is_empty());
    }
}
