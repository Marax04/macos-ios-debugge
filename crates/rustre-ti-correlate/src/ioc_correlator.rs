//! Multi-source IoC correlation engine.
//!
//! Provides [`IocCorrelator`] which accepts IoCs from multiple independent
//! threat-intelligence feeds, normalises them, and computes pairwise
//! correlation scores. Results are returned as [`IocMatch`] records, each
//! carrying a [`CorrelationScore`] and the list of sources in which the
//! indicator was observed.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_threatintel::{IoC, IoCType};

// ── CorrelationScore ──────────────────────────────────────────────────────────

/// A numeric correlation score with component breakdown.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CorrelationScore {
    /// Raw score in the range [0.0, 1.0].
    pub score: f32,
    /// Component: structural similarity of the IoC values (0.0–1.0).
    pub structural: f32,
    /// Component: number of sources overlap (0.0–1.0).
    pub source_overlap: f32,
    /// Component: co-occurrence in the same threat report (0.0–1.0).
    pub co_occurrence: f32,
    /// Component: temporal proximity of first-seen timestamps (0.0–1.0).
    pub temporal: f32,
}

impl CorrelationScore {
    /// Compute the final weighted score from the four components.
    #[must_use]
    pub fn compute(structural: f32, source_overlap: f32, co_occurrence: f32, temporal: f32) -> Self {
        let score = 0.35 * structural
            + 0.25 * source_overlap
            + 0.25 * co_occurrence
            + 0.15 * temporal;
        Self {
            score: score.clamp(0.0, 1.0),
            structural,
            source_overlap,
            co_occurrence,
            temporal,
        }
    }

    /// Return the score as an integer percentage [0, 100].
    #[must_use]
    pub fn as_percent(self) -> u8 {
        // score is clamped to [0.0, 1.0]; guard against NaN before cast.
        let pct = (self.score * 100.0).round();
        if pct.is_finite() && pct >= 0.0 { pct.min(100.0) as u8 } else { 0 }
    }

    /// Return `true` if the score meets a confidence threshold.
    #[must_use]
    pub fn meets_threshold(self, threshold: f32) -> bool {
        self.score >= threshold
    }
}

impl fmt::Display for CorrelationScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.2} (struct={:.2} src={:.2} co={:.2} time={:.2})",
            self.score, self.structural, self.source_overlap, self.co_occurrence, self.temporal
        )
    }
}

// ── IocMatch ──────────────────────────────────────────────────────────────────

/// A correlation match between two IoCs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    /// First IoC in the pair.
    pub ioc_a: IoC,
    /// Second IoC in the pair.
    pub ioc_b: IoC,
    /// Computed correlation score.
    pub score: CorrelationScore,
    /// Source indices that contributed to IoC A.
    pub sources_a: Vec<usize>,
    /// Source indices that contributed to IoC B.
    pub sources_b: Vec<usize>,
    /// Human-readable reason for this match.
    pub reason: String,
}

impl IocMatch {
    /// Return the set of sources that contain both IoC A and IoC B.
    #[must_use]
    pub fn shared_sources(&self) -> Vec<usize> {
        let set_a: HashSet<usize> = self.sources_a.iter().copied().collect();
        self.sources_b
            .iter()
            .filter(|s| set_a.contains(s))
            .copied()
            .collect()
    }

    /// Return `true` if the match score meets or exceeds `threshold`.
    #[must_use]
    pub fn is_significant(&self, threshold: f32) -> bool {
        self.score.meets_threshold(threshold)
    }
}

impl fmt::Display for IocMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} <-> {} score={}",
            self.ioc_a.ioc_type.as_str(),
            self.ioc_a.value,
            self.ioc_b.value,
            self.score
        )
    }
}

// ── MultiSourceResult ─────────────────────────────────────────────────────────

/// Aggregated result from correlating multiple IoC sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSourceResult {
    /// All significant pairwise matches.
    pub matches: Vec<IocMatch>,
    /// IoCs present in at least `min_sources` sources.
    pub multi_source_iocs: Vec<(IoC, Vec<usize>)>,
    /// Total unique IoC values across all sources.
    pub total_unique: usize,
    /// Number of sources examined.
    pub source_count: usize,
}

impl MultiSourceResult {
    /// Return matches above a given score threshold.
    #[must_use]
    pub fn above_threshold(&self, threshold: f32) -> Vec<&IocMatch> {
        self.matches
            .iter()
            .filter(|m| m.score.meets_threshold(threshold))
            .collect()
    }

    /// Return matches sorted by score descending.
    #[must_use]
    pub fn sorted_by_score(&self) -> Vec<&IocMatch> {
        let mut v: Vec<_> = self.matches.iter().collect();
        v.sort_by(|a, b| b.score.score.partial_cmp(&a.score.score).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    /// Return the top `n` matches by score.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<&IocMatch> {
        self.sorted_by_score().into_iter().take(n).collect()
    }

    /// Return IoCs present in at least `min_sources` sources.
    #[must_use]
    pub fn filter_by_min_sources(&self, min: usize) -> Vec<&IoC> {
        self.multi_source_iocs
            .iter()
            .filter(|(_, srcs)| srcs.len() >= min)
            .map(|(ioc, _)| ioc)
            .collect()
    }
}

// ── IocNormaliser ─────────────────────────────────────────────────────────────

/// Normalise an IoC value for consistent comparison.
fn normalise(ioc_type: &IoCType, value: &str) -> String {
    match ioc_type {
        IoCType::Md5 | IoCType::Sha1 | IoCType::Sha256 | IoCType::Sha512 => {
            value.trim().to_ascii_uppercase()
        }
        IoCType::Domain | IoCType::Url | IoCType::Email => {
            value.trim().to_ascii_lowercase()
        }
        _ => value.trim().to_string(),
    }
}

/// Extract the /24 prefix from a dotted IPv4 string.
fn ip24(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// Compute structural similarity between two IoC values of the same type.
fn structural_similarity(t: &IoCType, a: &str, b: &str) -> f32 {
    if a == b {
        return 1.0;
    }
    match t {
        IoCType::Md5 | IoCType::Sha1 | IoCType::Sha256 | IoCType::Sha512 => {
            // Prefix similarity (normalised shared-prefix length / total length).
            let shared = a
                .chars()
                .zip(b.chars())
                .take_while(|(x, y)| x == y)
                .count();
            let max_len = a.len().max(b.len()).max(1);
            (shared as f32 / max_len as f32).min(0.8) // cap at 0.8 (not identical)
        }
        IoCType::Ip => {
            // Same /24 → 0.7, same /16 → 0.5, else 0.0
            match (ip24(a), ip24(b)) {
                (Some(pa), Some(pb)) if pa == pb => 0.7,
                _ => {
                    let pa: Vec<&str> = a.split('.').collect();
                    let pb: Vec<&str> = b.split('.').collect();
                    if pa.len() >= 2 && pb.len() >= 2 && pa[0] == pb[0] && pa[1] == pb[1] {
                        0.5
                    } else {
                        0.0
                    }
                }
            }
        }
        IoCType::Domain => {
            // Shared parent domain.
            let ends_a = domain_suffix(a);
            let ends_b = domain_suffix(b);
            if !ends_a.is_empty() && ends_a == ends_b {
                0.6
            } else {
                0.0
            }
        }
        _ => 0.0,
    }
}

fn domain_suffix(s: &str) -> String {
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        s.to_string()
    }
}

/// Temporal proximity score (0.0–1.0) based on first_seen difference.
fn temporal_score(a_ts: u64, b_ts: u64) -> f32 {
    if a_ts == 0 || b_ts == 0 {
        return 0.5;
    }
    let diff = a_ts.abs_diff(b_ts);
    const ONE_WEEK: u64 = 7 * 86_400;
    if diff == 0 {
        1.0
    } else if diff <= 3600 {
        0.9
    } else if diff <= 86_400 {
        0.7
    } else if diff <= ONE_WEEK {
        0.4
    } else {
        0.1
    }
}

// ── IocCorrelator ─────────────────────────────────────────────────────────────

/// Correlates IoCs across multiple independent threat-intelligence sources.
pub struct IocCorrelator {
    /// Minimum score to include in results.
    pub threshold: f32,
    /// Sources (each source is a labeled slice of IoCs).
    sources: Vec<(String, Vec<IoC>)>,
}

impl IocCorrelator {
    /// Create a new correlator with default threshold of 0.3.
    #[must_use]
    pub fn new() -> Self {
        Self {
            threshold: 0.30,
            sources: Vec::new(),
        }
    }

    /// Create with a custom score threshold.
    #[must_use]
    pub fn with_threshold(threshold: f32) -> Self {
        Self {
            threshold,
            sources: Vec::new(),
        }
    }

    /// Add a named source of IoCs.
    pub fn add_source(&mut self, name: impl Into<String>, iocs: Vec<IoC>) {
        self.sources.push((name.into(), iocs));
    }

    /// Return the number of sources registered.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Correlate all sources and return a [`MultiSourceResult`].
    ///
    /// Only IoC pairs of the same [`IoCType`] are compared.
    #[must_use]
    pub fn correlate(&self) -> MultiSourceResult {
        // Build index: normalised key → (representative IoC, source indices).
        let mut index: HashMap<(String, String), (IoC, Vec<usize>)> = HashMap::new();
        for (src_idx, (_name, iocs)) in self.sources.iter().enumerate() {
            for ioc in iocs {
                let norm = normalise(&ioc.ioc_type, &ioc.value);
                let key = (ioc.ioc_type.as_str().to_string(), norm.clone());
                let entry = index.entry(key).or_insert_with(|| {
                    let mut rep = ioc.clone();
                    rep.value = norm;
                    (rep, Vec::new())
                });
                if !entry.1.contains(&src_idx) {
                    entry.1.push(src_idx);
                }
            }
        }

        let total_unique = index.len();
        let source_count = self.sources.len();

        // Collect multi-source IoCs.
        let mut multi_source_iocs: Vec<(IoC, Vec<usize>)> = index
            .values()
            .filter(|(_, srcs)| srcs.len() > 1)
            .cloned()
            .collect();
        multi_source_iocs.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        // Compute pairwise matches.
        let all_iocs: Vec<(IoC, Vec<usize>)> = index.into_values().collect();
        let mut matches = Vec::new();

        for i in 0..all_iocs.len() {
            for j in (i + 1)..all_iocs.len() {
                let (ioc_a, srcs_a) = &all_iocs[i];
                let (ioc_b, srcs_b) = &all_iocs[j];

                if ioc_a.ioc_type != ioc_b.ioc_type {
                    continue;
                }
                if ioc_a.value == ioc_b.value {
                    continue;
                }

                let structural = structural_similarity(
                    &ioc_a.ioc_type,
                    &ioc_a.value,
                    &ioc_b.value,
                );
                if structural == 0.0 {
                    continue;
                }

                // Source overlap: Jaccard similarity.
                let set_a: HashSet<usize> = srcs_a.iter().copied().collect();
                let set_b: HashSet<usize> = srcs_b.iter().copied().collect();
                let intersection = set_a.intersection(&set_b).count();
                let union = set_a.union(&set_b).count();
                let source_overlap = if union > 0 {
                    intersection as f32 / union as f32
                } else {
                    0.0
                };

                // Co-occurrence: share at least one source.
                let co_occurrence = if intersection > 0 { 0.8 } else { 0.0 };

                let temporal = temporal_score(ioc_a.first_seen, ioc_b.first_seen);
                let score = CorrelationScore::compute(structural, source_overlap, co_occurrence, temporal);

                if !score.meets_threshold(self.threshold) {
                    continue;
                }

                let reason = format!(
                    "{} structural={:.2} src_overlap={:.2} co={:.2}",
                    ioc_a.ioc_type.as_str(),
                    structural,
                    source_overlap,
                    co_occurrence
                );

                matches.push(IocMatch {
                    ioc_a: ioc_a.clone(),
                    ioc_b: ioc_b.clone(),
                    score,
                    sources_a: srcs_a.clone(),
                    sources_b: srcs_b.clone(),
                    reason,
                });
            }
        }

        // Sort matches by score descending.
        matches.sort_by(|a, b| {
            b.score.score.partial_cmp(&a.score.score).unwrap_or(std::cmp::Ordering::Equal)
        });

        MultiSourceResult {
            matches,
            multi_source_iocs,
            total_unique,
            source_count,
        }
    }

    /// Find all IoCs in any source that match a given value (normalised).
    #[must_use]
    pub fn lookup(&self, ioc_type: &IoCType, value: &str) -> Vec<(usize, &IoC)> {
        let norm = normalise(ioc_type, value);
        let mut results = Vec::new();
        for (src_idx, (_name, iocs)) in self.sources.iter().enumerate() {
            for ioc in iocs {
                if ioc.ioc_type == *ioc_type && normalise(&ioc.ioc_type, &ioc.value) == norm {
                    results.push((src_idx, ioc));
                }
            }
        }
        results
    }

    /// Return the source name for index `i`.
    #[must_use]
    pub fn source_name(&self, i: usize) -> Option<&str> {
        self.sources.get(i).map(|(n, _)| n.as_str())
    }
}

impl Default for IocCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for IocCorrelator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IocCorrelator")
            .field("sources", &self.sources.len())
            .field("threshold", &self.threshold)
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(v: &str) -> IoC {
        IoC::new(IoCType::Ip, v.to_string(), "test".to_string())
    }

    fn sha256(v: &str) -> IoC {
        IoC::new(IoCType::Sha256, v.to_string(), "test".to_string())
    }

    fn domain(v: &str) -> IoC {
        IoC::new(IoCType::Domain, v.to_string(), "test".to_string())
    }

    fn _timed_sha(v: &str, ts: u64) -> IoC {
        let mut i = sha256(v);
        i.first_seen = ts;
        i
    }

    #[test]
    fn test_empty_correlator() {
        let c = IocCorrelator::new();
        let r = c.correlate();
        assert_eq!(r.total_unique, 0);
        assert_eq!(r.source_count, 0);
    }

    #[test]
    fn test_add_source() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![ip("1.2.3.4")]);
        assert_eq!(c.source_count(), 1);
    }

    #[test]
    fn test_multi_source_same_ioc() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![ip("1.2.3.4")]);
        c.add_source("feed2", vec![ip("1.2.3.4")]);
        let r = c.correlate();
        assert!(!r.multi_source_iocs.is_empty());
        assert_eq!(r.multi_source_iocs[0].1.len(), 2);
    }

    #[test]
    fn test_ip_subnet_match() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![ip("10.0.0.1"), ip("10.0.0.2")]);
        let r = c.correlate();
        // Should find structural match due to /24 overlap.
        assert!(!r.matches.is_empty());
    }

    #[test]
    fn test_hash_prefix_match() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![
            sha256("deadbeef0000111122223333"),
            sha256("deadbeef9999888877776666"),
        ]);
        let r = c.correlate();
        assert!(!r.matches.is_empty());
    }

    #[test]
    fn test_domain_parent_match() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![
            domain("c2.evil.example.com"),
            domain("drop.evil.example.com"),
        ]);
        let r = c.correlate();
        assert!(!r.matches.is_empty());
    }

    #[test]
    fn test_no_match_different_types() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![ip("10.0.0.1"), sha256("deadbeef0000111122223333")]);
        let r = c.correlate();
        // Different types should not be compared.
        assert!(r.matches.is_empty());
    }

    #[test]
    fn test_threshold_filters_low_scores() {
        let mut c = IocCorrelator::with_threshold(0.99);
        c.add_source("feed1", vec![ip("10.0.0.1"), ip("10.0.0.2")]);
        let r = c.correlate();
        // Should have no matches above 0.99.
        assert!(r.matches.is_empty());
    }

    #[test]
    fn test_lookup_existing() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![ip("1.2.3.4")]);
        let hits = c.lookup(&IoCType::Ip, "1.2.3.4");
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn test_lookup_missing() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![ip("1.2.3.4")]);
        let hits = c.lookup(&IoCType::Ip, "9.9.9.9");
        assert!(hits.is_empty());
    }

    #[test]
    fn test_source_name() {
        let mut c = IocCorrelator::new();
        c.add_source("AlienVault", vec![]);
        assert_eq!(c.source_name(0), Some("AlienVault"));
        assert_eq!(c.source_name(1), None);
    }

    #[test]
    fn test_result_top_n() {
        let mut c = IocCorrelator::new();
        c.add_source("feed1", vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")]);
        let r = c.correlate();
        let top1 = r.top_n(1);
        assert!(top1.len() <= 1);
    }

    #[test]
    fn test_result_filter_by_min_sources() {
        let mut c = IocCorrelator::new();
        c.add_source("s1", vec![ip("1.2.3.4")]);
        c.add_source("s2", vec![ip("1.2.3.4")]);
        c.add_source("s3", vec![ip("1.2.3.4")]);
        let r = c.correlate();
        let three = r.filter_by_min_sources(3);
        assert!(!three.is_empty());
    }

    #[test]
    fn test_correlation_score_percent() {
        let s = CorrelationScore::compute(0.7, 0.5, 0.6, 0.4);
        assert!(s.as_percent() > 0);
        assert!(s.as_percent() <= 100);
    }

    #[test]
    fn test_correlation_score_threshold() {
        let s = CorrelationScore::compute(0.8, 0.8, 0.8, 0.8);
        assert!(s.meets_threshold(0.5));
        assert!(!s.meets_threshold(1.1));
    }

    #[test]
    fn test_correlation_score_display() {
        let s = CorrelationScore::compute(0.5, 0.5, 0.5, 0.5);
        let txt = s.to_string();
        assert!(txt.contains("struct="));
    }

    #[test]
    fn test_ioc_match_shared_sources() {
        let m = IocMatch {
            ioc_a: ip("1.2.3.4"),
            ioc_b: ip("1.2.3.5"),
            score: CorrelationScore::compute(0.7, 0.5, 0.8, 0.5),
            sources_a: vec![0, 1],
            sources_b: vec![1, 2],
            reason: "test".to_string(),
        };
        let shared = m.shared_sources();
        assert_eq!(shared, vec![1]);
    }

    #[test]
    fn test_temporal_score_same_time() {
        assert!((temporal_score(1000, 1000) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_temporal_score_zero_timestamps() {
        assert!((temporal_score(0, 0) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_structural_similarity_equal() {
        assert!((structural_similarity(&IoCType::Ip, "1.2.3.4", "1.2.3.4") - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_ioc_correlator_debug() {
        let c = IocCorrelator::new();
        let s = format!("{c:?}");
        assert!(s.contains("IocCorrelator"));
    }

    #[test]
    fn test_ioc_match_display() {
        let m = IocMatch {
            ioc_a: ip("10.0.0.1"),
            ioc_b: ip("10.0.0.2"),
            score: CorrelationScore::compute(0.7, 0.5, 0.8, 0.5),
            sources_a: vec![0],
            sources_b: vec![0],
            reason: "subnet match".to_string(),
        };
        let s = m.to_string();
        assert!(s.contains("10.0.0.1"));
    }
}
