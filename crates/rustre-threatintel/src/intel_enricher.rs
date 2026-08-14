//! Threat intelligence enrichment engine.
//!
//! Combines data from multiple intelligence sources (STIX, MISP, `VirusTotal`,
//! `AbuseIPDB`, etc.) to produce `EnrichedIoc` records with consolidated threat
//! context, confidence, and provenance information.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// ThreatContext
// ---------------------------------------------------------------------------

/// Threat context collected from a single enrichment source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    /// Name of the enrichment source (e.g. `"virustotal"`, `"misp"`, `"stix"`).
    pub source: String,
    /// Human-readable label of the threat (e.g. malware family, campaign).
    pub label: String,
    /// Confidence that this context is accurate, 0.0–1.0.
    pub confidence: f32,
    /// MITRE ATT&CK technique IDs related to this context.
    pub mitre_ids: Vec<String>,
    /// Threat actor names attributed to this `IoC`.
    pub actors: Vec<String>,
    /// Malware family names.
    pub malware_families: Vec<String>,
    /// Additional key/value metadata.
    pub metadata: HashMap<String, String>,
}

impl ThreatContext {
    /// Create a new context from the minimum required fields.
    #[must_use]
    pub fn new(source: impl Into<String>, label: impl Into<String>, confidence: f32) -> Self {
        Self {
            source: source.into(),
            label: label.into(),
            confidence: confidence.clamp(0.0, 1.0),
            mitre_ids: Vec::new(),
            actors: Vec::new(),
            malware_families: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Builder: add a MITRE ATT&CK technique ID.
    #[must_use]
    pub fn with_mitre_id(mut self, id: impl Into<String>) -> Self {
        self.mitre_ids.push(id.into());
        self
    }

    /// Builder: add a threat actor name.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actors.push(actor.into());
        self
    }

    /// Builder: add a malware family name.
    #[must_use]
    pub fn with_malware_family(mut self, family: impl Into<String>) -> Self {
        self.malware_families.push(family.into());
        self
    }

    /// Insert a metadata key/value pair.
    pub fn insert_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

// ---------------------------------------------------------------------------
// EnrichedIoc
// ---------------------------------------------------------------------------

/// An `IoC` enriched with consolidated threat context from one or more sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedIoc {
    /// The raw `IoC` value (hash, IP, domain, URL, etc.).
    pub value: String,
    /// Broad category of the `IoC`.
    pub ioc_type: String,
    /// All context records gathered for this `IoC`.
    pub contexts: Vec<ThreatContext>,
    /// Consolidated confidence score (weighted average of contexts).
    pub consolidated_confidence: f32,
    /// Deduplicated list of all labels across all contexts.
    pub labels: Vec<String>,
    /// Deduplicated list of all MITRE technique IDs.
    pub mitre_ids: Vec<String>,
    /// Deduplicated list of all attributed actors.
    pub actors: Vec<String>,
    /// Deduplicated list of all malware families.
    pub malware_families: Vec<String>,
    /// Verdict: is this `IoC` considered malicious?
    pub is_malicious: bool,
}

impl EnrichedIoc {
    /// Create an empty `EnrichedIoc` for `value`.
    #[must_use]
    pub fn new(value: impl Into<String>, ioc_type: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            ioc_type: ioc_type.into(),
            contexts: Vec::new(),
            consolidated_confidence: 0.0,
            labels: Vec::new(),
            mitre_ids: Vec::new(),
            actors: Vec::new(),
            malware_families: Vec::new(),
            is_malicious: false,
        }
    }

    /// Add a context and recompute consolidated fields.
    pub fn add_context(&mut self, ctx: ThreatContext) {
        self.contexts.push(ctx);
        self.recompute();
    }

    /// Recompute derived fields from the current set of contexts.
    fn recompute(&mut self) {
        // Weighted average confidence (weight = 1.0 per source for now).
        if self.contexts.is_empty() {
            self.consolidated_confidence = 0.0;
        } else {
            let sum: f32 = self.contexts.iter().map(|c| c.confidence).sum();
            let mean = sum / crate::casts::usize_to_f32(self.contexts.len());
            // `EnrichmentContext::confidence` is a public unvalidated field, so
            // the divisor being non-zero is not enough — one non-finite context
            // poisons the mean, and a NaN consolidated score then fails every
            // downstream threshold comparison and silently drops the record.
            self.consolidated_confidence = if mean.is_finite() { mean } else { 0.0 };
        }

        // Deduplicate labels.
        let mut labels: Vec<String> = self
            .contexts
            .iter()
            .map(|c| c.label.clone())
            .filter(|l| !l.is_empty())
            .collect();
        labels.sort();
        labels.dedup();
        self.labels = labels;

        // Deduplicate MITRE IDs.
        let mut mitre: Vec<String> = self
            .contexts
            .iter()
            .flat_map(|c| c.mitre_ids.iter().cloned())
            .collect();
        mitre.sort();
        mitre.dedup();
        self.mitre_ids = mitre;

        // Deduplicate actors.
        let mut actors: Vec<String> = self
            .contexts
            .iter()
            .flat_map(|c| c.actors.iter().cloned())
            .collect();
        actors.sort();
        actors.dedup();
        self.actors = actors;

        // Deduplicate malware families.
        let mut families: Vec<String> = self
            .contexts
            .iter()
            .flat_map(|c| c.malware_families.iter().cloned())
            .collect();
        families.sort();
        families.dedup();
        self.malware_families = families;

        // Mark as malicious if any source has confidence >= 0.5.
        self.is_malicious = self
            .contexts
            .iter()
            .any(|c| c.confidence >= 0.5 && !c.label.is_empty());
    }

    /// Number of enrichment sources that provided context.
    #[must_use]
    pub const fn source_count(&self) -> usize {
        self.contexts.len()
    }
}

// ---------------------------------------------------------------------------
// EnrichmentResult
// ---------------------------------------------------------------------------

/// Result of an enrichment run for a batch of `IoCs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// Enriched `IoC` records.
    pub enriched: Vec<EnrichedIoc>,
    /// How many `IoCs` were processed.
    pub total_processed: usize,
    /// How many `IoCs` could not be enriched (no context found).
    pub no_context_count: usize,
    /// Per-source counts of how many `IoCs` each source had data for.
    pub source_hit_counts: HashMap<String, usize>,
}

impl EnrichmentResult {
    fn new() -> Self {
        Self {
            enriched: Vec::new(),
            total_processed: 0,
            no_context_count: 0,
            source_hit_counts: HashMap::new(),
        }
    }

    /// Fraction of `IoCs` that had at least one context record, 0.0–1.0.
    #[must_use]
    pub fn coverage(&self) -> f32 {
        if self.total_processed == 0 {
            0.0
        } else {
            crate::casts::usize_to_f32(self.total_processed - self.no_context_count) / crate::casts::usize_to_f32(self.total_processed)
        }
    }

    /// All enriched `IoCs` deemed malicious.
    #[must_use]
    pub fn malicious(&self) -> Vec<&EnrichedIoc> {
        self.enriched.iter().filter(|e| e.is_malicious).collect()
    }
}

// ---------------------------------------------------------------------------
// EnrichmentSource trait
// ---------------------------------------------------------------------------

/// Trait implemented by each intelligence source that can enrich an `IoC`.
pub trait EnrichmentSource: Send + Sync {
    /// The unique name of this source.
    fn name(&self) -> &str;

    /// Attempt to enrich `value` (`IoC` string) of `ioc_type`.
    ///
    /// Returns a `ThreatContext` if the source has data, or `None`.
    fn enrich(&self, value: &str, ioc_type: &str) -> Option<ThreatContext>;
}

// ---------------------------------------------------------------------------
// Built-in sources
// ---------------------------------------------------------------------------

/// A static threat-intel feed loaded from an in-memory lookup table.
///
/// Useful for testing or embedding small, curated indicator lists.
#[derive(Debug)]
pub struct StaticFeedSource {
    /// Name of this source.
    name: String,
    /// Map from indicator value to pre-built `ThreatContext`.
    entries: HashMap<String, ThreatContext>,
}

impl StaticFeedSource {
    /// Create a new empty static source with the given `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: HashMap::new(),
        }
    }

    /// Insert a `(value, context)` pair.
    pub fn insert(&mut self, value: impl Into<String>, context: ThreatContext) {
        self.entries.insert(value.into(), context);
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl EnrichmentSource for StaticFeedSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn enrich(&self, value: &str, _ioc_type: &str) -> Option<ThreatContext> {
        self.entries.get(value).cloned()
    }
}

// ---------------------------------------------------------------------------
// RegexPatternSource — enriches based on value pattern matching
// ---------------------------------------------------------------------------

/// An enrichment source that matches values against a set of regex patterns
/// and returns a fixed context when a pattern matches.
#[derive(Debug)]
pub struct RegexPatternSource {
    name: String,
    patterns: Vec<(String, ThreatContext)>,
}

impl RegexPatternSource {
    /// Create with the given `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            patterns: Vec::new(),
        }
    }

    /// Add a `(regex_pattern, context)` pair.
    ///
    /// The regex syntax is a simple glob-like subset: only `*` wildcards are
    /// supported (no full regex engine dependency).  A `*` in the pattern
    /// matches any sequence of characters in the value.
    pub fn add_pattern(&mut self, pattern: impl Into<String>, context: ThreatContext) {
        self.patterns.push((pattern.into(), context));
    }

    fn glob_match(pattern: &str, value: &str) -> bool {
        // Simple recursive glob match: '*' = zero or more chars.
        let pb = pattern.as_bytes();
        let vb = value.as_bytes();
        Self::glob_match_bytes(pb, vb)
    }

    fn glob_match_bytes(p: &[u8], v: &[u8]) -> bool {
        if p.is_empty() {
            return v.is_empty();
        }
        if p[0] == b'*' {
            // Try consuming zero or more characters of v.
            for skip in 0..=v.len() {
                if Self::glob_match_bytes(&p[1..], &v[skip..]) {
                    return true;
                }
            }
            return false;
        }
        if v.is_empty() {
            return false;
        }
        if p[0] == b'?' || p[0] == v[0] {
            return Self::glob_match_bytes(&p[1..], &v[1..]);
        }
        false
    }
}

impl EnrichmentSource for RegexPatternSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn enrich(&self, value: &str, _ioc_type: &str) -> Option<ThreatContext> {
        for (pattern, ctx) in &self.patterns {
            if Self::glob_match(pattern, value) {
                return Some(ctx.clone());
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// CidrSource — enriches IP addresses by CIDR range membership
// ---------------------------------------------------------------------------

/// Enriches IP-address `IoCs` by checking membership in known CIDR blocks.
///
/// Only IPv4 is supported in this implementation.
#[derive(Debug)]
pub struct CidrSource {
    name: String,
    /// List of (`network_u32`, `mask_u32`, context).
    ranges: Vec<(u32, u32, ThreatContext)>,
}

impl CidrSource {
    /// Create a new empty `CidrSource`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ranges: Vec::new(),
        }
    }

    /// Add a CIDR range `"A.B.C.D/prefix"` with the associated context.
    ///
    /// Returns `true` if the CIDR was parsed successfully.
    pub fn add_cidr(&mut self, cidr: &str, context: ThreatContext) -> bool {
        let Some((addr_str, prefix_str)) = cidr.split_once('/') else {
            return false;
        };
        let prefix: u32 = match prefix_str.parse() {
            Ok(p) if p <= 32 => p,
            _ => return false,
        };
        let mask: u32 = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let Some(addr_u32) = Self::parse_ipv4(addr_str) else {
            return false;
        };
        self.ranges.push((addr_u32 & mask, mask, context));
        true
    }

    fn parse_ipv4(s: &str) -> Option<u32> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut v = 0u32;
        for part in &parts {
            let b: u8 = part.parse().ok()?;
            v = (v << 8) | u32::from(b);
        }
        Some(v)
    }
}

impl EnrichmentSource for CidrSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn enrich(&self, value: &str, ioc_type: &str) -> Option<ThreatContext> {
        if ioc_type != "ip" && ioc_type != "ip-dst" && ioc_type != "ip-src" {
            return None;
        }
        // Strip port if present (e.g. "1.2.3.4:80").
        let ip_str = value.split(':').next().unwrap_or(value);
        let addr = Self::parse_ipv4(ip_str)?;
        for (network, mask, ctx) in &self.ranges {
            if addr & mask == *network {
                return Some(ctx.clone());
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// IntelEnricher
// ---------------------------------------------------------------------------

/// The central enrichment engine.
///
/// Sources are registered once and then queried in registration order for
/// every `IoC` submitted for enrichment.  The results are merged into
/// `EnrichedIoc` records.
#[derive(Default)]
pub struct IntelEnricher {
    sources: Vec<Box<dyn EnrichmentSource>>,
    /// Threshold below which an enriched `IoC` is considered unknown.
    min_confidence: f32,
}

impl IntelEnricher {
    /// Create a new enricher with default confidence threshold of 0.3.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            min_confidence: 0.3,
        }
    }

    /// Set the minimum confidence threshold.
    pub const fn set_min_confidence(&mut self, threshold: f32) {
        self.min_confidence = threshold.clamp(0.0, 1.0);
    }

    /// Register an enrichment source.
    pub fn add_source(&mut self, source: Box<dyn EnrichmentSource>) {
        self.sources.push(source);
    }

    /// Number of registered sources.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Enrich a single `IoC` value and type.
    #[must_use]
    pub fn enrich_one(&self, value: &str, ioc_type: &str) -> EnrichedIoc {
        let mut enriched = EnrichedIoc::new(value, ioc_type);
        for source in &self.sources {
            if let Some(ctx) = source.enrich(value, ioc_type) {
                enriched.add_context(ctx);
            }
        }
        enriched
    }

    /// Enrich a batch of `(value, ioc_type)` pairs.
    ///
    /// Returns an [`EnrichmentResult`] with all enriched records.
    #[must_use]
    pub fn enrich_batch(&self, iocs: &[(&str, &str)]) -> EnrichmentResult {
        let mut result = EnrichmentResult::new();
        result.total_processed = iocs.len();

        for &(value, ioc_type) in iocs {
            let enriched = self.enrich_one(value, ioc_type);
            // Track per-source hits.
            for ctx in &enriched.contexts {
                *result
                    .source_hit_counts
                    .entry(ctx.source.clone())
                    .or_insert(0) += 1;
            }
            if enriched.contexts.is_empty()
                || enriched.consolidated_confidence < self.min_confidence
            {
                result.no_context_count += 1;
            }
            result.enriched.push(enriched);
        }

        result
    }

    /// Enrich a list of `(value, ioc_type)` pairs using all sources and
    /// return only those with `consolidated_confidence >= min_confidence`.
    #[must_use]
    pub fn enrich_filtered(&self, iocs: &[(&str, &str)]) -> Vec<EnrichedIoc> {
        let result = self.enrich_batch(iocs);
        result
            .enriched
            .into_iter()
            .filter(|e| e.consolidated_confidence >= self.min_confidence)
            .collect()
    }

    /// Build a merged map of `value → Vec<ThreatContext>` for quick lookup.
    #[must_use]
    pub fn build_context_map(&self, iocs: &[(&str, &str)]) -> HashMap<String, Vec<ThreatContext>> {
        let mut map: HashMap<String, Vec<ThreatContext>> = HashMap::new();
        for &(value, ioc_type) in iocs {
            let enriched = self.enrich_one(value, ioc_type);
            map.entry(value.to_string())
                .or_default()
                .extend(enriched.contexts);
        }
        map
    }
}

impl std::fmt::Debug for IntelEnricher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntelEnricher")
            .field("source_count", &self.sources.len())
            .field("min_confidence", &self.min_confidence)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ConfidenceMerger — utility for combining multiple confidence signals
// ---------------------------------------------------------------------------

/// Merges confidence values from multiple sources using configurable strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeStrategy {
    /// Arithmetic mean of all source confidences.
    Average,
    /// Take the maximum confidence among all sources.
    Maximum,
    /// Take the minimum confidence among all sources.
    Minimum,
    /// Weighted average: sources earlier in the list have higher weight.
    WeightedFirst,
}

impl MergeStrategy {
    /// Apply the merge strategy to a slice of confidence values.
    #[must_use]
    pub fn merge(&self, values: &[f32]) -> f32 {
        if values.is_empty() {
            return 0.0;
        }
        let merged = match self {
            Self::Average => {
                let sum: f32 = values.iter().copied().sum();
                sum / crate::casts::usize_to_f32(values.len())
            }
            Self::Maximum => values.iter().copied().fold(f32::NEG_INFINITY, f32::max),
            Self::Minimum => values.iter().copied().fold(f32::INFINITY, f32::min),
            Self::WeightedFirst => {
                // Exponentially decaying weight (factor 0.5) so the first
                // source dominates the merged score even with many later ones.
                let mut weighted_sum = 0.0f32;
                let mut weight_total = 0.0f32;
                let mut w = 1.0f32;
                for &v in values {
                    weighted_sum = v.mul_add(w, weighted_sum);
                    weight_total += w;
                    w *= 0.5;
                }
                if weight_total > 0.0 {
                    weighted_sum / weight_total
                } else {
                    0.0
                }
            }
        };
        // `values` is caller-supplied, so every branch above can hand back a
        // non-finite result even though the emptiness check guards the divisor:
        // a NaN element poisons `Average` and `WeightedFirst`, while `Maximum`
        // and `Minimum` fold with `f32::max`/`f32::min`, which skip NaN and
        // therefore return the ±infinity they started from when every element
        // is NaN. Bounding the result is what makes all four branches total.
        if merged.is_finite() { merged } else { 0.0 }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_static_source() -> StaticFeedSource {
        let mut src = StaticFeedSource::new("test-static");
        src.insert(
            "1.2.3.4",
            ThreatContext::new("test-static", "KnownBad", 0.9)
                .with_actor("APT99")
                .with_malware_family("EvilLoader"),
        );
        src.insert(
            "deadbeef",
            ThreatContext::new("test-static", "Ransomware", 0.85)
                .with_mitre_id("T1486"),
        );
        src
    }

    #[test]
    fn enrich_single_ip() {
        let mut enricher = IntelEnricher::new();
        enricher.add_source(Box::new(make_static_source()));
        let result = enricher.enrich_one("1.2.3.4", "ip");
        assert!(result.is_malicious);
        assert!(result.actors.contains(&"APT99".to_string()));
        assert!(result.malware_families.contains(&"EvilLoader".to_string()));
    }

    #[test]
    fn enrich_unknown_ioc() {
        let mut enricher = IntelEnricher::new();
        enricher.add_source(Box::new(make_static_source()));
        let result = enricher.enrich_one("9.9.9.9", "ip");
        assert!(!result.is_malicious);
        assert_eq!(result.source_count(), 0);
    }

    #[test]
    fn enrich_batch_coverage() {
        let mut enricher = IntelEnricher::new();
        enricher.add_source(Box::new(make_static_source()));
        let iocs = vec![("1.2.3.4", "ip"), ("9.9.9.9", "ip")];
        let result = enricher.enrich_batch(&iocs);
        assert_eq!(result.total_processed, 2);
        assert!((result.coverage() - 0.5).abs() < 0.01);
    }

    #[test]
    fn merge_strategy_average() {
        let s = MergeStrategy::Average;
        let v = vec![0.4, 0.6, 0.8];
        assert!((s.merge(&v) - (0.4 + 0.6 + 0.8) / 3.0).abs() < 1e-6);
    }

    #[test]
    fn merge_strategy_maximum() {
        let s = MergeStrategy::Maximum;
        assert!((s.merge(&[0.2, 0.9, 0.5]) - 0.9).abs() < 1e-6);
    }

    #[test]
    fn merge_strategy_minimum() {
        let s = MergeStrategy::Minimum;
        assert!((s.merge(&[0.2, 0.9, 0.5]) - 0.2).abs() < 1e-6);
    }

    #[test]
    fn merge_strategy_weighted_first() {
        let s = MergeStrategy::WeightedFirst;
        // First value (weight 3) > second (weight 2) > third (weight 1).
        let merged = s.merge(&[1.0, 0.0, 0.0]);
        assert!(merged > 0.5, "first-source bias expected, got {merged}");
    }

    #[test]
    fn context_builder() {
        let ctx = ThreatContext::new("src", "Ransomware", 0.75)
            .with_mitre_id("T1486")
            .with_actor("FIN7")
            .with_malware_family("LockBit");
        assert_eq!(ctx.mitre_ids, ["T1486"]);
        assert_eq!(ctx.actors, ["FIN7"]);
        assert_eq!(ctx.malware_families, ["LockBit"]);
    }

    #[test]
    fn enriched_ioc_recompute() {
        let mut e = EnrichedIoc::new("bad.com", "domain");
        e.add_context(ThreatContext::new("s1", "PhishingKit", 0.6));
        e.add_context(ThreatContext::new("s2", "C2", 0.8));
        assert!((e.consolidated_confidence - 0.7).abs() < 1e-5);
        assert!(e.is_malicious);
        assert_eq!(e.source_count(), 2);
    }

    #[test]
    fn cidr_source_match() {
        let mut src = CidrSource::new("cidr-test");
        src.add_cidr(
            "10.0.0.0/8",
            ThreatContext::new("cidr-test", "InternalRange", 0.7),
        );
        let ctx = src.enrich("10.1.2.3", "ip");
        assert!(ctx.is_some());
        assert_eq!(ctx.unwrap().label, "InternalRange");
    }

    #[test]
    fn cidr_source_no_match() {
        let mut src = CidrSource::new("cidr-test");
        src.add_cidr(
            "192.168.0.0/16",
            ThreatContext::new("cidr-test", "Private", 0.5),
        );
        assert!(src.enrich("10.0.0.1", "ip").is_none());
    }

    #[test]
    fn regex_pattern_glob() {
        let mut src = RegexPatternSource::new("glob-test");
        src.add_pattern(
            "*.evil.com",
            ThreatContext::new("glob-test", "MalDomain", 0.9),
        );
        assert!(src.enrich("sub.evil.com", "domain").is_some());
        assert!(src.enrich("good.com", "domain").is_none());
    }

    #[test]
    fn intel_enricher_multi_source() {
        let mut enricher = IntelEnricher::new();
        let mut s1 = StaticFeedSource::new("s1");
        s1.insert("x.com", ThreatContext::new("s1", "ThreatA", 0.6));
        let mut s2 = StaticFeedSource::new("s2");
        s2.insert("x.com", ThreatContext::new("s2", "ThreatB", 0.8));
        enricher.add_source(Box::new(s1));
        enricher.add_source(Box::new(s2));
        let e = enricher.enrich_one("x.com", "domain");
        assert_eq!(e.source_count(), 2);
        // Average of 0.6 and 0.8 = 0.7
        assert!((e.consolidated_confidence - 0.7).abs() < 1e-5);
    }
}
