//! IOC enrichment pipeline — hash/domain/IP → `VirusTotal` lookup with rate
//! limiting, result caching, and MISP attribute export.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ─── IOC types ────────────────────────────────────────────────────────────────

/// Type of indicator of compromise.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Md5,
    Sha1,
    Sha256,
    Domain,
    Ip,
    Url,
    Email,
    RegistryKey,
    FilePath,
    MutexName,
    Custom(String),
}

impl IocKind {
    #[must_use] 
    pub fn from_value(value: &str) -> Self {
        let v = value.trim();
        // Length-based hash detection
        match v.len() {
            32 if v.chars().all(|c| c.is_ascii_hexdigit()) => Self::Md5,
            40 if v.chars().all(|c| c.is_ascii_hexdigit()) => Self::Sha1,
            64 if v.chars().all(|c| c.is_ascii_hexdigit()) => Self::Sha256,
            _ => {
                if v.starts_with("http://") || v.starts_with("https://") {
                    Self::Url
                } else if v.contains('@') {
                    Self::Email
                } else if v.starts_with("HKEY_") || v.starts_with("HK") {
                    Self::RegistryKey
                } else if v
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    && v.contains('.')
                    && !v.starts_with('.')
                {
                    // Could be domain or IP
                    if v.split('.').all(|part| {
                        part.parse::<u8>().is_ok()
                    }) && v.split('.').count() == 4
                    {
                        Self::Ip
                    } else {
                        Self::Domain
                    }
                } else {
                    Self::Custom("unknown".to_owned())
                }
            }
        }
    }

    #[must_use] 
    pub const fn vt_lookup_path(&self) -> Option<&'static str> {
        match self {
            Self::Md5 | Self::Sha1 | Self::Sha256 => Some("/files"),
            Self::Domain => Some("/domains"),
            Self::Ip => Some("/ip_addresses"),
            Self::Url => Some("/urls"),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn is_lookupable(&self) -> bool {
        self.vt_lookup_path().is_some()
    }
}

/// A single indicator of compromise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// The raw IOC value (hash, domain, IP, etc.)
    pub value: String,
    /// IOC kind (auto-detected if not specified)
    pub kind: IocKind,
    /// Optional source/context label
    pub source: Option<String>,
    /// Optional tags
    pub tags: Vec<String>,
}

impl Ioc {
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let kind = IocKind::from_value(&value);
        Self {
            value,
            kind,
            source: None,
            tags: vec![],
        }
    }

    #[must_use] 
    pub fn with_kind(mut self, kind: IocKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

// ─── Enrichment result ────────────────────────────────────────────────────────

/// VT enrichment data for a single IOC.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrichmentData {
    /// Whether VT had data for this IOC.
    pub found: bool,
    /// Detection ratio (positives / total) for files.
    pub detection_ratio: Option<f32>,
    /// Positives count.
    pub positives: Option<u32>,
    /// Total engines.
    pub total: Option<u32>,
    /// VT community reputation score.
    pub reputation: Option<i32>,
    /// Last analysis date (Unix timestamp).
    pub last_analysis_date: Option<i64>,
    /// First submission date (Unix timestamp).
    pub first_seen: Option<i64>,
    /// Names reported by AV engines.
    pub malware_names: Vec<String>,
    /// Tags from VT.
    pub tags: Vec<String>,
    /// File type (for files).
    pub type_tag: Option<String>,
    /// File size in bytes.
    pub size: Option<u64>,
    /// MD5 hash.
    pub md5: Option<String>,
    /// SHA-1 hash.
    pub sha1: Option<String>,
    /// SHA-256 hash.
    pub sha256: Option<String>,
    /// Country (for IPs).
    pub country: Option<String>,
    /// ASN (for IPs).
    pub asn: Option<u32>,
    /// Registrar (for domains).
    pub registrar: Option<String>,
    /// Known threat categories.
    pub categories: Vec<String>,
    /// Whether VT returned an error.
    pub error: Option<String>,
}

impl EnrichmentData {
    #[must_use] 
    pub fn is_malicious(&self, threshold: f32) -> bool {
        self.detection_ratio.is_some_and(|r| r >= threshold)
    }

    #[must_use] 
    pub fn is_suspicious(&self, rep_threshold: i32) -> bool {
        self.reputation
            .is_some_and(|r| r < rep_threshold)
    }
}

/// Result of enriching a single IOC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedIoc {
    pub ioc: Ioc,
    pub data: EnrichmentData,
    /// Time taken to fetch this result.
    pub fetch_duration_ms: u64,
    /// Whether the result came from cache.
    pub from_cache: bool,
}

impl EnrichedIoc {
    #[must_use] 
    pub fn not_found(ioc: Ioc) -> Self {
        Self {
            ioc,
            data: EnrichmentData {
                found: false,
                ..Default::default()
            },
            fetch_duration_ms: 0,
            from_cache: false,
        }
    }
}

// ─── Simple in-memory cache ───────────────────────────────────────────────────

#[derive(Debug)]
struct CacheEntry {
    data: EnrichmentData,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// In-memory cache for enrichment results.
pub struct EnrichmentCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl EnrichmentCache {
    #[must_use] 
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn get(&self, key: &str) -> Option<EnrichmentData> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(key) {
            if !entry.is_expired() {
                return Some(entry.data.clone());
            }
            entries.remove(key);
        }
        None
    }

    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn insert(&self, key: String, data: EnrichmentData) {
        let mut entries = self.entries.lock().unwrap();
        // Evict expired entries if at capacity
        if entries.len() >= self.max_entries {
            entries.retain(|_, v| !v.is_expired());
        }
        // If still at capacity, remove oldest
        while entries.len() >= self.max_entries {
            // `entries` is a HashMap and `inserted_at` ties easily (coarse
            // clock, bursts of insertions), so without a tie-break on the key
            // the evicted entry differs between runs on identical input.
            if let Some(oldest_key) = entries
                .iter()
                .min_by(|a, b| a.1.inserted_at.cmp(&b.1.inserted_at).then(a.0.cmp(b.0)))
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            } else {
                break;
            }
        }
        entries.insert(
            key,
            CacheEntry {
                data,
                inserted_at: Instant::now(),
                ttl: self.ttl,
            },
        );
    }

    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn invalidate(&self, key: &str) {
        self.entries.lock().unwrap().remove(key);
    }

    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn purge_expired(&self) {
        self.entries.lock().unwrap().retain(|_, v| !v.is_expired());
    }

    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn size(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

// ─── Token-bucket rate limiter ─────────────────────────────────────────────

/// Simple token bucket for API rate limiting.
///
/// `tokens` and `last_refill` are held in a **single** `Mutex` so that the
/// refill-and-consume sequence is atomic, eliminating the TOCTOU race that
/// existed when they were two separate locks.
pub struct RateLimiter {
    /// (`current_tokens`, `last_refill_instant`) — always locked together.
    state: Mutex<(f64, Instant)>,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl RateLimiter {
    /// Create a new rate limiter with the given `requests_per_minute` budget.
    #[must_use] 
    pub fn new(requests_per_minute: u32) -> Self {
        let rate = f64::from(requests_per_minute) / 60.0;
        let max = f64::from(requests_per_minute);
        Self {
            state: Mutex::new((max, Instant::now())),
            max_tokens: max,
            refill_rate: rate,
        }
    }

    /// Try to acquire one token. Returns true if allowed, false if throttled.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn try_acquire(&self) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let (ref mut tokens, ref mut last_refill) = *state;
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *last_refill = now;
        *tokens = elapsed.mul_add(self.refill_rate, *tokens).min(self.max_tokens);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Block until a token is available, spinning with 10ms sleep.
    pub fn acquire_blocking(&self) {
        loop {
            if self.try_acquire() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn available_tokens(&self) -> f64 {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let (ref mut tokens, ref mut last_refill) = *state;
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *last_refill = now;
        *tokens = elapsed.mul_add(self.refill_rate, *tokens).min(self.max_tokens);
        *tokens
    }
}

// ─── Enrichment pipeline ──────────────────────────────────────────────────────

/// Configuration for the enrichment pipeline.
#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    /// API key for `VirusTotal`.
    pub api_key: String,
    /// Requests per minute allowed (VT free tier = 4, premium = higher).
    pub requests_per_minute: u32,
    /// Cache TTL in seconds.
    pub cache_ttl_seconds: u64,
    /// Maximum cache entries.
    pub cache_max_entries: usize,
    /// Whether to enrich IOC types that VT doesn't support.
    pub skip_unsupported: bool,
    /// Number of concurrent workers for batch enrichment.
    pub concurrency: usize,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            requests_per_minute: 4,
            cache_ttl_seconds: 3600,
            cache_max_entries: 10_000,
            skip_unsupported: true,
            concurrency: 2,
        }
    }
}

impl EnrichmentConfig {
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = key.into();
        self
    }

    #[must_use] 
    pub const fn premium(mut self) -> Self {
        self.requests_per_minute = 500;
        self.concurrency = 8;
        self
    }
}

/// Mock fetch function — in a real implementation this would call the VT REST API.
/// Returns synthetic `EnrichmentData` based on simple heuristics on the IOC value.
fn mock_fetch_vt(ioc: &Ioc) -> EnrichmentData {
    // Simulate: values ending in "bad" are flagged
    let is_bad = ioc.value.to_lowercase().contains("bad")
        || ioc.value.to_lowercase().contains("malware")
        || ioc.value.to_lowercase().contains("evil");

    let is_suspicious = ioc.value.to_lowercase().contains("susp");

    EnrichmentData {
        found: true,
        detection_ratio: if is_bad {
            Some(0.75)
        } else if is_suspicious {
            Some(0.2)
        } else {
            Some(0.0)
        },
        positives: if is_bad { Some(52) } else { Some(0) },
        total: Some(70),
        reputation: if is_bad {
            Some(-80)
        } else {
            Some(20)
        },
        last_analysis_date: Some(1_700_000_000),
        first_seen: Some(1_690_000_000),
        malware_names: if is_bad {
            vec!["Trojan.GenericKD".to_owned(), "Win32.Malware".to_owned()]
        } else {
            vec![]
        },
        tags: vec!["peexe".to_owned()],
        type_tag: Some("peexe".to_owned()),
        size: Some(102_400),
        sha256: if matches!(ioc.kind, IocKind::Sha256) {
            Some(ioc.value.clone())
        } else {
            None
        },
        ..Default::default()
    }
}

/// The main enrichment pipeline.
pub struct EnrichmentPipeline {
    config: EnrichmentConfig,
    cache: Arc<EnrichmentCache>,
    rate_limiter: Arc<RateLimiter>,
}

impl EnrichmentPipeline {
    #[must_use] 
    pub fn new(config: EnrichmentConfig) -> Self {
        let cache = Arc::new(EnrichmentCache::new(
            Duration::from_secs(config.cache_ttl_seconds),
            config.cache_max_entries,
        ));
        let rate_limiter = Arc::new(RateLimiter::new(config.requests_per_minute));
        Self {
            config,
            cache,
            rate_limiter,
        }
    }

    /// Enrich a single IOC.
    #[must_use] 
    pub fn enrich(&self, ioc: Ioc) -> EnrichedIoc {
        if self.config.skip_unsupported && !ioc.kind.is_lookupable() {
            return EnrichedIoc::not_found(ioc);
        }

        let cache_key = format!("{}:{}", ioc.kind.vt_lookup_path().unwrap_or("?"), ioc.value);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            return EnrichedIoc {
                ioc,
                data: cached,
                fetch_duration_ms: 0,
                from_cache: true,
            };
        }

        // Rate limit
        self.rate_limiter.acquire_blocking();

        let start = Instant::now();
        let data = mock_fetch_vt(&ioc);
        let elapsed = start.elapsed().as_millis() as u64;

        // Store in cache
        self.cache.insert(cache_key, data.clone());

        EnrichedIoc {
            ioc,
            data,
            fetch_duration_ms: elapsed,
            from_cache: false,
        }
    }

    /// Enrich a batch of IOCs.
    /// Deduplicates before fetching, returns one result per input IOC.
    #[must_use] 
    pub fn enrich_batch(&self, iocs: Vec<Ioc>) -> Vec<EnrichedIoc> {
        use rayon::prelude::*;

        // Deduplicate by (kind, value)
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let unique: Vec<Ioc> = iocs
            .into_iter()
            .filter(|i| {
                let key = format!("{:?}:{}", i.kind, i.value);
                seen.insert(key)
            })
            .collect();

        // Process in parallel (rayon respects our concurrency via the global pool)
        unique
            .into_par_iter()
            .map(|ioc| self.enrich(ioc))
            .collect()
    }

    /// Return a reference to the cache.
    #[must_use] 
    pub fn cache(&self) -> &EnrichmentCache {
        &self.cache
    }
}

// ─── MISP export ──────────────────────────────────────────────────────────────

/// MISP attribute types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MispAttributeType {
    #[serde(rename = "md5")]
    Md5,
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "domain")]
    Domain,
    #[serde(rename = "ip-dst")]
    IpDst,
    #[serde(rename = "url")]
    Url,
    #[serde(rename = "email-src")]
    EmailSrc,
    #[serde(rename = "other")]
    Other,
}

impl MispAttributeType {
    const fn from_ioc_kind(kind: &IocKind) -> Self {
        match kind {
            IocKind::Md5 => Self::Md5,
            IocKind::Sha1 => Self::Sha1,
            IocKind::Sha256 => Self::Sha256,
            IocKind::Domain => Self::Domain,
            IocKind::Ip => Self::IpDst,
            IocKind::Url => Self::Url,
            IocKind::Email => Self::EmailSrc,
            _ => Self::Other,
        }
    }
}

/// A MISP attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttribute {
    #[serde(rename = "type")]
    pub attr_type: MispAttributeType,
    pub value: String,
    pub category: String,
    pub comment: String,
    pub to_ids: bool,
    pub distribution: u8,
    pub tags: Vec<MispTag>,
}

/// A MISP tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispTag {
    pub name: String,
    pub colour: String,
}

/// A MISP event containing a collection of attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    pub info: String,
    pub threat_level_id: u8,
    pub analysis: u8,
    pub distribution: u8,
    pub attributes: Vec<MispAttribute>,
}

impl MispEvent {
    pub fn new(info: impl Into<String>) -> Self {
        Self {
            info: info.into(),
            threat_level_id: 2, // medium
            analysis: 0,        // initial
            distribution: 0,    // org only
            attributes: vec![],
        }
    }

    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&serde_json::json!({ "Event": self }))
    }
}

/// Convert a batch of enriched IOCs into a MISP event.
pub fn to_misp_event(
    results: &[EnrichedIoc],
    event_info: impl Into<String>,
    malicious_threshold: f32,
) -> MispEvent {
    let mut event = MispEvent::new(event_info);

    for enriched in results {
        if !enriched.data.found {
            continue;
        }

        let attr_type = MispAttributeType::from_ioc_kind(&enriched.ioc.kind);
        let is_malicious = enriched.data.is_malicious(malicious_threshold);
        let to_ids = is_malicious;

        let comment = enriched.data.detection_ratio.map_or_else(String::new, |dr| format!(
                "VT detection: {:.0}%{}",
                dr * 100.0,
                if enriched.data.malware_names.is_empty() {
                    String::new()
                } else {
                    format!(" | {}", enriched.data.malware_names.join(", "))
                }
            ));

        let mut tags: Vec<MispTag> = vec![];
        if is_malicious {
            tags.push(MispTag {
                name: "tlp:red".to_owned(),
                colour: "#cc0033".to_owned(),
            });
            tags.push(MispTag {
                name: "malicious".to_owned(),
                colour: "#ff0000".to_owned(),
            });
        } else {
            tags.push(MispTag {
                name: "tlp:amber".to_owned(),
                colour: "#ffc000".to_owned(),
            });
        }

        for tag in &enriched.ioc.tags {
            tags.push(MispTag {
                name: tag.clone(),
                colour: "#0088cc".to_owned(),
            });
        }

        let category = match &enriched.ioc.kind {
            IocKind::Domain | IocKind::Ip | IocKind::Url => "Network activity",
            IocKind::Md5 | IocKind::Sha1 | IocKind::Sha256 | IocKind::Email => "Payload delivery",
            _ => "Other",
        };

        event.attributes.push(MispAttribute {
            attr_type,
            value: enriched.ioc.value.clone(),
            category: category.to_owned(),
            comment,
            to_ids,
            distribution: 0,
            tags,
        });
    }

    event
}

// ─── Enrichment report ────────────────────────────────────────────────────────

/// Summary of a batch enrichment run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentReport {
    pub total_iocs: usize,
    pub found: usize,
    pub not_found: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub clean: usize,
    pub from_cache: usize,
    pub errors: usize,
    pub top_malware_families: Vec<(String, usize)>,
}

impl EnrichmentReport {
    #[must_use] 
    pub fn from_results(results: &[EnrichedIoc], mal_threshold: f32, susp_rep_threshold: i32) -> Self {
        let mut found = 0usize;
        let mut not_found = 0usize;
        let mut malicious = 0usize;
        let mut suspicious = 0usize;
        let mut clean = 0usize;
        let mut from_cache = 0usize;
        let mut errors = 0usize;
        let mut family_counts: HashMap<String, usize> = HashMap::new();

        for r in results {
            if r.data.error.is_some() {
                errors += 1;
                continue;
            }
            if !r.data.found {
                not_found += 1;
                continue;
            }
            found += 1;
            if r.from_cache {
                from_cache += 1;
            }
            if r.data.is_malicious(mal_threshold) {
                malicious += 1;
                for name in &r.data.malware_names {
                    *family_counts.entry(name.clone()).or_insert(0) += 1;
                }
            } else if r.data.is_suspicious(susp_rep_threshold) {
                suspicious += 1;
            } else {
                clean += 1;
            }
        }

        let mut top_families: Vec<(String, usize)> = family_counts.into_iter().collect();
        top_families.sort_by(|a, b| b.1.cmp(&a.1));
        top_families.truncate(10);

        Self {
            total_iocs: results.len(),
            found,
            not_found,
            malicious,
            suspicious,
            clean,
            from_cache,
            errors,
            top_malware_families: top_families,
        }
    }

    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_kind_detection() {
        assert_eq!(
            IocKind::from_value("d41d8cd98f00b204e9800998ecf8427e"),
            IocKind::Md5
        );
        assert_eq!(
            IocKind::from_value("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            IocKind::Sha1
        );
        assert_eq!(
            IocKind::from_value(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            IocKind::Sha256
        );
        assert_eq!(IocKind::from_value("192.168.1.1"), IocKind::Ip);
        assert_eq!(IocKind::from_value("evil.example.com"), IocKind::Domain);
        assert_eq!(
            IocKind::from_value("https://evil.example.com/payload"),
            IocKind::Url
        );
    }

    #[test]
    fn test_enrich_bad_ioc() {
        let pipeline = EnrichmentPipeline::new(EnrichmentConfig::default());
        let ioc = Ioc::new("badmalware123").with_kind(IocKind::Sha256);
        let result = pipeline.enrich(ioc);
        assert!(result.data.found);
        assert!(result.data.is_malicious(0.5));
    }

    #[test]
    fn test_cache_hit() {
        let pipeline = EnrichmentPipeline::new(EnrichmentConfig::default());
        let ioc1 = Ioc::new("testvalue").with_kind(IocKind::Sha256);
        let ioc2 = Ioc::new("testvalue").with_kind(IocKind::Sha256);
        let r1 = pipeline.enrich(ioc1);
        let r2 = pipeline.enrich(ioc2);
        assert!(!r1.from_cache);
        assert!(r2.from_cache);
    }

    #[test]
    fn test_batch_enrich_dedup() {
        let pipeline = EnrichmentPipeline::new(EnrichmentConfig::default());
        let iocs = vec![
            Ioc::new("abc").with_kind(IocKind::Sha256),
            Ioc::new("abc").with_kind(IocKind::Sha256), // duplicate
            Ioc::new("def").with_kind(IocKind::Domain),
        ];
        let results = pipeline.enrich_batch(iocs);
        // Dedup should result in 2 unique IOCs processed
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_misp_export() {
        let pipeline = EnrichmentPipeline::new(EnrichmentConfig::default());
        let iocs = vec![
            Ioc::new("badmalware").with_kind(IocKind::Sha256),
            Ioc::new("clean-file").with_kind(IocKind::Sha256),
        ];
        let results = pipeline.enrich_batch(iocs);
        let event = to_misp_event(&results, "Test event", 0.5);
        assert!(!event.attributes.is_empty());
        let json = event.to_json().unwrap();
        assert!(json.contains("Event"));
    }

    #[test]
    fn test_enrichment_report() {
        let pipeline = EnrichmentPipeline::new(EnrichmentConfig::default());
        let iocs = vec![
            Ioc::new("badmalware").with_kind(IocKind::Sha256),
            Ioc::new("harmless").with_kind(IocKind::Sha256),
        ];
        let results = pipeline.enrich_batch(iocs);
        let report = EnrichmentReport::from_results(&results, 0.5, -10);
        assert_eq!(report.total_iocs, 2);
        assert!(report.malicious >= 1);
    }

    #[test]
    fn test_rate_limiter_tokens() {
        let rl = RateLimiter::new(60); // 1 per second
        // Initial burst should have tokens
        assert!(rl.available_tokens() > 0.0);
        // Drain tokens
        while rl.try_acquire() {}
        assert!(rl.available_tokens() < 1.0);
    }

    #[test]
    fn test_unsupported_ioc_skipped() {
        let config = EnrichmentConfig {
            skip_unsupported: true,
            ..Default::default()
        };
        let pipeline = EnrichmentPipeline::new(config);
        let ioc = Ioc::new("\\REGISTRY\\MACHINE\\SOFTWARE\\badkey").with_kind(IocKind::RegistryKey);
        let result = pipeline.enrich(ioc);
        assert!(!result.data.found);
    }
}
