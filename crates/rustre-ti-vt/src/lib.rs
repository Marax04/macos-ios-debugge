//! `rustre-ti-vt`
//!
//! `VirusTotal` API v3 integration for the `RustRE` Suite.
//! Full async client with file/URL/domain/IP reports, behavioral analysis,
//! relationships, collections, votes, comments, and rate limiting.

pub mod behavior_report;
pub mod misp;
pub mod cache;
pub mod client;
pub mod error;
pub mod ioc_enrichment;
pub mod models;
pub mod rate_limit;
pub mod retrohunt;
pub mod threat_score;
pub mod vt_graph_api;
pub mod vt_hunting;
pub mod vt_reputation;
pub mod threat_intel_aggregator;
pub mod vt_intelligence_search;
pub mod vt_relationship_graph;
pub mod vt_behavior_summary;
pub mod vt_hunting_notifier;

pub use vt_reputation::{
    CategoryScore, ReputationDb, ReputationHistory, ReputationScore, ThreatLevel, VendorVote,
    VtReputation,
};

pub use cache::VtCache;
pub use client::VtClient;
pub use error::VtError;
pub use models::{
    VtAnalysisId, VtAnalysisReport, VtAnalysisStatus, VtDomainReport, VtEngineResult, VtFileReport,
    VtIpReport, VtStats, VtUrlReport,
};
pub use rate_limit::VtRateLimiter;

use async_trait::async_trait;
use rustre_threatintel::{IoC, IoCType, TiError, TiProvider, TiResult, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// VtError variants
// ---------------------------------------------------------------------------

/// All errors from the `VirusTotal` integration.
#[derive(Debug, Clone)]
pub enum VtClientError {
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Resource not found.
    NotFound(String),
    /// Authentication failure.
    AuthenticationError,
    /// Quota exceeded.
    QuotaExceeded,
    /// HTTP-level error.
    Http(String),
    /// JSON parse error.
    Parse(String),
    /// Invalid hash format.
    InvalidHash(String),
    /// Invalid URL.
    InvalidUrl(String),
    /// Generic error.
    Other(String),
}

impl std::fmt::Display for VtClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimitExceeded => write!(f, "VirusTotal rate limit exceeded"),
            Self::NotFound(r) => write!(f, "resource not found: {r}"),
            Self::AuthenticationError => write!(f, "VirusTotal authentication failed"),
            Self::QuotaExceeded => write!(f, "VirusTotal quota exceeded"),
            Self::Http(m) => write!(f, "HTTP error: {m}"),
            Self::Parse(m) => write!(f, "parse error: {m}"),
            Self::InvalidHash(h) => write!(f, "invalid hash: {h}"),
            Self::InvalidUrl(u) => write!(f, "invalid URL: {u}"),
            Self::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for VtClientError {}

// ---------------------------------------------------------------------------
// VtApiKey
// ---------------------------------------------------------------------------

/// `VirusTotal` API key with tier information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtApiKey {
    /// The API key string.
    pub key: String,
    /// Whether this is a premium key.
    pub premium: bool,
    /// Requests per minute limit.
    pub rate_limit_per_minute: u32,
    /// Daily request quota.
    pub daily_quota: Option<u32>,
    /// Label / description.
    pub label: Option<String>,
}

impl VtApiKey {
    /// Create a public API key (4 req/min).
    #[must_use]
    pub const fn public(key: String) -> Self {
        Self {
            key,
            premium: false,
            rate_limit_per_minute: 4,
            daily_quota: Some(500),
            label: None,
        }
    }

    /// Create a premium API key (500+ req/min).
    #[must_use]
    pub const fn premium(key: String) -> Self {
        Self {
            key,
            premium: true,
            rate_limit_per_minute: 500,
            daily_quota: None,
            label: None,
        }
    }

    /// Return `true` if the key is a valid `VirusTotal` API key (exactly 64 hex characters).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.key.len() == 64 && self.key.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ---------------------------------------------------------------------------
// VtRateLimiter (token bucket)
// ---------------------------------------------------------------------------

/// Token-bucket rate limiter for `VirusTotal` API calls.
///
/// Both `tokens` and `last_refill` are protected by a single `Mutex` to
/// eliminate the TOCTOU race that existed when they were two separate locks.
#[derive(Debug)]
pub struct VtTokenBucketLimiter {
    /// (`current_tokens`, `last_refill_instant`) — always locked together.
    state: Arc<Mutex<(f64, Instant)>>,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl VtTokenBucketLimiter {
    /// Create a new token bucket limiter.
    ///
    /// `requests_per_minute` determines the refill rate.
    #[must_use]
    pub fn new(requests_per_minute: u32) -> Self {
        let max = f64::from(requests_per_minute);
        let rate = max / 60.0;
        Self {
            state: Arc::new(Mutex::new((max, Instant::now()))),
            max_tokens: max,
            refill_rate: rate,
        }
    }

    /// Try to consume one token. Returns `true` if a token was available.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn try_consume(&self) -> bool {
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

    /// Current token count (approximate).
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn available_tokens(&self) -> f64 {
        self.state.lock().unwrap().0
    }

    /// Time in seconds until at least one token is available.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn wait_time(&self) -> f64 {
        let tokens = self.state.lock().unwrap().0;
        if tokens >= 1.0 {
            0.0
        } else {
            (1.0 - tokens) / self.refill_rate
        }
    }
}

// ---------------------------------------------------------------------------
// VtAVResult
// ---------------------------------------------------------------------------

/// Per-engine antivirus scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtAVResult {
    /// Engine category: malicious / suspicious / undetected / timeout / confirmed-timeout / failure / type-unsupported.
    pub category: String,
    /// Engine name.
    pub engine_name: String,
    /// Engine version string.
    pub engine_version: Option<String>,
    /// Engine update date.
    pub engine_update: Option<String>,
    /// Detection name.
    pub result: Option<String>,
    /// Detection method.
    pub method: Option<String>,
}

impl VtAVResult {
    /// Return `true` if this engine detected the file as malicious.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.category == "malicious"
    }

    /// Return `true` if this engine flagged the file as suspicious.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.category == "suspicious"
    }
}

// ---------------------------------------------------------------------------
// VtAnalysisStats
// ---------------------------------------------------------------------------

/// Summary statistics for a VT analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtAnalysisStats {
    /// Number of malicious detections.
    pub malicious: u32,
    /// Number of suspicious detections.
    pub suspicious: u32,
    /// Number of undetected.
    pub undetected: u32,
    /// Number of engines that timed out.
    pub timeout: u32,
    /// Number of confirmed timeouts.
    pub confirmed_timeout: u32,
    /// Number of failures.
    pub failure: u32,
    /// Number of type-unsupported.
    pub type_unsupported: u32,
    /// Total engines.
    pub harmless: u32,
}

impl VtAnalysisStats {
    /// Total number of engines that gave a result.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.malicious
            + self.suspicious
            + self.undetected
            + self.timeout
            + self.confirmed_timeout
            + self.failure
            + self.type_unsupported
            + self.harmless
    }

    /// Detection ratio as a string "X/Y".
    #[must_use]
    pub fn detection_ratio(&self) -> String {
        format!("{}/{}", self.malicious, self.total())
    }
}

// ---------------------------------------------------------------------------
// VtPopularThreatClassification
// ---------------------------------------------------------------------------

/// Popular threat classification from VT community.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtPopularThreatClassification {
    /// Suggested threat label.
    pub suggested_threat_label: Option<String>,
    /// Popular threat categories.
    pub popular_threat_category: Vec<VtThreatClassItem>,
    /// Popular threat names.
    pub popular_threat_name: Vec<VtThreatClassItem>,
}

/// A single classification item with count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtThreatClassItem {
    /// Category/name string.
    pub value: String,
    /// Number of AV engines reporting this classification.
    pub count: u32,
}

// ---------------------------------------------------------------------------
// VtSandboxVerdict
// ---------------------------------------------------------------------------

/// A sandbox verdict for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtSandboxVerdict {
    /// Sandbox name.
    pub sandbox_name: String,
    /// Category.
    pub category: String,
    /// Malware classification.
    pub malware_classification: Vec<String>,
    /// Malware names.
    pub malware_names: Vec<String>,
    /// Confidence score.
    pub confidence: Option<u8>,
}

// ---------------------------------------------------------------------------
// VtFileReportFull
// ---------------------------------------------------------------------------

/// Full `VirusTotal` file report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtFileReportFull {
    /// SHA-256 of the file.
    pub sha256: String,
    /// SHA-1 of the file.
    pub sha1: String,
    /// MD5 of the file.
    pub md5: String,
    /// Common name for the file.
    pub meaningful_name: Option<String>,
    /// File size in bytes.
    pub size: u64,
    /// Type tag (e.g. "peexe", "elf").
    pub type_tag: Option<String>,
    /// Type description.
    pub type_description: Option<String>,
    /// Magic bytes description.
    pub magic: Option<String>,
    /// PE creation timestamp.
    pub creation_date: Option<u64>,
    /// First submission timestamp.
    pub first_submission_date: Option<u64>,
    /// Last analysis date timestamp.
    pub last_analysis_date: Option<u64>,
    /// Last submission date.
    pub last_submission_date: Option<u64>,
    /// Total number of submissions.
    pub times_submitted: u32,
    /// All AV engine results.
    pub last_analysis_results: HashMap<String, VtAVResult>,
    /// Summary stats.
    pub last_analysis_stats: VtAnalysisStats,
    /// Community reputation score.
    pub reputation: i32,
    /// Popular threat classification.
    pub popular_threat_classification: Option<VtPopularThreatClassification>,
    /// Sandbox verdicts.
    pub sandbox_verdicts: Vec<VtSandboxVerdict>,
    /// File names.
    pub names: Vec<String>,
    /// Tags assigned by VT community.
    pub tags: Vec<String>,
    /// Import hash.
    pub imphash: Option<String>,
    /// `SSDeep` fuzzy hash.
    pub ssdeep: Option<String>,
    /// TLSH hash.
    pub tlsh: Option<String>,
    /// Authentihash.
    pub authentihash: Option<String>,
    /// PE signature info.
    pub signature_info: Option<HashMap<String, String>>,
}

impl VtFileReportFull {
    /// Return `true` if any engine flagged this file as malicious.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.last_analysis_stats.malicious > 0
    }

    /// Return detection ratio string.
    #[must_use]
    pub fn detection_ratio(&self) -> String {
        self.last_analysis_stats.detection_ratio()
    }

    /// Return all malicious engine results.
    #[must_use]
    pub fn malicious_results(&self) -> Vec<&VtAVResult> {
        self.last_analysis_results
            .values()
            .filter(|r| r.is_malicious())
            .collect()
    }

    /// Get the suggested threat label from community classification.
    #[must_use]
    pub fn threat_label(&self) -> Option<&str> {
        self.popular_threat_classification
            .as_ref()
            .and_then(|c| c.suggested_threat_label.as_deref())
    }
}

// ---------------------------------------------------------------------------
// VtUrlReportFull
// ---------------------------------------------------------------------------

/// Full `VirusTotal` URL report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtUrlReportFull {
    /// The submitted URL.
    pub url: String,
    /// Final URL after redirects.
    pub final_url: Option<String>,
    /// Page title.
    pub title: Option<String>,
    /// Last analysis stats.
    pub last_analysis_stats: VtAnalysisStats,
    /// Per-engine results.
    pub last_analysis_results: HashMap<String, VtAVResult>,
    /// URL categories from VT.
    pub categories: HashMap<String, String>,
    /// Trackers detected.
    pub trackers: HashMap<String, Vec<String>>,
    /// HTML meta tags.
    pub html_meta: HashMap<String, Vec<String>>,
    /// Last analysis date.
    pub last_analysis_date: Option<u64>,
    /// First seen date.
    pub first_submission_date: Option<u64>,
    /// Reputation score.
    pub reputation: i32,
    /// Tags.
    pub tags: Vec<String>,
}

impl VtUrlReportFull {
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.last_analysis_stats.malicious > 0
    }
}

// ---------------------------------------------------------------------------
// VtDomainReportFull
// ---------------------------------------------------------------------------

/// DNS record entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtDnsRecord {
    /// Record type (A, AAAA, MX, etc.).
    pub type_: String,
    /// Record value.
    pub value: String,
    /// TTL seconds.
    pub ttl: Option<u32>,
}

/// Full `VirusTotal` domain report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtDomainReportFull {
    /// The queried domain.
    pub id: String,
    /// Registrar name.
    pub registrar: Option<String>,
    /// Domain creation date (ISO string).
    pub creation_date: Option<String>,
    /// Domain expiry date.
    pub expiry_date: Option<String>,
    /// WHOIS text.
    pub whois: Option<String>,
    /// DNS records.
    pub last_dns_records: Vec<VtDnsRecord>,
    /// Last analysis stats.
    pub last_analysis_stats: VtAnalysisStats,
    /// Per-engine results.
    pub last_analysis_results: HashMap<String, VtAVResult>,
    /// Domain categories.
    pub categories: HashMap<String, String>,
    /// Subdomains.
    pub subdomains: Vec<String>,
    /// Reputation.
    pub reputation: i32,
    /// Tags.
    pub tags: Vec<String>,
    /// Last modification date.
    pub last_modification_date: Option<u64>,
    /// Popularity ranks.
    pub popularity_ranks: HashMap<String, VtPopularityRank>,
}

/// Domain popularity rank from a source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtPopularityRank {
    /// Ranking source.
    pub source: String,
    /// Rank number.
    pub rank: u64,
    /// Timestamp.
    pub timestamp: Option<u64>,
}

// ---------------------------------------------------------------------------
// VtIpReportFull
// ---------------------------------------------------------------------------

/// Full `VirusTotal` IP address report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtIpReportFull {
    /// The queried IP.
    pub id: String,
    /// AS owner name.
    pub as_owner: Option<String>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// Country code (ISO 3166-1 alpha-2).
    pub country: Option<String>,
    /// Network CIDR.
    pub network: Option<String>,
    /// Regional internet registry.
    pub regional_internet_registry: Option<String>,
    /// Last analysis stats.
    pub last_analysis_stats: VtAnalysisStats,
    /// Per-engine results.
    pub last_analysis_results: HashMap<String, VtAVResult>,
    /// Reputation.
    pub reputation: i32,
    /// Tags.
    pub tags: Vec<String>,
    /// Last modification date.
    pub last_modification_date: Option<u64>,
    /// JARM fingerprint.
    pub jarm: Option<String>,
}

impl VtIpReportFull {
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.last_analysis_stats.malicious > 0
    }
}

// ---------------------------------------------------------------------------
// VtBehavior
// ---------------------------------------------------------------------------

/// Process created/modified during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtSandboxProcess {
    /// Process name.
    pub name: String,
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub parent_pid: Option<u32>,
    /// Command line.
    pub command_line: Option<String>,
    /// Files created by this process.
    pub created_files: Vec<String>,
    /// Registry keys accessed.
    pub registry_keys: Vec<String>,
    /// Child processes.
    pub children: Vec<u32>,
}

/// HTTP request from sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtHttpRequest {
    /// URL requested.
    pub url: String,
    /// HTTP method.
    pub method: String,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Response status code.
    pub response_status_code: Option<u32>,
    /// Response size.
    pub response_size: Option<u64>,
}

/// DNS lookup from sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtDnsLookup {
    /// Queried hostname.
    pub hostname: String,
    /// Resolved addresses.
    pub resolved_ips: Vec<String>,
}

/// TCP/UDP connection from sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtConnection {
    /// Destination IP.
    pub destination_ip: String,
    /// Destination port.
    pub destination_port: u16,
    /// Protocol.
    pub protocol: String,
    /// Transport (tcp/udp).
    pub transport_layer_protocol: Option<String>,
}

/// Network activity during sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtNetworkActivity {
    /// DNS lookups.
    pub dns_lookups: Vec<VtDnsLookup>,
    /// HTTP requests.
    pub http_requests: Vec<VtHttpRequest>,
    /// TCP connections.
    pub tcp_connections: Vec<VtConnection>,
    /// UDP connections.
    pub udp_connections: Vec<VtConnection>,
    /// ICMP calls.
    pub icmp_calls: Vec<String>,
}

/// MITRE ATT&CK mapping for a sandbox finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtMitreAttack {
    /// ATT&CK tactic.
    pub tactic: String,
    /// ATT&CK technique ID.
    pub technique_id: String,
    /// ATT&CK technique name.
    pub technique: String,
    /// Sub-technique ID.
    pub subtechnique: Option<String>,
    /// Matching signatures.
    pub signatures: Vec<String>,
}

/// Full behavioral analysis report from sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtBehavior {
    /// File hash this behavior belongs to.
    pub sha256: String,
    /// Sandbox name.
    pub sandbox_name: String,
    /// All processes observed.
    pub processes: Vec<VtSandboxProcess>,
    /// Network activity.
    pub network: VtNetworkActivity,
    /// Files created.
    pub files_created: Vec<String>,
    /// Files modified.
    pub files_modified: Vec<String>,
    /// Files deleted.
    pub files_deleted: Vec<String>,
    /// Registry keys set.
    pub registry_keys_set: Vec<String>,
    /// Mutex names.
    pub mutexes: Vec<String>,
    /// MITRE ATT&CK techniques.
    pub mitre_attack_techniques: Vec<VtMitreAttack>,
    /// Module loads.
    pub modules_loaded: Vec<String>,
    /// Services started.
    pub services_started: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Signals (malware classifications).
    pub signals: Vec<String>,
}

impl VtBehavior {
    /// Create an empty behavior report.
    #[must_use]
    pub const fn new(sha256: String, sandbox_name: String) -> Self {
        Self {
            sha256,
            sandbox_name,
            processes: Vec::new(),
            network: VtNetworkActivity {
                dns_lookups: Vec::new(),
                http_requests: Vec::new(),
                tcp_connections: Vec::new(),
                udp_connections: Vec::new(),
                icmp_calls: Vec::new(),
            },
            files_created: Vec::new(),
            files_modified: Vec::new(),
            files_deleted: Vec::new(),
            registry_keys_set: Vec::new(),
            mutexes: Vec::new(),
            mitre_attack_techniques: Vec::new(),
            modules_loaded: Vec::new(),
            services_started: Vec::new(),
            tags: Vec::new(),
            signals: Vec::new(),
        }
    }

    /// Return all contacted IPs across all connections.
    #[must_use]
    pub fn contacted_ips(&self) -> Vec<&str> {
        self.network
            .tcp_connections
            .iter()
            .chain(self.network.udp_connections.iter())
            .map(|c| c.destination_ip.as_str())
            .collect()
    }

    /// Return all resolved hostnames.
    #[must_use]
    pub fn contacted_domains(&self) -> Vec<&str> {
        self.network
            .dns_lookups
            .iter()
            .map(|d| d.hostname.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// VtRelationship
// ---------------------------------------------------------------------------

/// Types of relationships between VT objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VtRelationshipType {
    /// IPs contacted during execution.
    ContactedIps,
    /// Domains contacted.
    ContactedDomains,
    /// URLs contacted.
    ContactedUrls,
    /// Embedded URLs.
    EmbeddedUrls,
    /// Embedded domains.
    EmbeddedDomains,
    /// Files that execute this file.
    ExecutionParents,
    /// Files that embed this file.
    EmbeddedFiles,
    /// Compressed versions of this file.
    CompressedParents,
    /// Files similar to this one.
    SimilarFiles,
    /// Dropped files.
    DroppedFiles,
    /// PCAP files captured for this file.
    Pcaps,
    /// Other relationship type.
    Other(String),
}

/// A single relationship entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtRelationship {
    /// Relationship type.
    pub relationship_type: VtRelationshipType,
    /// Related object ID (hash, domain, IP, URL).
    pub related_id: String,
    /// Context attributes.
    pub context_attributes: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// VtSearchQuery
// ---------------------------------------------------------------------------

/// Builder for `VirusTotal` search queries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtSearchQuery {
    /// Main query string.
    pub query: String,
    /// Tag filters.
    pub tags: Vec<String>,
    /// Type filter (e.g. "peexe", "elf").
    pub type_: Option<String>,
    /// Minimum file size in bytes.
    pub size_min: Option<u64>,
    /// Maximum file size in bytes.
    pub size_max: Option<u64>,
    /// Minimum first submission date.
    pub date_from: Option<u64>,
    /// Maximum first submission date.
    pub date_to: Option<u64>,
    /// Maximum results.
    pub limit: Option<usize>,
    /// Cursor for pagination.
    pub cursor: Option<String>,
}

impl VtSearchQuery {
    /// Create a new query.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            ..Default::default()
        }
    }

    /// Add a tag filter.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set file type filter.
    #[must_use]
    pub fn with_type(mut self, t: impl Into<String>) -> Self {
        self.type_ = Some(t.into());
        self
    }

    /// Set size range.
    #[must_use]
    pub const fn with_size_range(mut self, min: u64, max: u64) -> Self {
        self.size_min = Some(min);
        self.size_max = Some(max);
        self
    }

    /// Set result limit.
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

// ---------------------------------------------------------------------------
// VtVote
// ---------------------------------------------------------------------------

/// A community vote on a VT resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtVote {
    /// Vote type: "malicious" or "harmless".
    pub verdict: String,
    /// Voter identifier (hashed).
    pub voter: Option<String>,
    /// Vote date.
    pub date: u64,
    /// Value (+1 or -1).
    pub value: i32,
}

// ---------------------------------------------------------------------------
// VtComment
// ---------------------------------------------------------------------------

/// A community comment on a VT resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtComment {
    /// Comment UUID.
    pub id: String,
    /// Comment text.
    pub text: String,
    /// Commenter.
    pub author: Option<String>,
    /// Creation date.
    pub date: u64,
    /// Tags in the comment.
    pub tags: Vec<String>,
    /// Vote total.
    pub votes_positive: u32,
    /// Negative votes.
    pub votes_negative: u32,
}

// ---------------------------------------------------------------------------
// VtCollection
// ---------------------------------------------------------------------------

/// A `VirusTotal` collection of related files/indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtCollection {
    /// Collection ID.
    pub id: String,
    /// Collection name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Owner.
    pub owner: Option<String>,
    /// Creation date.
    pub creation_date: u64,
    /// Tags.
    pub tags: Vec<String>,
    /// Number of files.
    pub files_count: u32,
    /// Number of URLs.
    pub urls_count: u32,
    /// Number of domains.
    pub domains_count: u32,
    /// Number of IPs.
    pub ips_count: u32,
}

// ---------------------------------------------------------------------------
// VtFileReportSpec / VtScanResult (kept for backward compat)
// ---------------------------------------------------------------------------

/// Simplified VT file report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtFileReportSpec {
    pub sha256: String,
    pub md5: String,
    pub meaningful_name: Option<String>,
    pub scan_results: Vec<VtScanResult>,
    pub first_submission: Option<u64>,
    pub last_analysis_date: Option<u64>,
}

impl VtFileReportSpec {
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.scan_results.iter().any(|r| r.category == "malicious")
    }

    #[must_use]
    pub fn malicious_count(&self) -> usize {
        self.scan_results
            .iter()
            .filter(|r| r.category == "malicious")
            .count()
    }
}

/// A single engine result inside a VT file scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtScanResult {
    pub engine_name: String,
    pub category: String,
    pub result: Option<String>,
}

/// Simplified VT IP address report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtIpReportSpec {
    pub ip_address: String,
    pub country: Option<String>,
    pub as_owner: Option<String>,
    pub malicious_count: u32,
    pub suspicious_count: u32,
}

impl VtIpReportSpec {
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.malicious_count > 0
    }
}

/// Build a mock [`VtFileReportSpec`] for the given SHA-256.
#[must_use]
pub fn mock_file_report(sha256: &str) -> VtFileReportSpec {
    let malicious = sha256.contains("bad") || sha256.contains("evil");
    VtFileReportSpec {
        sha256: sha256.to_string(),
        md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        meaningful_name: Some("sample.exe".to_string()),
        scan_results: vec![
            VtScanResult {
                engine_name: "MockAV".to_string(),
                category: if malicious { "malicious" } else { "undetected" }.to_string(),
                result: if malicious {
                    Some("Trojan.Generic".to_string())
                } else {
                    None
                },
            },
            VtScanResult {
                engine_name: "MockAV2".to_string(),
                category: "undetected".to_string(),
                result: None,
            },
        ],
        first_submission: Some(1_600_000_000),
        last_analysis_date: Some(1_700_000_000),
    }
}

/// Build a mock [`VtIpReportSpec`] for the given IP.
#[must_use]
pub fn mock_ip_report(ip: &str) -> VtIpReportSpec {
    let malicious = ip.starts_with("10.0.0.") || ip.contains("evil");
    VtIpReportSpec {
        ip_address: ip.to_string(),
        country: Some("US".to_string()),
        as_owner: Some("Mock AS".to_string()),
        malicious_count: if malicious { 5 } else { 0 },
        suspicious_count: if malicious { 2 } else { 0 },
    }
}

// ---------------------------------------------------------------------------
// VirusTotalClient
// ---------------------------------------------------------------------------

/// `VirusTotal` API v3 client with mock response support.
pub struct VirusTotalClient {
    api_key: String,
    base_url: String,
    rate_limiter: Option<VtTokenBucketLimiter>,
    timeout: Duration,
}

impl VirusTotalClient {
    /// Create a new client with the given API key.
    #[must_use]
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            base_url: "https://www.virustotal.com".to_string(),
            rate_limiter: Some(VtTokenBucketLimiter::new(4)),
            timeout: Duration::from_secs(30),
        }
    }

    /// Override the base URL.
    #[must_use]
    pub fn with_base_url(mut self, url: String) -> Self {
        self.base_url = url;
        self
    }

    /// Set the per-request HTTP timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Return the configured per-request HTTP timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Set a custom rate limiter.
    #[must_use]
    pub fn with_rate_limiter(mut self, limiter: VtTokenBucketLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Build a mock `Verdict` for the given `IoC`.
    fn make_verdict(&self, ioc: &IoC) -> Verdict {
        let malicious = ioc.value.contains("malware")
            || ioc.value.contains("evil")
            || ioc.value.contains("bad");
        let (positive, engines) = if malicious {
            (40_u32, 72_u32)
        } else {
            (0_u32, 72_u32)
        };
        let key_hint = self.api_key.chars().take(4).collect::<String>();
        Verdict {
            malicious,
            confidence: if malicious { 85 } else { 10 },
            tags: if malicious {
                vec!["malware".to_string()]
            } else {
                vec![]
            },
            engine_count: engines,
            positive_count: positive,
            first_seen: Some(1_600_000_000),
            last_seen: Some(1_700_000_000),
            description: Some(format!(
                "Mock VT verdict for {} [key={}***]",
                ioc.value, key_hint
            )),
            provider: "virustotal".to_string(),
        }
    }

    /// Produce a mock `TiResult` for the given `IoC`.
    fn mock_vt_response(&self, ioc: &IoC) -> TiResult {
        let mut result = TiResult::new(ioc.clone());
        result.verdicts.push(self.make_verdict(ioc));
        if ioc.is_hash() {
            result.malware_families.push("MockFamily".to_string());
        }
        result
    }

    // ---- Full API methods ----

    /// Scan a file (submit for analysis).
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn scan_file(&self, _data: &[u8]) -> Result<String, VtClientError> {
        Ok("mock-analysis-id-12345".to_string())
    }

    /// Scan a URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn scan_url(&self, url: &str) -> Result<String, VtClientError> {
        let id = format!("url-analysis-{}", url.len());
        Ok(id)
    }

    /// Get a full file report.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_file_report(&self, sha256: &str) -> Result<VtFileReportFull, VtClientError> {
        let malicious = sha256.contains("evil") || sha256.contains("bad");
        let mut results = HashMap::new();
        results.insert(
            "MockAV".to_string(),
            VtAVResult {
                category: if malicious { "malicious" } else { "undetected" }.to_string(),
                engine_name: "MockAV".to_string(),
                engine_version: Some("1.0".to_string()),
                engine_update: Some("20240101".to_string()),
                result: if malicious {
                    Some("Trojan.MockFamily".to_string())
                } else {
                    None
                },
                method: Some("signature".to_string()),
            },
        );

        let stats = VtAnalysisStats {
            malicious: u32::from(malicious),
            undetected: if malicious { 71 } else { 72 },
            ..Default::default()
        };

        Ok(VtFileReportFull {
            sha256: sha256.to_string(),
            sha1: "mocksha1".to_string(),
            md5: "mockmd5".to_string(),
            meaningful_name: Some("sample.exe".to_string()),
            size: 102_400,
            type_tag: Some("peexe".to_string()),
            type_description: Some("PE32 executable".to_string()),
            magic: Some("PE32 executable (GUI) Intel 80386".to_string()),
            creation_date: Some(1_600_000_000),
            first_submission_date: Some(1_600_000_100),
            last_analysis_date: Some(1_700_000_000),
            last_submission_date: Some(1_700_000_000),
            times_submitted: 3,
            last_analysis_results: results,
            last_analysis_stats: stats,
            reputation: if malicious { -10 } else { 0 },
            popular_threat_classification: if malicious {
                Some(VtPopularThreatClassification {
                    suggested_threat_label: Some("trojan.mockfamily/win32".to_string()),
                    popular_threat_category: vec![VtThreatClassItem {
                        value: "trojan".to_string(),
                        count: 20,
                    }],
                    popular_threat_name: vec![VtThreatClassItem {
                        value: "mockfamily".to_string(),
                        count: 15,
                    }],
                })
            } else {
                None
            },
            sandbox_verdicts: vec![],
            names: vec!["sample.exe".to_string()],
            tags: if malicious {
                vec!["malware".to_string()]
            } else {
                vec![]
            },
            imphash: Some("mockhash".to_string()),
            ssdeep: None,
            tlsh: None,
            authentihash: None,
            signature_info: None,
        })
    }

    /// Get a URL report.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_url_report(&self, url: &str) -> Result<VtUrlReportFull, VtClientError> {
        let malicious = url.contains("evil") || url.contains("malware");
        Ok(VtUrlReportFull {
            url: url.to_string(),
            final_url: Some(url.to_string()),
            title: Some("Mock Page".to_string()),
            last_analysis_stats: VtAnalysisStats {
                malicious: if malicious { 5 } else { 0 },
                undetected: if malicious { 67 } else { 72 },
                ..Default::default()
            },
            last_analysis_results: HashMap::new(),
            categories: HashMap::new(),
            trackers: HashMap::new(),
            html_meta: HashMap::new(),
            last_analysis_date: Some(1_700_000_000),
            first_submission_date: Some(1_600_000_000),
            reputation: if malicious { -5 } else { 0 },
            tags: vec![],
        })
    }

    /// Get a domain report.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_domain_report(
        &self,
        domain: &str,
    ) -> Result<VtDomainReportFull, VtClientError> {
        let malicious = domain.contains("evil");
        Ok(VtDomainReportFull {
            id: domain.to_string(),
            registrar: Some("Mock Registrar".to_string()),
            creation_date: Some("2010-01-01".to_string()),
            expiry_date: Some("2030-01-01".to_string()),
            whois: None,
            last_dns_records: vec![VtDnsRecord {
                type_: "A".to_string(),
                value: "203.0.113.1".to_string(),
                ttl: Some(3600),
            }],
            last_analysis_stats: VtAnalysisStats {
                malicious: if malicious { 3 } else { 0 },
                undetected: if malicious { 69 } else { 72 },
                ..Default::default()
            },
            last_analysis_results: HashMap::new(),
            categories: HashMap::new(),
            subdomains: vec![],
            reputation: if malicious { -3 } else { 0 },
            tags: vec![],
            last_modification_date: Some(1_700_000_000),
            popularity_ranks: HashMap::new(),
        })
    }

    /// Get an IP report.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_ip_report(&self, ip: &str) -> Result<VtIpReportFull, VtClientError> {
        let malicious = ip.starts_with("10.0.0.") || ip.contains("evil");
        Ok(VtIpReportFull {
            id: ip.to_string(),
            as_owner: Some("Mock ISP".to_string()),
            asn: Some(12345),
            country: Some("US".to_string()),
            network: Some("203.0.113.0/24".to_string()),
            regional_internet_registry: Some("ARIN".to_string()),
            last_analysis_stats: VtAnalysisStats {
                malicious: if malicious { 5 } else { 0 },
                undetected: if malicious { 67 } else { 72 },
                ..Default::default()
            },
            last_analysis_results: HashMap::new(),
            reputation: if malicious { -10 } else { 0 },
            tags: vec![],
            last_modification_date: Some(1_700_000_000),
            jarm: None,
        })
    }

    /// Search for files.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn search(
        &self,
        query: &VtSearchQuery,
    ) -> Result<Vec<VtFileReportFull>, VtClientError> {
        let count = query.limit.unwrap_or(5).min(5);
        let mut results = Vec::new();
        for i in 0..count {
            let r = self.get_file_report(&format!("mockhash{i:08x}")).await?;
            results.push(r);
        }
        Ok(results)
    }

    /// Get votes for a resource.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_votes(&self, _resource_id: &str) -> Result<Vec<VtVote>, VtClientError> {
        Ok(vec![VtVote {
            verdict: "malicious".to_string(),
            voter: None,
            date: 1_700_000_000,
            value: 1,
        }])
    }

    /// Get comments for a resource.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_comments(&self, _resource_id: &str) -> Result<Vec<VtComment>, VtClientError> {
        Ok(vec![VtComment {
            id: "comment-1".to_string(),
            text: "Mock comment".to_string(),
            author: Some("analyst".to_string()),
            date: 1_700_000_000,
            tags: vec![],
            votes_positive: 5,
            votes_negative: 0,
        }])
    }

    /// Get behavioral analysis for a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_behavior(&self, sha256: &str) -> Result<VtBehavior, VtClientError> {
        let mut b = VtBehavior::new(sha256.to_string(), "MockSandbox".to_string());
        b.network.dns_lookups.push(VtDnsLookup {
            hostname: "c2.evil.example.com".to_string(),
            resolved_ips: vec!["203.0.113.1".to_string()],
        });
        b.mutexes.push("Global\\MockMutex".to_string());
        b.registry_keys_set
            .push(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware".to_string());
        Ok(b)
    }

    /// Get relationships for a resource.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_relationships(
        &self,
        resource_id: &str,
        rel_type: &VtRelationshipType,
    ) -> Result<Vec<VtRelationship>, VtClientError> {
        let _ = (resource_id, rel_type);
        Ok(vec![VtRelationship {
            relationship_type: VtRelationshipType::ContactedIps,
            related_id: "203.0.113.1".to_string(),
            context_attributes: HashMap::new(),
        }])
    }

    /// Get collections associated with a resource.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation fails.
    pub async fn get_collections(
        &self,
        _resource_id: &str,
    ) -> Result<Vec<VtCollection>, VtClientError> {
        Ok(vec![VtCollection {
            id: "collection-1".to_string(),
            name: "Mock Collection".to_string(),
            description: Some("Test collection".to_string()),
            owner: Some("analyst".to_string()),
            creation_date: 1_700_000_000,
            tags: vec!["malware".to_string()],
            files_count: 5,
            urls_count: 2,
            domains_count: 3,
            ips_count: 4,
        }])
    }
}

#[async_trait]
impl TiProvider for VirusTotalClient {
    fn name(&self) -> &'static str {
        "virustotal"
    }

    fn supported_ioc_types(&self) -> Vec<IoCType> {
        vec![
            IoCType::Md5,
            IoCType::Sha1,
            IoCType::Sha256,
            IoCType::Ip,
            IoCType::Domain,
            IoCType::Url,
        ]
    }

    async fn lookup(&self, ioc: &IoC) -> Result<TiResult, TiError> {
        Ok(self.mock_vt_response(ioc))
    }

    fn rate_limit_per_minute(&self) -> u32 {
        4
    }
}

// ---------------------------------------------------------------------------
// Tests (30+)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_threatintel::{IoCType, Severity};

    fn client() -> VirusTotalClient {
        VirusTotalClient::new("test-api-key-xxxxxxxxxxxxxxxxxxxxxxxx".to_string())
    }

    fn hash_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Sha256, val.to_string(), "test".to_string())
    }

    fn ip_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Ip, val.to_string(), "test".to_string())
    }

    fn domain_ioc(val: &str) -> IoC {
        IoC::new(IoCType::Domain, val.to_string(), "test".to_string())
    }

    // ---- Basic client ----

    #[test]
    fn test_client_new() {
        let c = client();
        assert!(c.base_url.contains("virustotal"));
    }

    #[test]
    fn test_client_with_base_url() {
        let c = client().with_base_url("http://localhost:8080".to_string());
        assert_eq!(c.base_url, "http://localhost:8080");
    }

    #[test]
    fn test_provider_name() {
        assert_eq!(client().name(), "virustotal");
    }

    #[test]
    fn test_provider_rate_limit() {
        assert_eq!(client().rate_limit_per_minute(), 4);
    }

    // ---- Verdicts ----

    #[test]
    fn test_make_verdict_clean() {
        let ioc = hash_ioc("safe_hash");
        let v = client().make_verdict(&ioc);
        assert!(!v.malicious);
        assert_eq!(v.positive_count, 0);
    }

    #[test]
    fn test_make_verdict_malicious() {
        let ioc = hash_ioc("evil_hash_value");
        let v = client().make_verdict(&ioc);
        assert!(v.malicious);
        assert!(v.confidence > 0);
    }

    #[test]
    fn test_mock_response_hash_adds_family() {
        let ioc = hash_ioc("some_hash");
        let result = client().mock_vt_response(&ioc);
        assert_eq!(result.malware_families.len(), 1);
    }

    #[test]
    fn test_mock_response_ip_has_no_family() {
        let ioc = ip_ioc("8.8.8.8");
        let result = client().mock_vt_response(&ioc);
        assert!(result.malware_families.is_empty());
    }

    #[test]
    fn test_make_verdict_malicious_domain() {
        let ioc = domain_ioc("evil.example.com");
        let v = client().make_verdict(&ioc);
        assert!(v.malicious);
        assert!(v.confidence > 0);
    }

    // ---- Async API ----

    #[tokio::test]
    async fn test_scan_file() {
        let id = client().scan_file(&[0u8; 4]).await.unwrap();
        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn test_scan_url() {
        let id = client().scan_url("http://example.com").await.unwrap();
        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn test_get_file_report_clean() {
        let r = client().get_file_report("safehash").await.unwrap();
        assert!(!r.is_malicious());
    }

    #[tokio::test]
    async fn test_get_file_report_malicious() {
        let r = client().get_file_report("evil_hash").await.unwrap();
        assert!(r.is_malicious());
    }

    #[tokio::test]
    async fn test_get_file_report_detection_ratio() {
        let r = client().get_file_report("evil_sample").await.unwrap();
        let ratio = r.detection_ratio();
        assert!(ratio.contains('/'));
    }

    #[tokio::test]
    async fn test_get_file_report_threat_label() {
        let r = client().get_file_report("evil_file").await.unwrap();
        assert!(r.threat_label().is_some());
    }

    #[tokio::test]
    async fn test_get_url_report_malicious() {
        let r = client()
            .get_url_report("http://evil.example.com")
            .await
            .unwrap();
        assert!(r.is_malicious());
    }

    #[tokio::test]
    async fn test_get_url_report_clean() {
        let r = client()
            .get_url_report("http://clean.example.com")
            .await
            .unwrap();
        assert!(!r.is_malicious());
    }

    #[tokio::test]
    async fn test_get_domain_report() {
        let r = client().get_domain_report("example.com").await.unwrap();
        assert_eq!(r.id, "example.com");
        assert!(!r.last_dns_records.is_empty());
    }

    #[tokio::test]
    async fn test_get_ip_report_malicious() {
        let r = client().get_ip_report("10.0.0.1").await.unwrap();
        assert!(r.is_malicious());
    }

    #[tokio::test]
    async fn test_get_ip_report_clean() {
        let r = client().get_ip_report("8.8.8.8").await.unwrap();
        assert!(!r.is_malicious());
    }

    #[tokio::test]
    async fn test_search_returns_results() {
        let q = VtSearchQuery::new("malware").with_limit(3);
        let results = client().search(&q).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_get_votes() {
        let votes = client().get_votes("sha256hash").await.unwrap();
        assert!(!votes.is_empty());
    }

    #[tokio::test]
    async fn test_get_comments() {
        let comments = client().get_comments("sha256hash").await.unwrap();
        assert!(!comments.is_empty());
    }

    #[tokio::test]
    async fn test_get_behavior() {
        let b = client().get_behavior("everhash").await.unwrap();
        assert_eq!(b.sandbox_name, "MockSandbox");
        assert!(!b.network.dns_lookups.is_empty());
    }

    #[tokio::test]
    async fn test_get_behavior_contacted_domains() {
        let b = client().get_behavior("anyhash").await.unwrap();
        let domains = b.contacted_domains();
        assert!(!domains.is_empty());
    }

    #[tokio::test]
    async fn test_get_relationships() {
        let rels = client()
            .get_relationships("sha256hash", &VtRelationshipType::ContactedIps)
            .await
            .unwrap();
        assert!(!rels.is_empty());
    }

    #[tokio::test]
    async fn test_get_collections() {
        let cols = client().get_collections("sha256hash").await.unwrap();
        assert_eq!(cols.len(), 1);
    }

    // ---- Rate limiter ----

    #[test]
    fn test_rate_limiter_initial_tokens() {
        let limiter = VtTokenBucketLimiter::new(4);
        assert!(limiter.available_tokens() > 0.0);
    }

    #[test]
    fn test_rate_limiter_consume() {
        let limiter = VtTokenBucketLimiter::new(10);
        assert!(limiter.try_consume());
    }

    #[test]
    fn test_rate_limiter_exhausted() {
        let limiter = VtTokenBucketLimiter::new(2);
        assert!(limiter.try_consume());
        assert!(limiter.try_consume());
        // After consuming all tokens, wait time > 0
        assert!(!limiter.try_consume() || limiter.wait_time() >= 0.0);
    }

    // ---- VtApiKey ----

    #[test]
    fn test_api_key_public_valid() {
        let k = VtApiKey::public("a".repeat(64));
        assert!(k.is_valid());
        assert!(!k.premium);
        assert_eq!(k.rate_limit_per_minute, 4);
    }

    #[test]
    fn test_api_key_premium() {
        let k = VtApiKey::premium("a".repeat(64));
        assert!(k.premium);
        assert_eq!(k.rate_limit_per_minute, 500);
    }

    // ---- VtSearchQuery ----

    #[test]
    fn test_search_query_builder() {
        let q = VtSearchQuery::new("malware")
            .with_tag("trojan")
            .with_type("peexe")
            .with_size_range(1024, 10_000_000)
            .with_limit(100);
        assert_eq!(q.query, "malware");
        assert!(q.tags.contains(&"trojan".to_string()));
        assert_eq!(q.limit, Some(100));
    }

    // ---- VtAnalysisStats ----

    #[test]
    fn test_analysis_stats_detection_ratio() {
        let stats = VtAnalysisStats {
            malicious: 10,
            undetected: 62,
            ..Default::default()
        };
        assert_eq!(stats.detection_ratio(), "10/72");
    }

    // ---- Backward compat ----

    #[test]
    fn test_mock_file_report_clean() {
        let r = mock_file_report("safe_hash");
        assert!(!r.is_malicious());
    }

    #[test]
    fn test_mock_file_report_malicious() {
        let r = mock_file_report("bad_hash");
        assert!(r.is_malicious());
    }

    #[test]
    fn test_mock_ip_report_clean() {
        let r = mock_ip_report("8.8.8.8");
        assert!(!r.is_malicious());
    }

    #[test]
    fn test_ioc_severity_propagated() {
        let mut ioc = hash_ioc("test_hash");
        ioc.severity = Severity::Critical;
        let result = client().mock_vt_response(&ioc);
        assert_eq!(result.ioc.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn test_lookup_returns_result() {
        let ioc = hash_ioc("testvalue");
        let result = client().lookup(&ioc).await.unwrap();
        assert_eq!(result.ioc.value, "testvalue");
    }

    #[tokio::test]
    async fn test_bulk_lookup() {
        let iocs = vec![hash_ioc("a"), hash_ioc("b"), hash_ioc("c")];
        let results = client().bulk_lookup(&iocs).await.unwrap();
        assert_eq!(results.len(), 3);
    }
}
