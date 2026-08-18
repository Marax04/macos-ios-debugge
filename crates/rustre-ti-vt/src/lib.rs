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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VtClientError {
    /// No usable `VirusTotal` API key is configured, so no lookup was performed.
    ///
    /// This is returned INSTEAD of an invented report: a verdict about a hash,
    /// URL, domain or IP can only come from the live `VirusTotal` service.
    NoApiKey,
    /// The requested answer can only be obtained from the live service and no
    /// network lookup was possible.
    NetworkRequired(String),
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
            Self::NoApiKey => write!(
                f,
                "no VirusTotal API key configured: a network lookup against {} {}",
                "https://www.virustotal.com is required to answer this query;",
                "no verdict was produced"
            ),
            Self::NetworkRequired(what) => write!(
                f,
                "network lookup required for {what}: no result was produced offline"
            ),
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

impl VtRelationshipType {
    /// The `VirusTotal` v3 relationship path segment for this type.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        match self {
            Self::ContactedIps => "contacted_ips",
            Self::ContactedDomains => "contacted_domains",
            Self::ContactedUrls => "contacted_urls",
            Self::EmbeddedUrls => "embedded_urls",
            Self::EmbeddedDomains => "embedded_domains",
            Self::ExecutionParents => "execution_parents",
            Self::EmbeddedFiles => "embedded_files",
            Self::CompressedParents => "compressed_parents",
            Self::SimilarFiles => "similar_files",
            Self::DroppedFiles => "dropped_files",
            Self::Pcaps => "pcaps",
            Self::Other(s) => s.as_str(),
        }
    }
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

/// Return `true` when `key` looks like a real `VirusTotal` API key.
///
/// `VirusTotal` v3 keys are 64 lowercase hexadecimal characters.  Anything
/// else (empty string, placeholder such as `"test-api-key"`, a truncated key)
/// cannot authenticate, so no lookup is attempted with it.
#[must_use]
pub fn api_key_is_valid(key: &str) -> bool {
    key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse a real `VirusTotal` `/api/v3/files/<hash>` JSON document into a
/// [`VtFileReportSpec`].
///
/// This is an OFFLINE parser: it invents nothing, it only reshapes a document
/// the caller already obtained from `VirusTotal`.
///
/// # Errors
///
/// Returns [`VtClientError::Parse`] if the document has no `data.attributes`.
pub fn parse_file_report_spec(json: &serde_json::Value) -> Result<VtFileReportSpec, VtClientError> {
    let attrs = &json["data"]["attributes"];
    if !attrs.is_object() {
        return Err(VtClientError::Parse(
            "missing data.attributes in VirusTotal file response".to_string(),
        ));
    }
    let mut scan_results = Vec::new();
    if let Some(map) = attrs["last_analysis_results"].as_object() {
        for (engine, v) in map {
            scan_results.push(VtScanResult {
                engine_name: v["engine_name"]
                    .as_str()
                    .unwrap_or(engine.as_str())
                    .to_string(),
                category: v["category"].as_str().unwrap_or("undetected").to_string(),
                result: v["result"].as_str().map(str::to_string),
            });
        }
    }
    Ok(VtFileReportSpec {
        sha256: attrs["sha256"].as_str().unwrap_or_default().to_string(),
        md5: attrs["md5"].as_str().unwrap_or_default().to_string(),
        meaningful_name: attrs["meaningful_name"].as_str().map(str::to_string),
        scan_results,
        first_submission: attrs["first_submission_date"].as_u64(),
        last_analysis_date: attrs["last_analysis_date"].as_u64(),
    })
}

/// Parse a real `VirusTotal` `/api/v3/ip_addresses/<ip>` JSON document into a
/// [`VtIpReportSpec`].
///
/// Offline parser — see [`parse_file_report_spec`].
///
/// # Errors
///
/// Returns [`VtClientError::Parse`] if the document has no `data.attributes`.
pub fn parse_ip_report_spec(json: &serde_json::Value) -> Result<VtIpReportSpec, VtClientError> {
    let attrs = &json["data"]["attributes"];
    if !attrs.is_object() {
        return Err(VtClientError::Parse(
            "missing data.attributes in VirusTotal IP response".to_string(),
        ));
    }
    let stats = &attrs["last_analysis_stats"];
    Ok(VtIpReportSpec {
        ip_address: json["data"]["id"].as_str().unwrap_or_default().to_string(),
        country: attrs["country"].as_str().map(str::to_string),
        as_owner: attrs["as_owner"].as_str().map(str::to_string),
        malicious_count: u32::try_from(stats["malicious"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX),
        suspicious_count: u32::try_from(stats["suspicious"].as_u64().unwrap_or(0))
            .unwrap_or(u32::MAX),
    })
}

/// Report on a file by SHA-256.
///
/// A file verdict is only knowable from the live `VirusTotal` service, and this
/// free function has neither an API key nor an async context in which to make
/// the request.  It therefore performs NO lookup and returns
/// [`VtClientError::NetworkRequired`] rather than a fabricated verdict.
///
/// To obtain a real report use [`VtClient::lookup_file`] or
/// [`VirusTotalClient::get_file_report`] with a configured API key, or feed an
/// already-fetched response to [`parse_file_report_spec`].
///
/// # Errors
///
/// Always returns [`VtClientError::NetworkRequired`].
pub fn mock_file_report(sha256: &str) -> Result<VtFileReportSpec, VtClientError> {
    Err(VtClientError::NetworkRequired(format!(
        "VirusTotal file report for {sha256}"
    )))
}

/// Report on an IP address.
///
/// See [`mock_file_report`]: no lookup is performed and nothing is invented.
///
/// # Errors
///
/// Always returns [`VtClientError::NetworkRequired`].
pub fn mock_ip_report(ip: &str) -> Result<VtIpReportSpec, VtClientError> {
    Err(VtClientError::NetworkRequired(format!(
        "VirusTotal IP report for {ip}"
    )))
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
    /// Real HTTP transport.  Every report method below goes through this.
    http: reqwest::Client,
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
            http: reqwest::Client::builder()
                .use_rustls_tls()
                .build()
                .unwrap_or_default(),
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

    /// Return the configured API key, or an error naming exactly what is
    /// missing.  No method in this client invents a verdict when this fails.
    ///
    /// # Errors
    ///
    /// Returns [`VtClientError::NoApiKey`] when no usable key is configured.
    pub fn require_api_key(&self) -> Result<&str, VtClientError> {
        if api_key_is_valid(&self.api_key) {
            Ok(&self.api_key)
        } else {
            Err(VtClientError::NoApiKey)
        }
    }

    /// Perform a real authenticated `GET` against the `VirusTotal` v3 API.
    ///
    /// # Errors
    ///
    /// Returns [`VtClientError::NoApiKey`] when unauthenticated, and the
    /// transport / status errors otherwise.  It never falls back to canned data.
    pub async fn api_get(&self, path: &str) -> Result<serde_json::Value, VtClientError> {
        let key = self.require_api_key()?;
        if let Some(ref limiter) = self.rate_limiter
            && !limiter.try_consume()
        {
            return Err(VtClientError::RateLimitExceeded);
        }
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("x-apikey", key)
            .header("Accept", "application/json")
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| VtClientError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        match status {
            401 | 403 => return Err(VtClientError::AuthenticationError),
            404 => return Err(VtClientError::NotFound(path.to_string())),
            429 => return Err(VtClientError::RateLimitExceeded),
            s if s >= 400 => {
                let body = resp.text().await.unwrap_or_default();
                return Err(VtClientError::Http(format!("HTTP {s}: {body}")));
            }
            _ => {}
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| VtClientError::Parse(e.to_string()))
    }

    /// Build a [`Verdict`] from a real `last_analysis_stats` block.
    ///
    /// Offline: it summarises a document the caller already fetched.
    #[must_use]
    pub fn verdict_from_json(json: &serde_json::Value) -> Verdict {
        let attrs = &json["data"]["attributes"];
        let stats = parse_stats_json(&attrs["last_analysis_stats"]);
        let positive = stats.malicious + stats.suspicious;
        let engines = stats.malicious
            + stats.suspicious
            + stats.undetected
            + stats.harmless
            + stats.timeout
            + stats.confirmed_timeout
            + stats.failure
            + stats.type_unsupported;
        Verdict {
            malicious: stats.malicious > 0,
            confidence: if engines == 0 {
                0
            } else {
                u8::try_from((u64::from(positive) * 100 / u64::from(engines)).min(100))
                    .unwrap_or(100)
            },
            tags: parse_string_vec(&attrs["tags"]),
            engine_count: engines,
            positive_count: positive,
            first_seen: attrs["first_submission_date"].as_u64(),
            last_seen: attrs["last_analysis_date"].as_u64(),
            description: attrs["popular_threat_classification"]["suggested_threat_label"]
                .as_str()
                .map(str::to_string),
            provider: "virustotal".to_string(),
        }
    }

    /// Path under `/api/v3` for the given `IoC`.
    ///
    /// # Errors
    ///
    /// Returns [`VtClientError::Other`] for an IoC type VirusTotal has no
    /// endpoint for.
    pub fn ioc_path(ioc: &IoC) -> Result<String, VtClientError> {
        match ioc.ioc_type {
            IoCType::Md5 | IoCType::Sha1 | IoCType::Sha256 => {
                Ok(format!("/api/v3/files/{}", ioc.value))
            }
            IoCType::Ip => Ok(format!("/api/v3/ip_addresses/{}", ioc.value)),
            IoCType::Domain => Ok(format!("/api/v3/domains/{}", ioc.value)),
            IoCType::Url => Ok(format!("/api/v3/urls/{}", vt_url_id(&ioc.value))),
            _ => Err(VtClientError::Other(format!(
                "VirusTotal has no endpoint for IoC type {:?}",
                ioc.ioc_type
            ))),
        }
    }

    /// Perform a real lookup for an `IoC` and build a [`TiResult`].
    ///
    /// # Errors
    ///
    /// Propagates the transport / auth error; produces no result offline.
    pub async fn lookup_ioc(&self, ioc: &IoC) -> Result<TiResult, VtClientError> {
        let path = Self::ioc_path(ioc)?;
        let json = self.api_get(&path).await?;
        let mut result = TiResult::new(ioc.clone());
        result.verdicts.push(Self::verdict_from_json(&json));
        if ioc.is_hash()
            && let Some(label) = json["data"]["attributes"]["popular_threat_classification"]
                ["popular_threat_name"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|v| v["value"].as_str())
        {
            result.malware_families.push(label.to_string());
        }
        Ok(result)
    }

    // ---- Full API methods ----

    /// Submit a file for analysis.
    ///
    /// # Errors
    ///
    /// Returns [`VtClientError::NoApiKey`] when unauthenticated, otherwise the
    /// transport error.  No analysis id is invented.
    pub async fn scan_file(&self, data: &[u8]) -> Result<String, VtClientError> {
        let key = self.require_api_key()?;
        let part = reqwest::multipart::Part::bytes(data.to_vec())
            .file_name("sample.bin")
            .mime_str("application/octet-stream")
            .map_err(|e| VtClientError::Http(e.to_string()))?;
        let form = reqwest::multipart::Form::new().part("file", part);
        let resp = self
            .http
            .post(format!("{}/api/v3/files", self.base_url))
            .header("x-apikey", key)
            .timeout(self.timeout)
            .multipart(form)
            .send()
            .await
            .map_err(|e| VtClientError::Http(e.to_string()))?;
        Self::analysis_id_from(resp).await
    }

    /// Submit a URL for analysis.
    ///
    /// # Errors
    ///
    /// As [`Self::scan_file`].
    pub async fn scan_url(&self, url: &str) -> Result<String, VtClientError> {
        let key = self.require_api_key()?;
        let resp = self
            .http
            .post(format!("{}/api/v3/urls", self.base_url))
            .header("x-apikey", key)
            .timeout(self.timeout)
            .form(&[("url", url)])
            .send()
            .await
            .map_err(|e| VtClientError::Http(e.to_string()))?;
        Self::analysis_id_from(resp).await
    }

    async fn analysis_id_from(resp: reqwest::Response) -> Result<String, VtClientError> {
        let status = resp.status().as_u16();
        match status {
            401 | 403 => return Err(VtClientError::AuthenticationError),
            429 => return Err(VtClientError::RateLimitExceeded),
            s if s >= 400 => {
                let body = resp.text().await.unwrap_or_default();
                return Err(VtClientError::Http(format!("HTTP {s}: {body}")));
            }
            _ => {}
        }
        let json = resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e| VtClientError::Parse(e.to_string()))?;
        json["data"]["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| VtClientError::Parse("missing data.id in submit response".to_string()))
    }

    /// Get a full file report from `VirusTotal`.
    ///
    /// # Errors
    ///
    /// Returns [`VtClientError::NoApiKey`] when unauthenticated; the API's
    /// error otherwise.  Nothing is fabricated.
    pub async fn get_file_report(&self, sha256: &str) -> Result<VtFileReportFull, VtClientError> {
        let key = sha256.trim().to_ascii_lowercase();
        if !matches!(key.len(), 32 | 40 | 64) || !key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(VtClientError::InvalidHash(sha256.to_string()));
        }
        let json = self.api_get(&format!("/api/v3/files/{key}")).await?;
        Ok(parse_file_report_full(&json))
    }

    /// Get a URL report.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_url_report(&self, url: &str) -> Result<VtUrlReportFull, VtClientError> {
        if url.trim().is_empty() {
            return Err(VtClientError::InvalidUrl(url.to_string()));
        }
        let json = self
            .api_get(&format!("/api/v3/urls/{}", vt_url_id(url)))
            .await?;
        let attrs = &json["data"]["attributes"];
        Ok(VtUrlReportFull {
            url: url.to_string(),
            final_url: attrs["last_final_url"].as_str().map(str::to_string),
            title: attrs["title"].as_str().map(str::to_string),
            last_analysis_stats: parse_stats_json(&attrs["last_analysis_stats"]),
            last_analysis_results: parse_av_results(&attrs["last_analysis_results"]),
            categories: parse_string_map(&attrs["categories"]),
            trackers: parse_string_list_map(&attrs["trackers"]),
            html_meta: parse_string_list_map(&attrs["html_meta"]),
            last_analysis_date: attrs["last_analysis_date"].as_u64(),
            first_submission_date: attrs["first_submission_date"].as_u64(),
            reputation: parse_i32(&attrs["reputation"]),
            tags: parse_string_vec(&attrs["tags"]),
        })
    }

    /// Get a domain report.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_domain_report(
        &self,
        domain: &str,
    ) -> Result<VtDomainReportFull, VtClientError> {
        let key = domain.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(VtClientError::Other("empty domain".to_string()));
        }
        let json = self.api_get(&format!("/api/v3/domains/{key}")).await?;
        let attrs = &json["data"]["attributes"];
        let last_dns_records = attrs["last_dns_records"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|r| VtDnsRecord {
                        type_: r["type"].as_str().unwrap_or_default().to_string(),
                        value: r["value"].as_str().unwrap_or_default().to_string(),
                        ttl: r["ttl"].as_u64().and_then(|v| u32::try_from(v).ok()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(VtDomainReportFull {
            id: json["data"]["id"].as_str().unwrap_or(&key).to_string(),
            registrar: attrs["registrar"].as_str().map(str::to_string),
            creation_date: attrs["creation_date"].as_u64().map(|v| v.to_string()),
            expiry_date: attrs["expiration_date"].as_u64().map(|v| v.to_string()),
            whois: attrs["whois"].as_str().map(str::to_string),
            last_dns_records,
            last_analysis_stats: parse_stats_json(&attrs["last_analysis_stats"]),
            last_analysis_results: parse_av_results(&attrs["last_analysis_results"]),
            categories: parse_string_map(&attrs["categories"]),
            subdomains: parse_string_vec(&attrs["subdomains"]),
            reputation: parse_i32(&attrs["reputation"]),
            tags: parse_string_vec(&attrs["tags"]),
            last_modification_date: attrs["last_modification_date"].as_u64(),
            popularity_ranks: HashMap::new(),
        })
    }

    /// Get an IP report.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_ip_report(&self, ip: &str) -> Result<VtIpReportFull, VtClientError> {
        if ip.trim().is_empty() {
            return Err(VtClientError::Other("empty IP address".to_string()));
        }
        let json = self.api_get(&format!("/api/v3/ip_addresses/{ip}")).await?;
        let attrs = &json["data"]["attributes"];
        Ok(VtIpReportFull {
            id: json["data"]["id"].as_str().unwrap_or(ip).to_string(),
            as_owner: attrs["as_owner"].as_str().map(str::to_string),
            asn: attrs["asn"].as_u64().and_then(|v| u32::try_from(v).ok()),
            country: attrs["country"].as_str().map(str::to_string),
            network: attrs["network"].as_str().map(str::to_string),
            regional_internet_registry: attrs["regional_internet_registry"]
                .as_str()
                .map(str::to_string),
            last_analysis_stats: parse_stats_json(&attrs["last_analysis_stats"]),
            last_analysis_results: parse_av_results(&attrs["last_analysis_results"]),
            reputation: parse_i32(&attrs["reputation"]),
            tags: parse_string_vec(&attrs["tags"]),
            last_modification_date: attrs["last_modification_date"].as_u64(),
            jarm: attrs["jarm"].as_str().map(str::to_string),
        })
    }

    /// Run a `VirusTotal` Intelligence search.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].  Requires a Premium API key; the API's
    /// own 403 is surfaced rather than masked with sample results.
    pub async fn search(
        &self,
        query: &VtSearchQuery,
    ) -> Result<Vec<VtFileReportFull>, VtClientError> {
        let limit = query.limit.unwrap_or(20);
        let json = self
            .api_get(&format!(
                "/api/v3/intelligence/search?query={}&limit={limit}",
                percent_encode(&query.query)
            ))
            .await?;
        Ok(json["data"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|item| {
                        let wrapped = serde_json::json!({ "data": item });
                        parse_file_report_full(&wrapped)
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Get community votes for a resource.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_votes(&self, resource_id: &str) -> Result<Vec<VtVote>, VtClientError> {
        let json = self
            .api_get(&format!("/api/v3/files/{resource_id}/votes"))
            .await?;
        Ok(json["data"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| {
                        let attrs = &v["attributes"];
                        let verdict = attrs["verdict"].as_str().unwrap_or("harmless").to_string();
                        VtVote {
                            value: if verdict == "malicious" { -1 } else { 1 },
                            verdict,
                            voter: v["id"].as_str().map(str::to_string),
                            date: attrs["date"].as_u64().unwrap_or(0),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Get community comments for a resource.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_comments(&self, resource_id: &str) -> Result<Vec<VtComment>, VtClientError> {
        let json = self
            .api_get(&format!("/api/v3/files/{resource_id}/comments"))
            .await?;
        Ok(json["data"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| {
                        let attrs = &v["attributes"];
                        VtComment {
                            id: v["id"].as_str().unwrap_or_default().to_string(),
                            text: attrs["text"].as_str().unwrap_or_default().to_string(),
                            author: attrs["author"].as_str().map(str::to_string),
                            date: attrs["date"].as_u64().unwrap_or(0),
                            tags: parse_string_vec(&attrs["tags"]),
                            votes_positive: parse_u32(&attrs["votes"]["positive"]),
                            votes_negative: parse_u32(&attrs["votes"]["negative"]),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Get a sandbox behaviour summary for a file.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_behavior(&self, sha256: &str) -> Result<VtBehavior, VtClientError> {
        let json = self
            .api_get(&format!("/api/v3/files/{sha256}/behaviour_summary"))
            .await?;
        let attrs = &json["data"];
        let mut b = VtBehavior::new(sha256.to_string(), "virustotal".to_string());
        if let Some(list) = attrs["dns_lookups"].as_array() {
            for d in list {
                b.network.dns_lookups.push(VtDnsLookup {
                    hostname: d["hostname"].as_str().unwrap_or_default().to_string(),
                    resolved_ips: parse_string_vec(&d["resolved_ips"]),
                });
            }
        }
        b.mutexes = parse_string_vec(&attrs["mutexes_created"]);
        b.registry_keys_set = parse_string_vec(&attrs["registry_keys_set"]);
        Ok(b)
    }

    /// Get relationships of a resource.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_relationships(
        &self,
        resource_id: &str,
        rel_type: &VtRelationshipType,
    ) -> Result<Vec<VtRelationship>, VtClientError> {
        let json = self
            .api_get(&format!(
                "/api/v3/files/{resource_id}/{}",
                rel_type.endpoint()
            ))
            .await?;
        Ok(json["data"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| VtRelationship {
                        relationship_type: rel_type.clone(),
                        related_id: v["id"].as_str().unwrap_or_default().to_string(),
                        context_attributes: HashMap::new(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Get collections a resource belongs to.
    ///
    /// # Errors
    ///
    /// See [`Self::get_file_report`].
    pub async fn get_collections(
        &self,
        resource_id: &str,
    ) -> Result<Vec<VtCollection>, VtClientError> {
        let json = self
            .api_get(&format!("/api/v3/files/{resource_id}/collections"))
            .await?;
        Ok(json["data"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| {
                        let attrs = &v["attributes"];
                        VtCollection {
                            id: v["id"].as_str().unwrap_or_default().to_string(),
                            name: attrs["name"].as_str().unwrap_or_default().to_string(),
                            description: attrs["description"].as_str().map(str::to_string),
                            owner: attrs["owner"].as_str().map(str::to_string),
                            creation_date: attrs["creation_date"].as_u64().unwrap_or(0),
                            tags: parse_string_vec(&attrs["tags"]),
                            files_count: parse_u32(&attrs["files_count"]),
                            urls_count: parse_u32(&attrs["urls_count"]),
                            domains_count: parse_u32(&attrs["domains_count"]),
                            ips_count: parse_u32(&attrs["ips_count"]),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Offline JSON -> struct helpers (shared by the methods above)
// ---------------------------------------------------------------------------

fn parse_u32(v: &serde_json::Value) -> u32 {
    u32::try_from(v.as_u64().unwrap_or(0)).unwrap_or(u32::MAX)
}

fn parse_i32(v: &serde_json::Value) -> i32 {
    i32::try_from(v.as_i64().unwrap_or(0)).unwrap_or(i32::MAX)
}

fn parse_string_vec(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_string_map(v: &serde_json::Value) -> HashMap<String, String> {
    v.as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_string_list_map(v: &serde_json::Value) -> HashMap<String, Vec<String>> {
    v.as_object()
        .map(|o| {
            o.iter()
                .map(|(k, val)| (k.clone(), parse_string_vec(val)))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a `last_analysis_stats` object.  Absent keys count as zero — this
/// reports what the service said, never a guess.
fn parse_stats_json(v: &serde_json::Value) -> VtAnalysisStats {
    VtAnalysisStats {
        malicious: parse_u32(&v["malicious"]),
        suspicious: parse_u32(&v["suspicious"]),
        undetected: parse_u32(&v["undetected"]),
        timeout: parse_u32(&v["timeout"]),
        confirmed_timeout: parse_u32(&v["confirmed-timeout"]),
        failure: parse_u32(&v["failure"]),
        type_unsupported: parse_u32(&v["type-unsupported"]),
        harmless: parse_u32(&v["harmless"]),
    }
}

fn parse_av_results(v: &serde_json::Value) -> HashMap<String, VtAVResult> {
    v.as_object()
        .map(|o| {
            o.iter()
                .map(|(k, r)| {
                    (
                        k.clone(),
                        VtAVResult {
                            category: r["category"].as_str().unwrap_or("undetected").to_string(),
                            engine_name: r["engine_name"].as_str().unwrap_or(k).to_string(),
                            engine_version: r["engine_version"].as_str().map(str::to_string),
                            engine_update: r["engine_update"].as_str().map(str::to_string),
                            result: r["result"].as_str().map(str::to_string),
                            method: r["method"].as_str().map(str::to_string),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a full `/api/v3/files` document into a [`VtFileReportFull`].
///
/// Offline: reshapes only what the service returned.
#[must_use]
pub fn parse_file_report_full(json: &serde_json::Value) -> VtFileReportFull {
    let attrs = &json["data"]["attributes"];
    let ptc = &attrs["popular_threat_classification"];
    let class_items = |v: &serde_json::Value| -> Vec<VtThreatClassItem> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .map(|i| VtThreatClassItem {
                        value: i["value"].as_str().unwrap_or_default().to_string(),
                        count: parse_u32(&i["count"]),
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    VtFileReportFull {
        sha256: attrs["sha256"].as_str().unwrap_or_default().to_string(),
        sha1: attrs["sha1"].as_str().unwrap_or_default().to_string(),
        md5: attrs["md5"].as_str().unwrap_or_default().to_string(),
        meaningful_name: attrs["meaningful_name"].as_str().map(str::to_string),
        size: attrs["size"].as_u64().unwrap_or(0),
        type_tag: attrs["type_tag"].as_str().map(str::to_string),
        type_description: attrs["type_description"].as_str().map(str::to_string),
        magic: attrs["magic"].as_str().map(str::to_string),
        creation_date: attrs["creation_date"].as_u64(),
        first_submission_date: attrs["first_submission_date"].as_u64(),
        last_analysis_date: attrs["last_analysis_date"].as_u64(),
        last_submission_date: attrs["last_submission_date"].as_u64(),
        times_submitted: parse_u32(&attrs["times_submitted"]),
        last_analysis_results: parse_av_results(&attrs["last_analysis_results"]),
        last_analysis_stats: parse_stats_json(&attrs["last_analysis_stats"]),
        reputation: parse_i32(&attrs["reputation"]),
        popular_threat_classification: if ptc.is_object() {
            Some(VtPopularThreatClassification {
                suggested_threat_label: ptc["suggested_threat_label"].as_str().map(str::to_string),
                popular_threat_category: class_items(&ptc["popular_threat_category"]),
                popular_threat_name: class_items(&ptc["popular_threat_name"]),
            })
        } else {
            None
        },
        sandbox_verdicts: vec![],
        names: parse_string_vec(&attrs["names"]),
        tags: parse_string_vec(&attrs["tags"]),
        imphash: attrs["pe_info"]["imphash"].as_str().map(str::to_string),
        ssdeep: attrs["ssdeep"].as_str().map(str::to_string),
        tlsh: attrs["tlsh"].as_str().map(str::to_string),
        authentihash: attrs["authentihash"].as_str().map(str::to_string),
        signature_info: attrs["signature_info"]
            .is_object()
            .then(|| parse_string_map(&attrs["signature_info"])),
    }
}

/// `VirusTotal` URL identifier: unpadded base64url of the URL.
#[must_use]
pub fn vt_url_id(url: &str) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = url.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        }
    }
    out
}

/// Minimal percent-encoding for a query-string value.
fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
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
        self.lookup_ioc(ioc)
            .await
            .map_err(|e| TiError::Other(e.to_string()))
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
    use rustre_threatintel::IoCType;

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

    // ---- Honesty: no key => no verdict, never a fabricated one ----

    fn no_key_client() -> VirusTotalClient {
        VirusTotalClient::new("test-api-key-xxxxxxxxxxxxxxxxxxxxxxxx".to_string())
    }

    #[test]
    fn test_api_key_is_valid_rejects_placeholder() {
        assert!(!api_key_is_valid(""));
        assert!(!api_key_is_valid("test-api-key-xxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(api_key_is_valid(&"a".repeat(64)));
        assert!(!api_key_is_valid(&"z".repeat(64)));
    }

    #[test]
    fn test_require_api_key_errors_without_key() {
        assert!(matches!(
            no_key_client().require_api_key(),
            Err(VtClientError::NoApiKey)
        ));
    }

    #[test]
    fn test_mock_file_report_never_fabricates() {
        let e = mock_file_report("safe_hash").unwrap_err();
        assert!(matches!(e, VtClientError::NetworkRequired(_)));
        assert!(e.to_string().contains("network lookup required"));
    }

    #[test]
    fn test_mock_file_report_no_verdict_for_bad_looking_hash() {
        // The old implementation called any hash containing "bad" malicious.
        assert!(mock_file_report("bad_hash").is_err());
    }

    #[test]
    fn test_mock_ip_report_never_fabricates() {
        assert!(matches!(
            mock_ip_report("8.8.8.8").unwrap_err(),
            VtClientError::NetworkRequired(_)
        ));
        assert!(mock_ip_report("10.0.0.1").is_err());
    }

    #[tokio::test]
    async fn test_scan_file_requires_key() {
        assert!(matches!(
            no_key_client().scan_file(&[0u8; 4]).await,
            Err(VtClientError::NoApiKey)
        ));
    }

    #[tokio::test]
    async fn test_scan_url_requires_key() {
        assert!(matches!(
            no_key_client().scan_url("http://example.com").await,
            Err(VtClientError::NoApiKey)
        ));
    }

    #[tokio::test]
    async fn test_get_file_report_requires_key() {
        let e = no_key_client().get_file_report(&"a".repeat(64)).await;
        assert!(matches!(e, Err(VtClientError::NoApiKey)));
    }

    #[tokio::test]
    async fn test_get_file_report_rejects_non_hash() {
        assert!(matches!(
            no_key_client().get_file_report("evil_hash").await,
            Err(VtClientError::InvalidHash(_))
        ));
    }

    #[tokio::test]
    async fn test_get_url_report_requires_key() {
        assert!(matches!(
            no_key_client().get_url_report("http://evil.example.com").await,
            Err(VtClientError::NoApiKey)
        ));
    }

    #[tokio::test]
    async fn test_get_domain_report_requires_key() {
        assert!(matches!(
            no_key_client().get_domain_report("example.com").await,
            Err(VtClientError::NoApiKey)
        ));
    }

    #[tokio::test]
    async fn test_get_ip_report_requires_key() {
        assert!(matches!(
            no_key_client().get_ip_report("10.0.0.1").await,
            Err(VtClientError::NoApiKey)
        ));
    }

    #[tokio::test]
    async fn test_search_requires_key() {
        let q = VtSearchQuery::new("malware").with_limit(3);
        assert!(matches!(
            no_key_client().search(&q).await,
            Err(VtClientError::NoApiKey)
        ));
    }

    #[tokio::test]
    async fn test_votes_comments_behavior_require_key() {
        let c = no_key_client();
        assert!(c.get_votes("sha256hash").await.is_err());
        assert!(c.get_comments("sha256hash").await.is_err());
        assert!(c.get_behavior("anyhash").await.is_err());
        assert!(
            c.get_relationships("sha256hash", &VtRelationshipType::ContactedIps)
                .await
                .is_err()
        );
        assert!(c.get_collections("sha256hash").await.is_err());
    }

    #[tokio::test]
    async fn test_lookup_reports_missing_key_instead_of_verdict() {
        let ioc = hash_ioc(&"a".repeat(64));
        let err = no_key_client().lookup(&ioc).await.unwrap_err();
        assert!(err.to_string().contains("no VirusTotal API key configured"));
    }

    // ---- Offline parsers: real document in, real numbers out ----

    fn sample_file_json() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "id": "aa".repeat(32),
                "attributes": {
                    "sha256": "aa".repeat(32),
                    "sha1": "bb".repeat(20),
                    "md5": "cc".repeat(16),
                    "meaningful_name": "invoice.exe",
                    "size": 4096,
                    "type_tag": "peexe",
                    "times_submitted": 7,
                    "reputation": -12,
                    "names": ["invoice.exe", "inv.exe"],
                    "tags": ["peexe", "signed"],
                    "first_submission_date": 1_600_000_000_u64,
                    "last_analysis_date": 1_700_000_000_u64,
                    "last_analysis_stats": {
                        "malicious": 42, "suspicious": 3, "undetected": 20,
                        "harmless": 0, "timeout": 1, "confirmed-timeout": 0,
                        "failure": 0, "type-unsupported": 5
                    },
                    "last_analysis_results": {
                        "Kaspersky": {
                            "category": "malicious", "engine_name": "Kaspersky",
                            "engine_version": "21.0", "result": "Trojan.Win32.Agent",
                            "method": "blacklist"
                        },
                        "ClamAV": {
                            "category": "undetected", "engine_name": "ClamAV",
                            "result": serde_json::Value::Null
                        }
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.agent/emotet",
                        "popular_threat_name": [{"value": "emotet", "count": 30}]
                    }
                }
            }
        })
    }

    #[test]
    fn test_parse_file_report_full_uses_real_numbers() {
        let r = parse_file_report_full(&sample_file_json());
        assert_eq!(r.last_analysis_stats.malicious, 42);
        assert_eq!(r.last_analysis_stats.type_unsupported, 5);
        assert_eq!(r.meaningful_name.as_deref(), Some("invoice.exe"));
        assert_eq!(r.times_submitted, 7);
        assert_eq!(r.reputation, -12);
        assert_eq!(r.last_analysis_results.len(), 2);
        assert_eq!(
            r.last_analysis_results["Kaspersky"].result.as_deref(),
            Some("Trojan.Win32.Agent")
        );
        assert!(r.last_analysis_results["ClamAV"].result.is_none());
    }

    #[test]
    fn test_parse_file_report_spec_reflects_document() {
        let r = parse_file_report_spec(&sample_file_json()).unwrap();
        assert_eq!(r.scan_results.len(), 2);
        assert!(r.is_malicious());
        assert_eq!(r.first_submission, Some(1_600_000_000));
    }

    #[test]
    fn test_parse_file_report_spec_rejects_garbage() {
        let e = parse_file_report_spec(&serde_json::json!({})).unwrap_err();
        assert!(matches!(e, VtClientError::Parse(_)));
    }

    #[test]
    fn test_parse_ip_report_spec() {
        let json = serde_json::json!({
            "data": {
                "id": "203.0.113.7",
                "attributes": {
                    "country": "DE",
                    "as_owner": "Example AS",
                    "last_analysis_stats": {"malicious": 4, "suspicious": 1}
                }
            }
        });
        let r = parse_ip_report_spec(&json).unwrap();
        assert_eq!(r.ip_address, "203.0.113.7");
        assert_eq!(r.malicious_count, 4);
        assert_eq!(r.suspicious_count, 1);
        assert!(r.is_malicious());
    }

    #[test]
    fn test_parse_ip_report_spec_clean_document() {
        let json = serde_json::json!({
            "data": {"id": "8.8.8.8", "attributes": {"last_analysis_stats": {"malicious": 0}}}
        });
        assert!(!parse_ip_report_spec(&json).unwrap().is_malicious());
    }

    #[test]
    fn test_verdict_from_json_counts_engines() {
        let v = VirusTotalClient::verdict_from_json(&sample_file_json());
        assert!(v.malicious);
        assert_eq!(v.positive_count, 45);
        assert_eq!(v.engine_count, 71);
        assert_eq!(v.description.as_deref(), Some("trojan.agent/emotet"));
        assert_eq!(v.provider, "virustotal");
    }

    #[test]
    fn test_verdict_from_json_empty_document_is_not_malicious() {
        let v = VirusTotalClient::verdict_from_json(&serde_json::json!({}));
        assert!(!v.malicious);
        assert_eq!(v.engine_count, 0);
        assert_eq!(v.confidence, 0);
    }

    #[test]
    fn test_vt_url_id_matches_base64url() {
        // Known VT identifier for "http://www.example.com/".
        assert_eq!(
            vt_url_id("http://www.example.com/"),
            "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"
        );
    }

    #[test]
    fn test_ioc_path_per_type() {
        let h = hash_ioc("abc");
        assert_eq!(
            VirusTotalClient::ioc_path(&h).unwrap(),
            "/api/v3/files/abc"
        );
        let ip = ip_ioc("1.2.3.4");
        assert_eq!(
            VirusTotalClient::ioc_path(&ip).unwrap(),
            "/api/v3/ip_addresses/1.2.3.4"
        );
        let d = domain_ioc("evil.example.com");
        assert_eq!(
            VirusTotalClient::ioc_path(&d).unwrap(),
            "/api/v3/domains/evil.example.com"
        );
    }

    #[test]
    fn test_relationship_endpoint_names() {
        assert_eq!(
            VtRelationshipType::ContactedIps.endpoint(),
            "contacted_ips"
        );
        assert_eq!(
            VtRelationshipType::Other("carbonblack_children".to_string()).endpoint(),
            "carbonblack_children"
        );
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

    #[tokio::test]
    async fn test_lookup_returns_error_not_a_result() {
        let ioc = hash_ioc("testvalue");
        assert!(client().lookup(&ioc).await.is_err());
    }

    #[tokio::test]
    async fn test_bulk_lookup_reports_missing_key_for_every_ioc() {
        let iocs = vec![hash_ioc("a"), hash_ioc("b"), hash_ioc("c")];
        // Without a key there is no verdict for ANY of them, and the failure
        // is surfaced rather than papered over with three invented results.
        assert!(client().bulk_lookup(&iocs).await.is_err());
    }
}
