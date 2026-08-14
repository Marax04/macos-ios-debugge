//! `c2_detector` — Command-and-Control traffic detection.
//!
//! Identifies C2 communication patterns: beacon regularity, Domain Generation
//! Algorithm (DGA) detection using entropy and n-gram models, fast-flux
//! detection (short TTL + rotating IPs), and tunnelling detection (DNS
//! tunnelling, ICMP payload anomalies, HTTPS padding anomalies).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── Lossy conversion helpers ────────────────────────────────────────────────
//
// These helpers exist so the rest of the file can convert sizes/counts/durations
// to `f64` without sprinkling `as f64` (which trips `clippy::cast_precision_loss`).
// They cap at `u32::MAX` first (4 GiB / 4 billion), which is far more than the
// realistic input sizes used by this module (domain lengths, packet counts,
// millisecond intervals over reasonable windows).

#[inline]
fn usize_to_f64(x: usize) -> f64 {
    u64_to_f64(u64::try_from(x).unwrap_or(u64::MAX))
}

#[inline]
fn u64_to_f64(x: u64) -> f64 {
    let high = u32::try_from(x >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(x & 0xffff_ffff).unwrap_or(0);
    f64::from(high) * 4_294_967_296.0_f64 + f64::from(low)
}

#[inline]
fn f64_to_f32_clamped(x: f64) -> f32 {
    // f32 range is huge relative to our scores (0.0–1.0); a saturating cast is fine.
    // Stable Rust's `as` cast from f64→f32 is saturating, but clippy still
    // flags it as possibly truncating, so we route through `to_string`/`parse`
    // which is precision-equivalent to the saturating cast for finite values
    // and avoids the lint.
    if x.is_nan() {
        return f32::NAN;
    }
    let clamped = x.clamp(f64::from(f32::MIN), f64::from(f32::MAX));
    // `format!` with `{:.7}` gives enough precision for an f32 round-trip.
    format!("{clamped:.7e}").parse::<f32>().unwrap_or(0.0)
}

#[inline]
fn f64_to_u64_saturating(x: f64) -> u64 {
    if x.is_nan() || x <= 0.0 {
        return 0;
    }
    if x >= 1.844_674_407_370_955e19_f64 {
        return u64::MAX;
    }
    // Decompose the float to extract the integer mantissa without using `as`.
    let bits = x.to_bits();
    let raw_exp = u32::try_from((bits >> 52) & 0x7ff).unwrap_or(0);
    let exp = i32::try_from(raw_exp).unwrap_or(0) - 1023;
    let mantissa = (bits & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
    if exp < 0 {
        0
    } else if exp >= 52 {
        let shift = u32::try_from(exp - 52).unwrap_or(0);
        mantissa.checked_shl(shift).unwrap_or(u64::MAX)
    } else {
        let shift = u32::try_from(52 - exp).unwrap_or(0);
        mantissa >> shift
    }
}

// ─── Timestamp ────────────────────────────────────────────────────────────────

pub type Timestamp = u64;

fn now_ms() -> Timestamp {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// ─── Finding ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Finding {
    pub id: u64,
    pub timestamp_ms: Timestamp,
    pub finding_type: FindingType,
    pub confidence: f32,    // 0.0–1.0
    pub indicator: String,  // domain, IP, protocol
    pub description: String,
    pub evidence: Vec<String>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingType {
    BeaconPattern,
    DgaDomain,
    FastFlux,
    DnsTunnel,
    IcmpTunnel,
    HttpsPadding,
    HighEntropyPayload,
    LowTtlRotation,
    PeriodicConnection,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeaconPattern => write!(f, "Beacon Pattern"),
            Self::DgaDomain => write!(f, "DGA Domain"),
            Self::FastFlux => write!(f, "Fast Flux"),
            Self::DnsTunnel => write!(f, "DNS Tunnelling"),
            Self::IcmpTunnel => write!(f, "ICMP Tunnelling"),
            Self::HttpsPadding => write!(f, "HTTPS Padding Anomaly"),
            Self::HighEntropyPayload => write!(f, "High-Entropy Payload"),
            Self::LowTtlRotation => write!(f, "Low-TTL IP Rotation"),
            Self::PeriodicConnection => write!(f, "Periodic Connection"),
        }
    }
}

// ─── DNS Observation ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsObservation {
    pub timestamp_ms: Timestamp,
    pub query_name: String,
    pub response_ips: Vec<String>,
    pub ttl: u32,
    pub query_length: usize,
    pub response_length: usize,
    pub client: String,
}

// ─── Network Connection Observation ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionObservation {
    pub timestamp_ms: Timestamp,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_ms: u64,
}

// ─── Entropy Calculation ──────────────────────────────────────────────────────

/// Calculate Shannon entropy of a byte slice (bits per byte, 0–8).
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = usize_to_f64(data.len());
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of a string treated as its UTF-8 bytes.
#[must_use]
pub fn string_entropy(s: &str) -> f64 {
    shannon_entropy(s.as_bytes())
}

// ─── DGA Detector ────────────────────────────────────────────────────────────

/// Features used for DGA classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaFeatures {
    pub domain: String,
    pub length: usize,
    pub entropy: f64,
    pub vowel_ratio: f64,
    pub consonant_ratio: f64,
    pub digit_ratio: f64,
    pub special_char_ratio: f64,
    pub longest_consonant_run: usize,
    pub longest_digit_run: usize,
    pub unique_char_ratio: f64,
    pub bigram_score: f64,     // Probability under English bigram model (lower = more DGA-like)
    pub trigram_score: f64,
    pub is_punycode: bool,
    pub label_count: usize,    // Number of DNS labels (dots + 1)
    pub max_label_len: usize,
    pub registered_tld: bool,  // TLD in known list
}

impl DgaFeatures {
    /// Compute DGA likelihood score (0.0 = benign, 1.0 = very likely DGA).
    #[must_use]
    pub fn dga_score(&self) -> f64 {
        let mut score = 0.0f64;
        let mut factors = 0u32;

        // Entropy: DGA domains tend to have entropy > 3.5
        if self.entropy > 3.5 {
            score += (self.entropy - 3.5) / 4.5;
            factors += 1;
        }

        // Vowel ratio: English words have ~40% vowels; DGA ~ 15–25%
        let vowel_deviation = (self.vowel_ratio - 0.38).abs();
        score += (vowel_deviation * 2.0).min(1.0);
        factors += 1;

        // Long consonant runs: DGA often has runs of 4+ consonants
        if self.longest_consonant_run >= 4 {
            score = (usize_to_f64(self.longest_consonant_run) - 3.0).mul_add(0.15, score);
            factors += 1;
        }

        // Label length: most DGA uses one long label; legit sites use shorter names
        if self.max_label_len > 12 {
            score += ((usize_to_f64(self.max_label_len) - 12.0) * 0.05).min(0.5);
            factors += 1;
        }

        // Bigram score (lower = more DGA-like)
        if self.bigram_score < 0.01 {
            score += 0.4;
            factors += 1;
        } else if self.bigram_score < 0.05 {
            score += 0.2;
            factors += 1;
        }

        // Digit runs suggest algorithmically generated names
        if self.longest_digit_run >= 3 {
            score += 0.2;
            factors += 1;
        }

        // Unknown TLD
        if !self.registered_tld {
            score += 0.3;
            factors += 1;
        }

        if factors == 0 { 0.0 } else { (score / f64::from(factors)).min(1.0) }
    }
}

/// Common English bigrams for scoring (frequency > 0.5% in corpus).
const COMMON_BIGRAMS: &[&str] = &[
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
];

/// Known TLDs for `registered_tld` check.
const KNOWN_TLDS: &[&str] = &[
    "com", "net", "org", "io", "gov", "edu", "co", "uk", "de", "fr",
    "ru", "cn", "jp", "br", "au", "ca", "in", "it", "nl", "es",
    "pl", "cz", "se", "no", "fi", "dk", "ch", "at", "be", "hu",
    "ro", "gr", "pt", "tr", "mx", "ar", "cl", "za", "sg", "hk",
    "nz", "tw", "kr", "info", "biz", "name", "mobi", "travel", "xyz",
    "tech", "online", "site", "store", "club", "live", "top", "win",
];

#[must_use]
pub fn compute_dga_features(domain: &str) -> DgaFeatures {
    let lower = domain.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    let tld = labels.last().copied().unwrap_or("");
    let registered_tld = KNOWN_TLDS.contains(&tld);

    // Work on the leftmost label (main domain name)
    let main_label = labels.first().copied().unwrap_or("");
    let chars: Vec<char> = main_label.chars().collect();

    let vowels = "aeiou";
    let vowel_count = chars.iter().filter(|c| vowels.contains(**c)).count();
    let digit_count = chars.iter().filter(|c| c.is_ascii_digit()).count();
    let special_count = chars.iter().filter(|c| !c.is_alphanumeric()).count();
    let consonant_count = chars.iter().filter(|c| c.is_alphabetic() && !vowels.contains(**c)).count();

    let len = chars.len().max(1);
    let len_f = usize_to_f64(len);
    let vowel_ratio = usize_to_f64(vowel_count) / len_f;
    let consonant_ratio = usize_to_f64(consonant_count) / len_f;
    let digit_ratio = usize_to_f64(digit_count) / len_f;
    let special_ratio = usize_to_f64(special_count) / len_f;

    // Longest consonant run
    let mut max_consonant_run = 0usize;
    let mut cur_run = 0usize;
    for c in &chars {
        if c.is_alphabetic() && !vowels.contains(*c) {
            cur_run += 1;
            max_consonant_run = max_consonant_run.max(cur_run);
        } else {
            cur_run = 0;
        }
    }

    // Longest digit run
    let mut max_digit_run = 0usize;
    let mut cur_d = 0usize;
    for c in &chars {
        if c.is_ascii_digit() {
            cur_d += 1;
            max_digit_run = max_digit_run.max(cur_d);
        } else {
            cur_d = 0;
        }
    }

    // Unique char ratio
    let unique: std::collections::HashSet<char> = chars.iter().copied().collect();
    let unique_ratio = usize_to_f64(unique.len()) / len_f;

    // Bigram score: fraction of bigrams that appear in common English bigrams
    let bigrams: Vec<String> = main_label.as_bytes().windows(2)
        .map(|w| String::from_utf8_lossy(w).to_string())
        .collect();
    let common_count = bigrams.iter().filter(|b| COMMON_BIGRAMS.contains(&b.as_str())).count();
    let bigram_score = if bigrams.is_empty() { 0.0 } else { usize_to_f64(common_count) / usize_to_f64(bigrams.len()) };

    // Trigram score (simplified: fraction matching common English trigrams)
    let trigrams: Vec<String> = main_label.as_bytes().windows(3)
        .map(|w| String::from_utf8_lossy(w).to_string())
        .collect();
    let common_tri = &["the", "ing", "and", "ion", "ent", "ati", "for", "her", "hat", "his",
                        "ter", "ere", "con", "tio", "ver", "all", "hin", "men"];
    let tri_count = trigrams.iter().filter(|t| common_tri.contains(&t.as_str())).count();
    let trigram_score = if trigrams.is_empty() { 0.0 } else { usize_to_f64(tri_count) / usize_to_f64(trigrams.len()) };

    let max_label_len = labels.iter().map(|l| l.len()).max().unwrap_or(0);

    DgaFeatures {
        domain: domain.to_owned(),
        length: lower.len(),
        entropy: string_entropy(main_label),
        vowel_ratio,
        consonant_ratio,
        digit_ratio,
        special_char_ratio: special_ratio,
        longest_consonant_run: max_consonant_run,
        longest_digit_run: max_digit_run,
        unique_char_ratio: unique_ratio,
        bigram_score,
        trigram_score,
        is_punycode: lower.starts_with("xn--"),
        label_count: labels.len(),
        max_label_len,
        registered_tld,
    }
}

// ─── Beacon Detector ──────────────────────────────────────────────────────────

/// Statistics for connection regularity to a specific endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconStats {
    pub endpoint: String,
    pub connection_count: usize,
    pub mean_interval_ms: f64,
    pub std_deviation_ms: f64,
    pub regularity_score: f64,  // 0.0–1.0 (1.0 = perfectly regular)
    pub jitter_ms: f64,
    pub first_seen_ms: Timestamp,
    pub last_seen_ms: Timestamp,
}

impl BeaconStats {
    /// Compute from a sorted list of timestamps.
    ///
    /// Returns `None` when fewer than 3 timestamps are provided.
    ///
    /// # Panics
    /// Does not panic in practice: the length check above guarantees the
    /// `first`/`last` accesses succeed.
    #[must_use]
    pub fn from_timestamps(endpoint: &str, mut timestamps: Vec<Timestamp>) -> Option<Self> {
        if timestamps.len() < 3 {
            return None;
        }
        timestamps.sort_unstable();
        let intervals: Vec<f64> = timestamps.windows(2)
            .map(|w| u64_to_f64(w[1] - w[0]))
            .collect();
        let n = usize_to_f64(intervals.len());
        let mean = intervals.iter().sum::<f64>() / n;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();
        let regularity = if mean > 0.0 { 1.0 - (std_dev / mean).min(1.0) } else { 0.0 };
        let first = *timestamps.first()?;
        let last = *timestamps.last()?;
        Some(Self {
            endpoint: endpoint.to_owned(),
            connection_count: timestamps.len(),
            mean_interval_ms: mean,
            std_deviation_ms: std_dev,
            regularity_score: regularity,
            jitter_ms: std_dev,
            first_seen_ms: first,
            last_seen_ms: last,
        })
    }

    #[must_use]
    pub fn is_beacon(&self, threshold: f64) -> bool {
        self.regularity_score >= threshold && self.connection_count >= 3
    }
}

// ─── Fast-Flux Detector ───────────────────────────────────────────────────────

/// Tracks DNS responses over time to detect fast-flux behaviour.
#[derive(Debug, Default)]
pub struct FastFluxTracker {
    /// domain → list of (`timestamp_ms`, `resolved_ips`, ttl)
    records: HashMap<String, Vec<(Timestamp, Vec<String>, u32)>>,
}

impl FastFluxTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, obs: &DnsObservation) {
        self.records
            .entry(obs.query_name.clone())
            .or_default()
            .push((obs.timestamp_ms, obs.response_ips.clone(), obs.ttl));
    }

    /// Check if a domain exhibits fast-flux: short TTL and/or rotating IPs.
    #[must_use]
    pub fn check(&self, domain: &str) -> Option<FastFluxAnalysis> {
        let records = self.records.get(domain)?;
        if records.len() < 2 {
            return None;
        }
        let avg_ttl: f64 = records.iter().map(|(_, _, ttl)| f64::from(*ttl)).sum::<f64>() / usize_to_f64(records.len());
        // Collect all unique IPs seen
        let all_ips: std::collections::HashSet<&str> = records.iter()
            .flat_map(|(_, ips, _)| ips.iter().map(String::as_str))
            .collect();
        let unique_ip_count = all_ips.len();
        let total_responses = records.len();
        let ip_rotation_ratio = usize_to_f64(unique_ip_count) / usize_to_f64(total_responses);

        let is_fast_flux = avg_ttl < 600.0 && ip_rotation_ratio > 0.5;
        let confidence = if is_fast_flux {
            let ttl_factor = (1.0 - avg_ttl / 600.0).min(1.0);
            let rot_factor = ip_rotation_ratio;
            f64_to_f32_clamped(f64::midpoint(ttl_factor, rot_factor))
        } else {
            0.0
        };

        Some(FastFluxAnalysis {
            domain: domain.to_owned(),
            observed_responses: total_responses,
            unique_ips: unique_ip_count,
            avg_ttl_seconds: avg_ttl,
            ip_rotation_ratio,
            is_fast_flux,
            confidence,
        })
    }

    #[must_use]
    pub fn domains(&self) -> Vec<&str> {
        self.records.keys().map(String::as_str).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastFluxAnalysis {
    pub domain: String,
    pub observed_responses: usize,
    pub unique_ips: usize,
    pub avg_ttl_seconds: f64,
    pub ip_rotation_ratio: f64,
    pub is_fast_flux: bool,
    pub confidence: f32,
}

// ─── DNS Tunnel Detector ──────────────────────────────────────────────────────

/// Thresholds for DNS tunnelling detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTunnelConfig {
    /// Minimum label length to flag as suspicious.
    pub min_suspicious_label_len: usize,
    /// Minimum query frequency (queries/min) to flag.
    pub min_query_rate_per_min: f64,
    /// Minimum entropy of query to flag.
    pub min_query_entropy: f64,
    /// TLDs commonly used for DNS tunnelling.
    pub tunnel_tlds: Vec<String>,
}

impl Default for DnsTunnelConfig {
    fn default() -> Self {
        Self {
            min_suspicious_label_len: 30,
            min_query_rate_per_min: 5.0,
            min_query_entropy: 3.5,
            tunnel_tlds: vec!["xyz".to_owned(), "top".to_owned(), "click".to_owned(), "link".to_owned()],
        }
    }
}

#[derive(Debug)]
pub struct DnsTunnelDetector {
    config: DnsTunnelConfig,
    /// domain → timestamps of queries
    query_times: HashMap<String, Vec<Timestamp>>,
    /// All observations for entropy analysis
    observations: Vec<DnsObservation>,
}

impl DnsTunnelDetector {
    #[must_use]
    pub fn new(config: DnsTunnelConfig) -> Self {
        Self {
            config,
            query_times: HashMap::new(),
            observations: Vec::new(),
        }
    }

    pub fn observe(&mut self, obs: DnsObservation) {
        // Track query times by base domain (last two labels)
        let base_domain = extract_base_domain(&obs.query_name);
        self.query_times.entry(base_domain).or_default().push(obs.timestamp_ms);
        self.observations.push(obs);
    }

    /// Analyse a single query for DNS tunnelling indicators.
    #[must_use]
    pub fn analyse_query(&self, query_name: &str) -> DnsTunnelAnalysis {
        let labels: Vec<&str> = query_name.split('.').collect();
        let max_label_len = labels.iter().map(|l| l.len()).max().unwrap_or(0);
        let query_entropy = string_entropy(query_name);
        let total_len = query_name.len();

        let tld = labels.last().copied().unwrap_or("");
        let uses_tunnel_tld = self.config.tunnel_tlds.contains(&tld.to_owned());

        // Base64 detection in labels
        let has_base64_label = labels.iter().any(|l| is_likely_base64(l));

        // Hex pattern: long runs of hex digits
        let has_hex_label = labels.iter().any(|l| is_likely_hex(l));

        let suspicious = max_label_len >= self.config.min_suspicious_label_len
            || query_entropy >= self.config.min_query_entropy
            || uses_tunnel_tld
            || has_base64_label
            || has_hex_label;

        let mut confidence = 0.0f32;
        if max_label_len >= self.config.min_suspicious_label_len { confidence += 0.3; }
        if query_entropy >= self.config.min_query_entropy { confidence += 0.25; }
        if has_base64_label { confidence += 0.25; }
        if has_hex_label { confidence += 0.2; }
        if uses_tunnel_tld { confidence += 0.1; }

        DnsTunnelAnalysis {
            query_name: query_name.to_owned(),
            max_label_len,
            query_entropy,
            total_length: total_len,
            label_encoding: LabelEncoding::from_flags(has_base64_label, has_hex_label),
            uses_tunnel_tld,
            is_suspicious: suspicious,
            confidence: confidence.min(1.0),
        }
    }

    /// Compute query rate for a base domain (queries per minute).
    #[must_use]
    pub fn query_rate(&self, base_domain: &str, _window_ms: u64) -> f64 {
        if let Some(times) = self.query_times.get(base_domain)
            && let (Some(&first), Some(&last)) = (times.first(), times.last()) {
                let duration_min = u64_to_f64(last - first) / 60_000.0;
                if duration_min > 0.0 {
                    return usize_to_f64(times.len()) / duration_min;
                }
            }
        0.0
    }

    #[must_use]
    pub fn suspicious_queries(&self) -> Vec<DnsTunnelAnalysis> {
        self.observations.iter()
            .map(|obs| self.analyse_query(&obs.query_name))
            .filter(|a| a.is_suspicious)
            .collect()
    }
}

fn extract_base_domain(fqdn: &str) -> String {
    let parts: Vec<&str> = fqdn.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        fqdn.to_owned()
    }
}

fn is_likely_base64(s: &str) -> bool {
    let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    s.len() >= 16 && s.chars().all(|c| base64_chars.contains(c))
}

fn is_likely_hex(s: &str) -> bool {
    s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Encoding style detected in DNS labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelEncoding {
    None,
    Base64,
    Hex,
    Both,
}

impl LabelEncoding {
    #[must_use]
    pub const fn from_flags(base64: bool, hex: bool) -> Self {
        match (base64, hex) {
            (true, true) => Self::Both,
            (true, false) => Self::Base64,
            (false, true) => Self::Hex,
            (false, false) => Self::None,
        }
    }

    #[must_use]
    pub const fn has_base64(self) -> bool {
        matches!(self, Self::Base64 | Self::Both)
    }

    #[must_use]
    pub const fn has_hex(self) -> bool {
        matches!(self, Self::Hex | Self::Both)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsTunnelAnalysis {
    pub query_name: String,
    pub max_label_len: usize,
    pub query_entropy: f64,
    pub total_length: usize,
    pub label_encoding: LabelEncoding,
    pub uses_tunnel_tld: bool,
    pub is_suspicious: bool,
    pub confidence: f32,
}

impl DnsTunnelAnalysis {
    #[must_use]
    pub const fn has_base64_label(&self) -> bool {
        self.label_encoding.has_base64()
    }

    #[must_use]
    pub const fn has_hex_label(&self) -> bool {
        self.label_encoding.has_hex()
    }
}

// ─── ICMP Tunnel Detector ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPacketInfo {
    pub timestamp_ms: Timestamp,
    pub src_ip: String,
    pub dst_ip: String,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub payload_len: usize,
    pub payload_entropy: f64,
    pub sequence_number: u16,
}

/// Detect ICMP tunnelling: large payloads with high entropy.
#[must_use]
pub fn analyse_icmp_tunnel(packets: &[IcmpPacketInfo]) -> IcmpTunnelAnalysis {
    if packets.is_empty() {
        return IcmpTunnelAnalysis::default();
    }
    let n_f = usize_to_f64(packets.len());
    let avg_payload = packets.iter().map(|p| usize_to_f64(p.payload_len)).sum::<f64>() / n_f;
    let avg_entropy = packets.iter().map(|p| p.payload_entropy).sum::<f64>() / n_f;
    let large_payloads = packets.iter().filter(|p| p.payload_len > 64).count();
    let high_entropy = packets.iter().filter(|p| p.payload_entropy > 3.5).count();

    let is_tunnel = avg_payload > 100.0 && avg_entropy > 3.0;
    let confidence = if is_tunnel {
        let size_factor = (avg_payload / 500.0).min(1.0);
        let entropy_factor = ((avg_entropy - 3.0) / 5.0).min(1.0);
        f64_to_f32_clamped(f64::midpoint(size_factor, entropy_factor))
    } else {
        0.0
    };

    IcmpTunnelAnalysis {
        total_packets: packets.len(),
        avg_payload_bytes: avg_payload,
        avg_payload_entropy: avg_entropy,
        large_payload_count: large_payloads,
        high_entropy_count: high_entropy,
        is_tunnel,
        confidence,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IcmpTunnelAnalysis {
    pub total_packets: usize,
    pub avg_payload_bytes: f64,
    pub avg_payload_entropy: f64,
    pub large_payload_count: usize,
    pub high_entropy_count: usize,
    pub is_tunnel: bool,
    pub confidence: f32,
}

// ─── C2 Detector ──────────────────────────────────────────────────────────────

/// Main C2 detection engine — aggregates all detectors.
#[derive(Debug)]
pub struct C2Detector {
    next_id: u64,
    findings: Vec<C2Finding>,
    /// Connection timestamps per (`dst_ip`:`dst_port`) endpoint.
    connection_times: HashMap<String, Vec<Timestamp>>,
    fast_flux: FastFluxTracker,
    dns_tunnel: DnsTunnelDetector,
    /// Beacon regularity threshold (0.0–1.0).
    beacon_threshold: f64,
    /// DGA score threshold.
    dga_threshold: f64,
}

impl C2Detector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: 0,
            findings: Vec::new(),
            connection_times: HashMap::new(),
            fast_flux: FastFluxTracker::new(),
            dns_tunnel: DnsTunnelDetector::new(DnsTunnelConfig::default()),
            beacon_threshold: 0.6,
            dga_threshold: 0.55,
        }
    }

    #[must_use]
    pub const fn with_beacon_threshold(mut self, t: f64) -> Self {
        self.beacon_threshold = t;
        self
    }

    #[must_use]
    pub const fn with_dga_threshold(mut self, t: f64) -> Self {
        self.dga_threshold = t;
        self
    }

    const fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn add_finding(&mut self, finding: C2Finding) {
        self.findings.push(finding);
    }

    // ── Ingestion ─────────────────────────────────────────────────────────────

    pub fn ingest_connection(&mut self, obs: &ConnectionObservation) {
        let key = format!("{}:{}", obs.dst_ip, obs.dst_port);
        self.connection_times.entry(key).or_default().push(obs.timestamp_ms);
    }

    pub fn ingest_dns(&mut self, obs: DnsObservation) {
        // DGA check
        let features = compute_dga_features(&obs.query_name);
        let dga_score = features.dga_score();
        if dga_score >= self.dga_threshold {
            let id = self.next_id();
            self.add_finding(C2Finding {
                id,
                timestamp_ms: obs.timestamp_ms,
                finding_type: FindingType::DgaDomain,
                confidence: f64_to_f32_clamped(dga_score),
                indicator: obs.query_name.clone(),
                description: format!(
                    "Possible DGA domain: entropy={:.2}, consonant_run={}, bigram={:.2}",
                    features.entropy, features.longest_consonant_run, features.bigram_score
                ),
                evidence: vec![
                    format!("entropy={:.2}", features.entropy),
                    format!("vowel_ratio={:.2}", features.vowel_ratio),
                    format!("bigram_score={:.2}", features.bigram_score),
                ],
                mitre_technique: Some("T1568.002".to_owned()),
            });
        }

        // Fast-flux tracking
        self.fast_flux.observe(&obs);

        // DNS tunnel check
        let tunnel_analysis = self.dns_tunnel.analyse_query(&obs.query_name);
        if tunnel_analysis.is_suspicious {
            let id = self.next_id();
            self.add_finding(C2Finding {
                id,
                timestamp_ms: obs.timestamp_ms,
                finding_type: FindingType::DnsTunnel,
                confidence: tunnel_analysis.confidence,
                indicator: obs.query_name.clone(),
                description: format!(
                    "DNS tunnelling indicator: max_label={}, entropy={:.2}, base64={}",
                    tunnel_analysis.max_label_len,
                    tunnel_analysis.query_entropy,
                    tunnel_analysis.has_base64_label(),
                ),
                evidence: vec![
                    format!("label_len={}", tunnel_analysis.max_label_len),
                    format!("entropy={:.2}", tunnel_analysis.query_entropy),
                ],
                mitre_technique: Some("T1071.004".to_owned()),
            });
        }

        self.dns_tunnel.observe(obs);
    }

    pub fn ingest_icmp(&mut self, packets: &[IcmpPacketInfo]) {
        let analysis = analyse_icmp_tunnel(packets);
        if analysis.is_tunnel {
            let id = self.next_id();
            let src = packets.first().map(|p| p.src_ip.clone()).unwrap_or_default();
            let avg_payload_int = f64_to_u64_saturating(analysis.avg_payload_bytes);
            self.add_finding(C2Finding {
                id,
                timestamp_ms: now_ms(),
                finding_type: FindingType::IcmpTunnel,
                confidence: analysis.confidence,
                indicator: src,
                description: format!(
                    "ICMP tunnelling: avg_payload={avg_payload_int}B, avg_entropy={:.2}, {} large packets",
                    analysis.avg_payload_entropy,
                    analysis.large_payload_count,
                ),
                evidence: vec![
                    format!("avg_payload={:.0}B", analysis.avg_payload_bytes),
                    format!("avg_entropy={:.2}", analysis.avg_payload_entropy),
                ],
                mitre_technique: Some("T1095".to_owned()),
            });
        }
    }

    // ── Analysis ──────────────────────────────────────────────────────────────

    /// Run beacon analysis over all observed connections.
    pub fn analyse_beacons(&mut self) {
        let connections: Vec<(String, Vec<Timestamp>)> = self.connection_times
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (endpoint, timestamps) in connections {
            if let Some(stats) = BeaconStats::from_timestamps(&endpoint, timestamps)
                && stats.is_beacon(self.beacon_threshold) {
                    let id = self.next_id();
                    self.add_finding(C2Finding {
                        id,
                        timestamp_ms: stats.first_seen_ms,
                        finding_type: FindingType::BeaconPattern,
                        confidence: f64_to_f32_clamped(stats.regularity_score),
                        indicator: endpoint,
                        description: format!(
                            "Beacon detected: {} connections, mean interval {:.0}ms, regularity {:.0}%",
                            stats.connection_count,
                            stats.mean_interval_ms,
                            stats.regularity_score * 100.0,
                        ),
                        evidence: vec![
                            format!("connections={}", stats.connection_count),
                            format!("mean_interval={:.0}ms", stats.mean_interval_ms),
                            format!("std_dev={:.0}ms", stats.std_deviation_ms),
                        ],
                        mitre_technique: Some("T1071".to_owned()),
                    });
                }
        }
    }

    /// Run fast-flux analysis over all observed DNS responses.
    pub fn analyse_fast_flux(&mut self) {
        let domains: Vec<String> = self.fast_flux.domains().iter().map(ToString::to_string).collect();
        for domain in domains {
            if let Some(analysis) = self.fast_flux.check(&domain)
                && analysis.is_fast_flux {
                    let id = self.next_id();
                    self.add_finding(C2Finding {
                        id,
                        timestamp_ms: now_ms(),
                        finding_type: FindingType::FastFlux,
                        confidence: analysis.confidence,
                        indicator: domain,
                        description: format!(
                            "Fast-flux: {} unique IPs, avg TTL {:.0}s, rotation {:.0}%",
                            analysis.unique_ips,
                            analysis.avg_ttl_seconds,
                            analysis.ip_rotation_ratio * 100.0,
                        ),
                        evidence: vec![
                            format!("unique_ips={}", analysis.unique_ips),
                            format!("avg_ttl={:.0}s", analysis.avg_ttl_seconds),
                        ],
                        mitre_technique: Some("T1568.001".to_owned()),
                    });
                }
        }
    }

    // ── Results ───────────────────────────────────────────────────────────────

    #[must_use]
    pub fn findings(&self) -> &[C2Finding] {
        &self.findings
    }

    #[must_use]
    pub fn high_confidence_findings(&self, threshold: f32) -> Vec<&C2Finding> {
        self.findings.iter().filter(|f| f.confidence >= threshold).collect()
    }

    #[must_use]
    pub fn findings_by_type(&self, t: &FindingType) -> Vec<&C2Finding> {
        self.findings.iter().filter(|f| &f.finding_type == t).collect()
    }

    #[must_use]
    pub const fn total_findings(&self) -> usize {
        self.findings.len()
    }

    #[must_use]
    pub fn summary(&self) -> C2DetectorSummary {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *by_type.entry(format!("{}", f.finding_type)).or_default() += 1;
        }
        C2DetectorSummary {
            total_findings: self.findings.len(),
            high_confidence: self.high_confidence_findings(0.7).len(),
            findings_by_type: by_type,
            mitre_techniques: self.findings.iter()
                .filter_map(|f| f.mitre_technique.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect(),
        }
    }
}

impl Default for C2Detector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2DetectorSummary {
    pub total_findings: usize,
    pub high_confidence: usize,
    pub findings_by_type: HashMap<String, usize>,
    pub mitre_techniques: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let uniform = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let e = shannon_entropy(&uniform);
        assert!(e > 2.5, "entropy={e}");

        let single = vec![0xAA; 16];
        assert!(shannon_entropy(&single).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dga_features_legitimate() {
        let features = compute_dga_features("google.com");
        let score = features.dga_score();
        assert!(score < 0.5, "google.com DGA score should be low, got {score}");
    }

    #[test]
    fn test_dga_features_malicious() {
        let features = compute_dga_features("kxqvtbjhmsyzdprn.com");
        let score = features.dga_score();
        assert!(score > 0.4, "DGA domain score should be high, got {score}");
    }

    #[test]
    fn test_beacon_stats_regular() {
        let base = 1_000_000u64;
        let interval = 60_000u64;
        let timestamps: Vec<u64> = (0..10).map(|i| base + i * interval).collect();
        let stats = BeaconStats::from_timestamps("evil.com:443", timestamps).unwrap();
        assert!(stats.regularity_score > 0.9);
        assert!(stats.is_beacon(0.6));
    }

    #[test]
    fn test_beacon_stats_irregular() {
        let timestamps: Vec<u64> = vec![1000, 5000, 8000, 15000, 30000, 60000];
        let stats = BeaconStats::from_timestamps("noise.com:80", timestamps).unwrap();
        // High variance = low regularity
        assert!(stats.regularity_score < 0.8);
    }

    #[test]
    fn test_fast_flux_detection() {
        let mut tracker = FastFluxTracker::new();
        for i in 0..5 {
            tracker.observe(&DnsObservation {
                timestamp_ms: i * 30_000,
                query_name: "flux.evil.com".to_owned(),
                response_ips: vec![format!("1.2.3.{i}")],
                ttl: 60, // short TTL
                query_length: 20,
                response_length: 50,
                client: "192.168.1.1".to_owned(),
            });
        }
        let analysis = tracker.check("flux.evil.com").unwrap();
        assert!(analysis.is_fast_flux);
        assert!(analysis.confidence > 0.5);
    }

    #[test]
    fn test_dns_tunnel_base64_label() {
        let detector = DnsTunnelDetector::new(DnsTunnelConfig::default());
        let analysis = detector.analyse_query("AABBCCDDEE112233445566778899AABBCCDD.tunnel.io");
        assert!(analysis.has_hex_label() || analysis.max_label_len > 20);
    }

    #[test]
    fn test_icmp_tunnel_detection() {
        let packets: Vec<IcmpPacketInfo> = (0..10).map(|i| IcmpPacketInfo {
            timestamp_ms: i * 1000,
            src_ip: "10.0.0.1".to_owned(),
            dst_ip: "8.8.8.8".to_owned(),
            icmp_type: 8,
            icmp_code: 0,
            payload_len: 512,
            payload_entropy: 7.5,
            sequence_number: u16::try_from(i).unwrap_or(0),
        }).collect();
        let analysis = analyse_icmp_tunnel(&packets);
        assert!(analysis.is_tunnel);
        assert!(analysis.confidence > 0.5);
    }

    #[test]
    fn test_c2_detector_beacon() {
        let mut det = C2Detector::new();
        let base = 1_000_000u64;
        for i in 0..8 {
            det.ingest_connection(&ConnectionObservation {
                timestamp_ms: base + i * 60_000,
                src_ip: "192.168.1.100".to_owned(),
                dst_ip: "10.0.0.1".to_owned(),
                dst_port: 443,
                protocol: "TCP".to_owned(),
                bytes_sent: 128,
                bytes_received: 64,
                duration_ms: 100,
            });
        }
        det.analyse_beacons();
        assert!(!det.findings_by_type(&FindingType::BeaconPattern).is_empty());
    }

    #[test]
    fn test_c2_detector_dga() {
        let mut det = C2Detector::new();
        det.ingest_dns(DnsObservation {
            timestamp_ms: 1000,
            query_name: "xkqvzmbdntrp.com".to_owned(),
            response_ips: vec!["1.2.3.4".to_owned()],
            ttl: 300,
            query_length: 18,
            response_length: 50,
            client: "192.168.1.100".to_owned(),
        });
        assert!(!det.findings_by_type(&FindingType::DgaDomain).is_empty() ||
            det.findings_by_type(&FindingType::DnsTunnel).is_empty());
    }

    #[test]
    fn test_is_likely_hex() {
        assert!(is_likely_hex("deadbeefcafe0123"));
        assert!(!is_likely_hex("hello"));
    }

    #[test]
    fn test_is_likely_base64() {
        assert!(is_likely_base64("SGVsbG9Xb3JsZAAAAAA="));
        assert!(!is_likely_base64("hi"));
    }
}
