//! `AlienVault` OTX pulse parser.
//!
//! Parses raw JSON pulses from the OTX REST API into structured `OtxPulse`
//! objects with full indicator lists, tags, and MITRE ATT&CK mappings.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{OtxConfig, OtxError, ThreatLevel};

// ─── OtxIndicatorType ─────────────────────────────────────────────────────────

/// The type of an OTX indicator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OtxIndicatorType {
    Ipv4,
    Ipv6,
    Domain,
    Hostname,
    Email,
    Url,
    Uri,
    FileHashMd5,
    FileHashSha1,
    FileHashSha256,
    FilePath,
    Mutex,
    Cve,
    Yara,
    CidrIpv4,
    CidrIpv6,
    #[serde(other)]
    Other,
}

impl fmt::Display for OtxIndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Domain => "domain",
            Self::Hostname => "hostname",
            Self::Email => "email",
            Self::Url => "URL",
            Self::Uri => "URI",
            Self::FileHashMd5 => "MD5",
            Self::FileHashSha1 => "SHA1",
            Self::FileHashSha256 => "SHA256",
            Self::FilePath => "file_path",
            Self::Mutex => "mutex",
            Self::Cve => "CVE",
            Self::Yara => "YARA",
            Self::CidrIpv4 => "CIDR_IPv4",
            Self::CidrIpv6 => "CIDR_IPv6",
            Self::Other => "other",
        };
        write!(f, "{s}")
    }
}

impl OtxIndicatorType {
    /// Returns `true` if this indicator type is a network observable.
    #[must_use]
    pub const fn is_network(&self) -> bool {
        matches!(
            self,
            Self::Ipv4 | Self::Ipv6 | Self::Domain | Self::Hostname
                | Self::Url | Self::Uri | Self::CidrIpv4 | Self::CidrIpv6
        )
    }

    /// Returns `true` if this indicator type is a file hash.
    #[must_use]
    pub const fn is_hash(&self) -> bool {
        matches!(
            self,
            Self::FileHashMd5 | Self::FileHashSha1 | Self::FileHashSha256
        )
    }
}

// ─── OtxIndicator ─────────────────────────────────────────────────────────────

/// A single indicator within an OTX pulse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxIndicator {
    /// OTX indicator ID (numeric).
    pub id: u64,
    /// Indicator type.
    pub indicator_type: OtxIndicatorType,
    /// The indicator value (IP, domain, hash, …).
    pub indicator: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Title assigned by the pulse author.
    pub title: Option<String>,
    /// RFC 3339 creation time.
    pub created: String,
    /// Whether this indicator is still active.
    pub is_active: bool,
    /// Related CVE if applicable.
    pub related_cve: Option<String>,
}

impl OtxIndicator {
    /// Returns `true` if the indicator has a non-empty value.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.indicator.trim().is_empty()
    }

    /// Create a minimal IP indicator for tests.
    #[must_use]
    pub fn ip(id: u64, ip: impl Into<String>) -> Self {
        Self {
            id,
            indicator_type: OtxIndicatorType::Ipv4,
            indicator: ip.into(),
            description: None,
            title: None,
            created: "2024-01-01T00:00:00Z".to_string(),
            is_active: true,
            related_cve: None,
        }
    }

    /// Create a minimal domain indicator for tests.
    #[must_use]
    pub fn domain(id: u64, domain: impl Into<String>) -> Self {
        Self {
            id,
            indicator_type: OtxIndicatorType::Domain,
            indicator: domain.into(),
            description: None,
            title: None,
            created: "2024-01-01T00:00:00Z".to_string(),
            is_active: true,
            related_cve: None,
        }
    }

    /// Create a SHA-256 hash indicator for tests.
    #[must_use]
    pub fn sha256(id: u64, hash: impl Into<String>) -> Self {
        Self {
            id,
            indicator_type: OtxIndicatorType::FileHashSha256,
            indicator: hash.into(),
            description: None,
            title: None,
            created: "2024-01-01T00:00:00Z".to_string(),
            is_active: true,
            related_cve: None,
        }
    }
}

// ─── OtxPulse ─────────────────────────────────────────────────────────────────

/// A fully parsed OTX pulse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxPulse {
    /// OTX pulse ID.
    pub id: String,
    /// Pulse name.
    pub name: String,
    /// Pulse description.
    pub description: Option<String>,
    /// Author's OTX username.
    pub author_name: String,
    /// Threat level reported by the author.
    pub tlp: Option<String>,
    /// Numeric threat level (1–4).
    pub threat_level_id: Option<u8>,
    /// Tags assigned to this pulse.
    pub tags: Vec<String>,
    /// Industries targeted.
    pub industries: Vec<String>,
    /// Countries targeted.
    pub targeted_countries: Vec<String>,
    /// MITRE ATT&CK technique IDs referenced.
    pub attack_ids: Vec<String>,
    /// All indicators in this pulse.
    pub indicators: Vec<OtxIndicator>,
    /// Malware families referenced.
    pub malware_families: Vec<String>,
    /// RFC 3339 creation timestamp.
    pub created: String,
    /// RFC 3339 modification timestamp.
    pub modified: String,
    /// Number of subscribers to this pulse.
    pub subscriber_count: u32,
    /// Number of up-votes.
    pub upvotes_count: u32,
    /// Whether the pulse is public.
    pub public: bool,
    /// Revision number.
    pub revision: u32,
    /// Related OTX pulse IDs.
    pub related_pulses: Vec<String>,
}

impl OtxPulse {
    /// Derive a `ThreatLevel` from the numeric `threat_level_id`.
    #[must_use]
    pub fn threat_level(&self) -> ThreatLevel {
        self.threat_level_id
            .map_or(ThreatLevel::Unknown, ThreatLevel::from_int)
    }

    /// Count indicators by type.
    #[must_use]
    pub fn indicator_counts(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for ind in &self.indicators {
            *map.entry(ind.indicator_type.to_string()).or_default() += 1;
        }
        map
    }

    /// All network indicators (IPs, domains, URLs).
    #[must_use]
    pub fn network_indicators(&self) -> Vec<&OtxIndicator> {
        self.indicators
            .iter()
            .filter(|i| i.indicator_type.is_network())
            .collect()
    }

    /// All file hash indicators.
    #[must_use]
    pub fn hash_indicators(&self) -> Vec<&OtxIndicator> {
        self.indicators
            .iter()
            .filter(|i| i.indicator_type.is_hash())
            .collect()
    }

    /// Returns `true` if the pulse references any MITRE ATT&CK techniques.
    #[must_use]
    pub const fn has_attack_mapping(&self) -> bool {
        !self.attack_ids.is_empty()
    }

    /// Create a sample pulse for unit tests.
    #[must_use]
    pub fn sample() -> Self {
        Self {
            id: "pulse-abc-123".to_string(),
            name: "Emotet Spam Campaign Q1 2024".to_string(),
            description: Some("Fresh Emotet IOCs from Q1 2024 spam campaign.".to_string()),
            author_name: "ti_analyst".to_string(),
            tlp: Some("white".to_string()),
            threat_level_id: Some(3),
            tags: vec!["emotet".to_string(), "spam".to_string(), "banking-trojan".to_string()],
            industries: vec!["finance".to_string()],
            targeted_countries: vec!["DE".to_string(), "FR".to_string()],
            attack_ids: vec!["T1071".to_string(), "T1055".to_string()],
            indicators: vec![
                OtxIndicator::ip(1, "185.220.101.1"),
                OtxIndicator::domain(2, "evil-c2.example.com"),
                OtxIndicator::sha256(
                    3,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
            ],
            malware_families: vec!["Emotet".to_string()],
            created: "2024-01-10T08:00:00Z".to_string(),
            modified: "2024-01-11T09:00:00Z".to_string(),
            subscriber_count: 1234,
            upvotes_count: 56,
            public: true,
            revision: 1,
            related_pulses: vec![],
        }
    }
}

// ─── ParseConfig ─────────────────────────────────────────────────────────────

/// Controls the parsing behaviour of `OtxPulseParser`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseConfig {
    /// Skip inactive indicators (`is_active == false`).
    pub skip_inactive: bool,
    /// Skip indicators with empty values.
    pub skip_invalid: bool,
    /// Maximum indicators to keep per pulse (None = unlimited).
    pub max_indicators: Option<usize>,
    /// Only keep indicators of these types (empty = keep all).
    pub allowed_types: Vec<OtxIndicatorType>,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            skip_inactive: true,
            skip_invalid: true,
            max_indicators: None,
            allowed_types: vec![],
        }
    }
}

// ─── OtxPulseParser ───────────────────────────────────────────────────────────

/// Parses raw OTX API responses into `OtxPulse` objects.
pub struct OtxPulseParser {
    config: OtxConfig,
    parse_config: ParseConfig,
}

impl OtxPulseParser {
    /// Create a new parser.
    #[must_use]
    pub const fn new(config: OtxConfig, parse_config: ParseConfig) -> Self {
        Self { config, parse_config }
    }

    /// Create a parser with default parse config.
    #[must_use]
    pub fn with_defaults(config: OtxConfig) -> Self {
        Self::new(config, ParseConfig::default())
    }

    /// Maximum JSON input size accepted by any parse method (16 MiB).
    ///
    /// The OTX API returns text/JSON; a single pulse page should never exceed
    /// this. Rejecting oversized payloads protects against server-side bugs or
    /// adversarial responses that could exhaust heap or stack.
    const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;

    /// Parse a single pulse from a JSON string.
    ///
    /// # Errors
    /// Returns `OtxError::Json` if the string is not valid JSON or exceeds the
    /// size limit.
    pub fn parse_pulse(&self, json: &str) -> Result<OtxPulse, OtxError> {
        if json.len() > Self::MAX_JSON_BYTES {
            return Err(OtxError::Json(format!(
                "pulse JSON too large: {} bytes (limit {})",
                json.len(),
                Self::MAX_JSON_BYTES,
            )));
        }
        let raw: serde_json::Value =
            serde_json::from_str(json).map_err(|e| OtxError::Json(e.to_string()))?;
        self.value_to_pulse(&raw)
    }

    /// Parse a page of pulses from the `/api/v1/pulses/subscribed` response.
    ///
    /// # Errors
    /// Returns `OtxError::Json` if the response is malformed or exceeds the
    /// size limit.
    pub fn parse_subscribed_page(&self, json: &str) -> Result<Vec<OtxPulse>, OtxError> {
        if json.len() > Self::MAX_JSON_BYTES {
            return Err(OtxError::Json(format!(
                "subscribed-page JSON too large: {} bytes (limit {})",
                json.len(),
                Self::MAX_JSON_BYTES,
            )));
        }
        let raw: serde_json::Value =
            serde_json::from_str(json).map_err(|e| OtxError::Json(e.to_string()))?;

        let results = raw
            .get("results")
            .and_then(|r| r.as_array())
            .ok_or_else(|| OtxError::Json("missing 'results' array".into()))?;

        let mut pulses = Vec::with_capacity(results.len());
        for entry in results {
            match self.value_to_pulse(entry) {
                Ok(p) => pulses.push(p),
                Err(e) => {
                    // Log and skip invalid entries — do not abort the whole page.
                    warn!("OtxPulseParser: skipping pulse: {e}");
                }
            }
        }
        Ok(pulses)
    }

    /// Convert a `serde_json::Value` into an `OtxPulse`.
    fn value_to_pulse(&self, v: &serde_json::Value) -> Result<OtxPulse, OtxError> {
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| OtxError::Json("missing pulse id".into()))?
            .to_string();

        let name = v
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or("Unnamed")
            .to_string();

        let description = v
            .get("description")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        let author_name = v
            .get("author_name")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();

        let tlp = v
            .get("tlp")
            .and_then(|x| x.as_str())
            .map(ToString::to_string);

        let threat_level_id = v
            .get("threat_level_id")
            .and_then(serde_json::Value::as_u64)
            .map(|n| u8::try_from(n).unwrap_or(u8::MAX));

        let tags = parse_string_array(v, "tags");
        let industries = parse_string_array(v, "industries");
        let targeted_countries = parse_string_array(v, "targeted_countries");
        let malware_families = parse_string_array(v, "malware_families");
        let related_pulses = v
            .get("references")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let attack_ids = v
            .get("attack_ids")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| {
                        x.get("display_name")
                            .or_else(|| x.get("id"))
                            .and_then(|d| d.as_str())
                    })
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let raw_indicators = v
            .get("indicators")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();

        let indicators = self.filter_indicators(&raw_indicators);

        let created = v
            .get("created")
            .and_then(|x| x.as_str())
            .unwrap_or("1970-01-01T00:00:00Z")
            .to_string();

        let modified = v
            .get("modified")
            .and_then(|x| x.as_str())
            .unwrap_or("1970-01-01T00:00:00Z")
            .to_string();

        let subscriber_count = parse_u32(v, "subscriber_count", 0);
        let upvotes_count = parse_u32(v, "upvotes_count", 0);
        let public = v
            .get("public")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|n| n != 0);
        let revision = parse_u32(v, "revision", 1);

        Ok(OtxPulse {
            id,
            name,
            description,
            author_name,
            tlp,
            threat_level_id,
            tags,
            industries,
            targeted_countries,
            attack_ids,
            indicators,
            malware_families,
            created,
            modified,
            subscriber_count,
            upvotes_count,
            public,
            revision,
            related_pulses,
        })
    }

    /// Apply parser config filters to a raw indicator list.
    fn filter_indicators(&self, raw_indicators: &[serde_json::Value]) -> Vec<OtxIndicator> {
        let mut indicators = Vec::with_capacity(raw_indicators.len());
        for ind_val in raw_indicators {
            let ind = Self::value_to_indicator(ind_val);
            if self.parse_config.skip_inactive && !ind.is_active {
                continue;
            }
            if self.parse_config.skip_invalid && !ind.is_valid() {
                continue;
            }
            if !self.parse_config.allowed_types.is_empty()
                && !self.parse_config.allowed_types.contains(&ind.indicator_type)
            {
                continue;
            }
            indicators.push(ind);
        }
        if let Some(max) = self.parse_config.max_indicators {
            indicators.truncate(max);
        }
        indicators
    }

    /// Parse a JSON indicator value.
    fn value_to_indicator(v: &serde_json::Value) -> OtxIndicator {
        let id = v.get("id").and_then(serde_json::Value::as_u64).unwrap_or(0);

        let raw_type = v
            .get("type")
            .or_else(|| v.get("indicator_type"))
            .and_then(|x| x.as_str())
            .unwrap_or("OTHER")
            .to_string();

        let indicator_type: OtxIndicatorType =
            serde_json::from_value(serde_json::Value::String(raw_type))
                .unwrap_or(OtxIndicatorType::Other);

        let indicator = v
            .get("indicator")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();

        let description = v
            .get("description")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        let title = v
            .get("title")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        let created = v
            .get("created")
            .and_then(|x| x.as_str())
            .unwrap_or("1970-01-01T00:00:00Z")
            .to_string();

        let is_active = v
            .get("is_active")
            .and_then(|x| x.as_bool().or_else(|| x.as_u64().map(|n| n != 0)))
            .unwrap_or(true);

        OtxIndicator {
            id,
            indicator_type,
            indicator,
            description,
            title,
            created,
            is_active,
            related_cve: None,
        }
    }

    /// Build the URL to fetch a pulse from the OTX API.
    #[must_use]
    pub fn pulse_url(&self, pulse_id: &str) -> String {
        self.config.pulse_url(pulse_id)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parse_u32(v: &serde_json::Value, key: &str, default: u32) -> u32 {
    v.get(key)
        .and_then(serde_json::Value::as_u64)
        .map_or(default, |n| u32::try_from(n).unwrap_or(u32::MAX))
}

fn parse_string_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_parser() -> OtxPulseParser {
        OtxPulseParser::with_defaults(OtxConfig::new("test-key"))
    }

    fn sample_pulse_json() -> String {
        serde_json::to_string(&OtxPulse::sample()).unwrap()
    }

    #[test]
    fn test_parse_pulse_roundtrip() {
        let parser = make_parser();
        let json = sample_pulse_json();
        let pulse = parser.parse_pulse(&json).expect("should parse");
        assert_eq!(pulse.name, "Emotet Spam Campaign Q1 2024");
        assert_eq!(pulse.indicators.len(), 3);
    }

    #[test]
    fn test_threat_level_derived() {
        let pulse = OtxPulse::sample();
        assert_eq!(pulse.threat_level(), ThreatLevel::High);
    }

    #[test]
    fn test_indicator_type_counts() {
        let pulse = OtxPulse::sample();
        let counts = pulse.indicator_counts();
        assert_eq!(counts.get("IPv4").copied().unwrap_or(0), 1);
        assert_eq!(counts.get("domain").copied().unwrap_or(0), 1);
        assert_eq!(counts.get("SHA256").copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_network_vs_hash_indicators() {
        let pulse = OtxPulse::sample();
        assert_eq!(pulse.network_indicators().len(), 2);
        assert_eq!(pulse.hash_indicators().len(), 1);
    }

    #[test]
    fn test_parse_invalid_json() {
        let parser = make_parser();
        let result = parser.parse_pulse("{bad json}");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_id() {
        let parser = make_parser();
        let result = parser.parse_pulse(r#"{"name": "No ID"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_indicators_limit() {
        let cfg = ParseConfig { max_indicators: Some(1), ..ParseConfig::default() };
        let parser = OtxPulseParser::new(OtxConfig::new("key"), cfg);
        let json = sample_pulse_json();
        let pulse = parser.parse_pulse(&json).expect("should parse");
        assert_eq!(pulse.indicators.len(), 1);
    }

    #[test]
    fn test_allowed_types_filter() {
        let cfg = ParseConfig { allowed_types: vec![OtxIndicatorType::Ipv4], ..ParseConfig::default() };
        let parser = OtxPulseParser::new(OtxConfig::new("key"), cfg);
        let json = sample_pulse_json();
        let pulse = parser.parse_pulse(&json).expect("should parse");
        assert!(!pulse.indicators.is_empty());
        assert!(pulse.indicators.iter().all(|i| i.indicator_type == OtxIndicatorType::Ipv4));
    }

    #[test]
    fn test_attack_mapping_present() {
        let pulse = OtxPulse::sample();
        assert!(pulse.has_attack_mapping());
    }
}
