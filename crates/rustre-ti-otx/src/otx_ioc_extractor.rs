//! OTX IOC extractor.
//!
//! Extracts, deduplicates, and categorises Indicators of Compromise from
//! `OtxPulse` objects returned by `OtxPulseParser`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::otx_pulse_parser::{OtxIndicator, OtxIndicatorType, OtxPulse};
use crate::OtxError;

// ─── IocType ─────────────────────────────────────────────────────────────────

/// High-level IOC category used by the extractor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHashMd5,
    FileHashSha1,
    FileHashSha256,
    Email,
    FilePath,
    Mutex,
    Cve,
    Yara,
    Other,
}

impl fmt::Display for IocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::IpAddress => "ip_address",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::FileHashMd5 => "md5",
            Self::FileHashSha1 => "sha1",
            Self::FileHashSha256 => "sha256",
            Self::Email => "email",
            Self::FilePath => "file_path",
            Self::Mutex => "mutex",
            Self::Cve => "cve",
            Self::Yara => "yara",
            Self::Other => "other",
        };
        write!(f, "{s}")
    }
}

impl From<&OtxIndicatorType> for IocType {
    fn from(t: &OtxIndicatorType) -> Self {
        match t {
            OtxIndicatorType::Ipv4 | OtxIndicatorType::Ipv6
            | OtxIndicatorType::CidrIpv4 | OtxIndicatorType::CidrIpv6 => Self::IpAddress,
            OtxIndicatorType::Domain | OtxIndicatorType::Hostname => Self::Domain,
            OtxIndicatorType::Url | OtxIndicatorType::Uri => Self::Url,
            OtxIndicatorType::FileHashMd5 => Self::FileHashMd5,
            OtxIndicatorType::FileHashSha1 => Self::FileHashSha1,
            OtxIndicatorType::FileHashSha256 => Self::FileHashSha256,
            OtxIndicatorType::Email => Self::Email,
            OtxIndicatorType::FilePath => Self::FilePath,
            OtxIndicatorType::Mutex => Self::Mutex,
            OtxIndicatorType::Cve => Self::Cve,
            OtxIndicatorType::Yara => Self::Yara,
            OtxIndicatorType::Other => Self::Other,
        }
    }
}

// ─── OtxIoc ──────────────────────────────────────────────────────────────────

/// A single de-duplicated IOC extracted from one or more OTX pulses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxIoc {
    /// IOC value (e.g. IP address, domain, hash).
    pub value: String,
    /// Categorised IOC type.
    pub ioc_type: IocType,
    /// Original OTX indicator type.
    pub raw_type: String,
    /// Pulse IDs that reference this IOC.
    pub pulse_ids: Vec<String>,
    /// Description from the first pulse that mentioned this IOC.
    pub description: Option<String>,
    /// Number of pulses that contain this IOC (popularity).
    pub occurrence_count: usize,
    /// RFC 3339 earliest creation date across all pulses.
    pub first_seen: String,
    /// RFC 3339 latest modification date across all pulses.
    pub last_seen: String,
    /// Whether this IOC is tagged as active across all observing pulses.
    pub is_active: bool,
}

impl OtxIoc {
    /// Create a new IOC from a single indicator observation.
    #[must_use]
    pub fn from_indicator(indicator: &OtxIndicator, pulse_id: impl Into<String>) -> Self {
        let ioc_type = IocType::from(&indicator.indicator_type);
        Self {
            value: indicator.indicator.clone(),
            ioc_type,
            raw_type: indicator.indicator_type.to_string(),
            pulse_ids: vec![pulse_id.into()],
            description: indicator.description.clone(),
            occurrence_count: 1,
            first_seen: indicator.created.clone(),
            last_seen: indicator.created.clone(),
            is_active: indicator.is_active,
        }
    }

    /// Merge another observation of the same IOC from a different pulse.
    ///
    /// `occurrence_count` tracks the number of **distinct pulses** that
    /// reference this IOC, so it is incremented only when `pulse_id` is new.
    pub fn merge(&mut self, indicator: &OtxIndicator, pulse_id: String, modified: &str) {
        if !self.pulse_ids.contains(&pulse_id) {
            self.pulse_ids.push(pulse_id);
            self.occurrence_count += 1;
        }
        // Keep earliest first_seen
        if indicator.created.as_str() < self.first_seen.as_str() {
            self.first_seen.clone_from(&indicator.created);
        }
        // Keep latest last_seen
        if modified > self.last_seen.as_str() {
            self.last_seen = modified.to_string();
        }
        // Stay active if any pulse says so
        if indicator.is_active {
            self.is_active = true;
        }
    }

    /// Returns `true` if this is a network-layer IOC.
    #[must_use]
    pub const fn is_network(&self) -> bool {
        matches!(self.ioc_type, IocType::IpAddress | IocType::Domain | IocType::Url)
    }

    /// Returns `true` if this is a file hash IOC.
    #[must_use]
    pub const fn is_hash(&self) -> bool {
        matches!(
            self.ioc_type,
            IocType::FileHashMd5 | IocType::FileHashSha1 | IocType::FileHashSha256
        )
    }
}

// ─── ExtractionConfig ────────────────────────────────────────────────────────

/// Configuration for the IOC extractor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionConfig {
    /// Only extract IOCs of these types. Empty = extract all.
    pub include_types: Vec<IocType>,
    /// Skip IOCs whose `occurrence_count` is below this threshold.
    pub min_occurrences: usize,
    /// Skip inactive IOCs.
    pub skip_inactive: bool,
    /// Maximum total IOCs to return. None = unlimited.
    pub max_iocs: Option<usize>,
    /// Deduplicate IOCs across pulses (always done by value).
    pub deduplicate: bool,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            include_types: vec![],
            min_occurrences: 1,
            skip_inactive: false,
            deduplicate: true,
            max_iocs: None,
        }
    }
}

// ─── ExtractionResult ────────────────────────────────────────────────────────

/// The result of an IOC extraction pass.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtractionResult {
    /// All extracted IOCs (deduplicated).
    pub iocs: Vec<OtxIoc>,
    /// Number of raw indicators processed.
    pub raw_indicator_count: usize,
    /// Number of duplicates collapsed.
    pub duplicate_count: usize,
    /// Number of IOCs excluded by the filter.
    pub excluded_count: usize,
}

impl ExtractionResult {
    /// All IP address IOCs.
    #[must_use]
    pub fn ips(&self) -> Vec<&OtxIoc> {
        self.iocs.iter().filter(|i| i.ioc_type == IocType::IpAddress).collect()
    }

    /// All domain IOCs.
    #[must_use]
    pub fn domains(&self) -> Vec<&OtxIoc> {
        self.iocs.iter().filter(|i| i.ioc_type == IocType::Domain).collect()
    }

    /// All URL IOCs.
    #[must_use]
    pub fn urls(&self) -> Vec<&OtxIoc> {
        self.iocs.iter().filter(|i| i.ioc_type == IocType::Url).collect()
    }

    /// All hash IOCs (MD5, SHA1, SHA256).
    #[must_use]
    pub fn hashes(&self) -> Vec<&OtxIoc> {
        self.iocs.iter().filter(|i| i.is_hash()).collect()
    }

    /// Group IOCs by type.
    #[must_use]
    pub fn grouped(&self) -> HashMap<String, Vec<&OtxIoc>> {
        let mut map: HashMap<String, Vec<&OtxIoc>> = HashMap::new();
        for ioc in &self.iocs {
            map.entry(ioc.ioc_type.to_string()).or_default().push(ioc);
        }
        map
    }

    /// Count IOCs per type.
    #[must_use]
    pub fn type_counts(&self) -> HashMap<String, usize> {
        self.grouped()
            .into_iter()
            .map(|(k, v)| (k, v.len()))
            .collect()
    }

    /// IOCs sorted by occurrence count (most frequent first).
    #[must_use]
    pub fn by_frequency(&self) -> Vec<&OtxIoc> {
        let mut sorted: Vec<&OtxIoc> = self.iocs.iter().collect();
        sorted.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));
        sorted
    }
}

// ─── OtxIocExtractor ─────────────────────────────────────────────────────────

/// Extracts and deduplicates IOCs from one or more `OtxPulse` objects.
pub struct OtxIocExtractor {
    config: ExtractionConfig,
}

impl OtxIocExtractor {
    /// Create a new extractor with the given config.
    #[must_use]
    pub const fn new(config: ExtractionConfig) -> Self {
        Self { config }
    }

    /// Create an extractor with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(ExtractionConfig::default())
    }

    /// Extract IOCs from a single pulse.
    ///
    /// # Errors
    /// Returns `OtxError::InvalidInput` if the pulse ID is empty.
    pub fn extract_from_pulse(&self, pulse: &OtxPulse) -> Result<ExtractionResult, OtxError> {
        if pulse.id.is_empty() {
            return Err(OtxError::InvalidInput("pulse id must not be empty".into()));
        }
        self.extract_iocs(std::slice::from_ref(pulse))
    }

    /// Extract and deduplicate IOCs from a collection of pulses.
    ///
    /// # Errors
    /// Returns `OtxError` if extraction fails.
    pub fn extract_iocs(&self, pulses: &[OtxPulse]) -> Result<ExtractionResult, OtxError> {
        let mut dedup: HashMap<String, OtxIoc> = HashMap::new();
        let mut raw_count = 0usize;

        for pulse in pulses {
            for indicator in &pulse.indicators {
                raw_count += 1;

                let key = format!("{}::{}", indicator.indicator_type, indicator.indicator);

                if self.config.deduplicate {
                    if let Some(existing) = dedup.get_mut(&key) {
                        existing.merge(indicator, pulse.id.clone(), &pulse.modified);
                    } else {
                        dedup.insert(
                            key,
                            OtxIoc::from_indicator(indicator, pulse.id.clone()),
                        );
                    }
                } else {
                    let ioc = OtxIoc::from_indicator(indicator, pulse.id.clone());
                    let unique_key = format!("{key}::{}", dedup.len());
                    dedup.insert(unique_key, ioc);
                }
            }
        }

        let duplicate_count = raw_count.saturating_sub(dedup.len());
        let mut iocs: Vec<OtxIoc> = dedup.into_values().collect();

        // Apply filters
        let before_filter = iocs.len();
        iocs.retain(|ioc| {
            // Type filter
            if !self.config.include_types.is_empty()
                && !self.config.include_types.contains(&ioc.ioc_type)
            {
                return false;
            }
            // Occurrence threshold
            if ioc.occurrence_count < self.config.min_occurrences {
                return false;
            }
            // Active filter
            if self.config.skip_inactive && !ioc.is_active {
                return false;
            }
            true
        });
        let excluded_count = before_filter.saturating_sub(iocs.len());

        // Sort for determinism: by type then value
        iocs.sort_by(|a, b| {
            a.ioc_type
                .to_string()
                .cmp(&b.ioc_type.to_string())
                .then(a.value.cmp(&b.value))
        });

        if let Some(max) = self.config.max_iocs {
            iocs.truncate(max);
        }

        Ok(ExtractionResult {
            iocs,
            raw_indicator_count: raw_count,
            duplicate_count,
            excluded_count,
        })
    }

    /// Extract only network IOCs (IPs, domains, URLs).
    ///
    /// # Errors
    /// Returns `OtxError` if extraction fails.
    pub fn extract_network_iocs(&self, pulses: &[OtxPulse]) -> Result<Vec<OtxIoc>, OtxError> {
        let result = self.extract_iocs(pulses)?;
        Ok(result.iocs.into_iter().filter(OtxIoc::is_network).collect())
    }

    /// Extract only hash IOCs.
    ///
    /// # Errors
    /// Returns `OtxError` if extraction fails.
    pub fn extract_hash_iocs(&self, pulses: &[OtxPulse]) -> Result<Vec<OtxIoc>, OtxError> {
        let result = self.extract_iocs(pulses)?;
        Ok(result.iocs.into_iter().filter(OtxIoc::is_hash).collect())
    }

    /// Return only IOCs seen in more than one pulse.
    ///
    /// # Errors
    /// Returns `OtxError` if extraction fails.
    pub fn extract_corroborated_iocs(
        &self,
        pulses: &[OtxPulse],
        min_pulses: usize,
    ) -> Result<Vec<OtxIoc>, OtxError> {
        let result = self.extract_iocs(pulses)?;
        Ok(result
            .iocs
            .into_iter()
            .filter(|i| i.pulse_ids.len() >= min_pulses)
            .collect())
    }

    /// Compute a simple threat score for a single IOC based on its type and
    /// occurrence frequency across pulses.
    #[must_use]
    pub fn score_ioc(ioc: &OtxIoc) -> u8 {
        let type_score: u8 = match ioc.ioc_type {
            IocType::IpAddress | IocType::Cve => 20,
            IocType::Domain | IocType::Yara => 18,
            IocType::Url | IocType::FileHashSha256 => 15,
            IocType::FileHashMd5 => 10,
            IocType::FileHashSha1 | IocType::Mutex => 12,
            IocType::Email => 8,
            IocType::FilePath => 5,
            IocType::Other => 3,
        };
        let frequency_bonus = u8::try_from(ioc.occurrence_count.min(5)).unwrap_or(u8::MAX) * 4;
        type_score.saturating_add(frequency_bonus).min(100)
    }

    /// Extract all unique pulse IDs that contributed IOCs in the result.
    #[must_use]
    pub fn contributing_pulses(result: &ExtractionResult) -> HashSet<String> {
        result
            .iocs
            .iter()
            .flat_map(|i| i.pulse_ids.iter().cloned())
            .collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otx_pulse_parser::OtxPulse;

    fn make_extractor() -> OtxIocExtractor {
        OtxIocExtractor::default_config()
    }

    #[test]
    fn test_extract_from_sample_pulse() {
        let extractor = make_extractor();
        let pulse = OtxPulse::sample();
        let result = extractor.extract_from_pulse(&pulse).expect("should extract");
        assert_eq!(result.iocs.len(), 3);
        assert_eq!(result.raw_indicator_count, 3);
    }

    #[test]
    fn test_ip_extraction() {
        let extractor = make_extractor();
        let pulse = OtxPulse::sample();
        let result = extractor.extract_from_pulse(&pulse).unwrap();
        assert_eq!(result.ips().len(), 1);
    }

    #[test]
    fn test_domain_extraction() {
        let extractor = make_extractor();
        let result = extractor.extract_from_pulse(&OtxPulse::sample()).unwrap();
        assert_eq!(result.domains().len(), 1);
    }

    #[test]
    fn test_hash_extraction() {
        let extractor = make_extractor();
        let result = extractor.extract_from_pulse(&OtxPulse::sample()).unwrap();
        assert_eq!(result.hashes().len(), 1);
    }

    #[test]
    fn test_deduplication_across_pulses() {
        let extractor = make_extractor();
        let p1 = OtxPulse::sample();
        let mut p2 = OtxPulse::sample();
        p2.id = "pulse-xyz-456".to_string();
        let result = extractor.extract_iocs(&[p1, p2]).unwrap();
        // Same 3 IOCs across 2 pulses => 3 unique, each with occurrence_count = 2
        assert_eq!(result.iocs.len(), 3);
        assert!(result.iocs.iter().all(|i| i.occurrence_count == 2));
        assert_eq!(result.duplicate_count, 3);
    }

    #[test]
    fn test_type_filter() {
        let config = ExtractionConfig {
            include_types: vec![IocType::IpAddress],
            ..Default::default()
        };
        let extractor = OtxIocExtractor::new(config);
        let result = extractor.extract_from_pulse(&OtxPulse::sample()).unwrap();
        assert_eq!(result.iocs.len(), 1);
        assert_eq!(result.iocs[0].ioc_type, IocType::IpAddress);
    }

    #[test]
    fn test_by_frequency_order() {
        let extractor = make_extractor();
        let p1 = OtxPulse::sample();
        let mut p2 = OtxPulse::sample();
        p2.id = "pulse-xyz".to_string();
        // Remove all but first indicator from p2 so only IP has higher freq
        p2.indicators.truncate(1);
        let result = extractor.extract_iocs(&[p1, p2]).unwrap();
        let sorted = result.by_frequency();
        assert_eq!(sorted[0].ioc_type, IocType::IpAddress);
    }

    #[test]
    fn test_score_ioc() {
        let ioc = OtxIoc {
            value: "1.2.3.4".to_string(),
            ioc_type: IocType::IpAddress,
            raw_type: "IPv4".to_string(),
            pulse_ids: vec!["p1".to_string(), "p2".to_string()],
            description: None,
            occurrence_count: 2,
            first_seen: "2024-01-01T00:00:00Z".to_string(),
            last_seen: "2024-01-02T00:00:00Z".to_string(),
            is_active: true,
        };
        let score = OtxIocExtractor::score_ioc(&ioc);
        assert!(score > 20);
    }

    #[test]
    fn test_empty_pulse_id_error() {
        let extractor = make_extractor();
        let mut pulse = OtxPulse::sample();
        pulse.id = String::new();
        assert!(extractor.extract_from_pulse(&pulse).is_err());
    }
}
