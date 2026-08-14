//! Trait definition for threat intelligence providers and result types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::TiError;
use crate::ioc::{IoC, IoCType};

/// Detailed verdict returned by a TI provider for a single `IoC`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// `true` when the provider classifies this `IoC` as malicious.
    pub malicious: bool,
    /// Provider confidence in the verdict, [0, 100].
    pub confidence: u8,
    /// Classification tags supplied by the provider.
    pub tags: Vec<String>,
    /// Total number of scanning engines / data sources consulted.
    pub engine_count: u32,
    /// Number of engines / sources that flagged the `IoC` as malicious.
    pub positive_count: u32,
    /// Unix timestamp of the earliest known observation.
    pub first_seen: Option<u64>,
    /// Unix timestamp of the most recent observation.
    pub last_seen: Option<u64>,
    /// Human-readable summary from the provider.
    pub description: Option<String>,
    /// Name of the provider that issued this verdict.
    pub provider: String,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] malicious={} confidence={} ({}/{})",
            self.provider, self.malicious, self.confidence, self.positive_count, self.engine_count
        )
    }
}

/// Aggregated result of looking up an `IoC` across one or more providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TiResult {
    /// The `IoC` that was looked up.
    pub ioc: IoC,
    /// Verdicts from all queried providers.
    pub verdicts: Vec<Verdict>,
    /// Additional `IoCs` found to be related to the queried indicator.
    pub related_iocs: Vec<IoC>,
    /// Malware family names associated with this `IoC`.
    pub malware_families: Vec<String>,
    /// Threat actor names associated with this `IoC`.
    pub threat_actors: Vec<String>,
}

impl TiResult {
    /// Create a minimal result wrapping a single `IoC`.
    #[must_use]
    pub const fn new(ioc: IoC) -> Self {
        Self {
            ioc,
            verdicts: Vec::new(),
            related_iocs: Vec::new(),
            malware_families: Vec::new(),
            threat_actors: Vec::new(),
        }
    }

    /// Return `true` if any provider verdict classifies this `IoC` as malicious.
    #[must_use]
    pub fn is_malicious(&self) -> bool {
        self.verdicts.iter().any(|v| v.malicious)
    }

    /// Return the highest confidence score among all verdicts, or `0` if none.
    #[must_use]
    pub fn max_confidence(&self) -> u8 {
        self.verdicts
            .iter()
            .map(|v| v.confidence)
            .max()
            .unwrap_or(0)
    }
}

impl fmt::Display for TiResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TiResult {{ ioc={}, malicious={}, verdicts={} }}",
            self.ioc,
            self.is_malicious(),
            self.verdicts.len()
        )
    }
}

/// Trait implemented by all threat intelligence provider integrations.
#[async_trait]
pub trait TiProvider: Send + Sync {
    /// Display name of this provider.
    fn name(&self) -> &str;

    /// `IoC` types this provider is capable of enriching.
    fn supported_ioc_types(&self) -> Vec<IoCType>;

    /// Look up a single `IoC`.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] when the provider request fails (rate limit, auth,
    /// network, parse).
    async fn lookup(&self, ioc: &IoC) -> Result<TiResult, TiError>;

    /// Look up multiple `IoCs`, defaulting to sequential calls.
    ///
    /// # Errors
    ///
    /// Returns [`TiError`] on the first failure encountered.
    async fn bulk_lookup(&self, iocs: &[IoC]) -> Result<Vec<TiResult>, TiError> {
        let mut results = Vec::with_capacity(iocs.len());
        for ioc in iocs {
            results.push(self.lookup(ioc).await?);
        }
        Ok(results)
    }

    /// Maximum requests this provider accepts per minute.
    fn rate_limit_per_minute(&self) -> u32 {
        60
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::Severity;

    fn make_ioc() -> IoC {
        IoC::new(IoCType::Sha256, "deadbeef".to_string(), "test".to_string())
    }

    fn make_verdict(malicious: bool, confidence: u8) -> Verdict {
        Verdict {
            malicious,
            confidence,
            tags: vec!["test-tag".to_string()],
            engine_count: 70,
            positive_count: if malicious { 40 } else { 0 },
            first_seen: None,
            last_seen: None,
            description: None,
            provider: "mock".to_string(),
        }
    }

    #[test]
    fn test_ti_result_new() {
        let result = TiResult::new(make_ioc());
        assert!(result.verdicts.is_empty());
        assert!(!result.is_malicious());
        assert_eq!(result.max_confidence(), 0);
    }

    #[test]
    fn test_ti_result_is_malicious_true() {
        let mut result = TiResult::new(make_ioc());
        result.verdicts.push(make_verdict(true, 90));
        assert!(result.is_malicious());
    }

    #[test]
    fn test_ti_result_is_malicious_false() {
        let mut result = TiResult::new(make_ioc());
        result.verdicts.push(make_verdict(false, 10));
        assert!(!result.is_malicious());
    }

    #[test]
    fn test_ti_result_max_confidence() {
        let mut result = TiResult::new(make_ioc());
        result.verdicts.push(make_verdict(false, 30));
        result.verdicts.push(make_verdict(true, 85));
        result.verdicts.push(make_verdict(true, 60));
        assert_eq!(result.max_confidence(), 85);
    }

    #[test]
    fn test_verdict_display() {
        let v = make_verdict(true, 95);
        let s = v.to_string();
        assert!(s.contains("mock"));
        assert!(s.contains("true"));
    }

    #[test]
    fn test_ti_result_display() {
        let result = TiResult::new(make_ioc());
        let s = result.to_string();
        assert!(s.contains("TiResult"));
        assert!(s.contains("false"));
    }

    #[test]
    fn test_verdict_serialization() {
        let v = make_verdict(true, 80);
        let json = serde_json::to_string(&v).unwrap();
        let decoded: Verdict = serde_json::from_str(&json).unwrap();
        assert!(decoded.malicious);
        assert_eq!(decoded.confidence, 80);
    }

    #[test]
    fn test_ti_result_related_iocs() {
        let mut result = TiResult::new(make_ioc());
        let related = IoC::new(IoCType::Ip, "1.2.3.4".to_string(), "test".to_string());
        result.related_iocs.push(related);
        assert_eq!(result.related_iocs.len(), 1);
    }

    #[test]
    fn test_ti_result_families_and_actors() {
        let mut result = TiResult::new(make_ioc());
        result.malware_families.push("Emotet".to_string());
        result.threat_actors.push("APT29".to_string());
        assert_eq!(result.malware_families.len(), 1);
        assert_eq!(result.threat_actors.len(), 1);
    }

    #[test]
    fn test_ioc_severity_in_result() {
        let mut ioc = make_ioc();
        ioc.severity = Severity::Critical;
        let result = TiResult::new(ioc);
        assert_eq!(result.ioc.severity, Severity::Critical);
    }
}
