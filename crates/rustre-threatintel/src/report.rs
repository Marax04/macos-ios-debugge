//! Threat report types including TLP classification.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ioc::IoC;
use crate::threat_actor::Ttp;

/// Traffic Light Protocol classification level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TlpLevel {
    /// Unrestricted — public disclosure allowed.
    White,
    /// Community — limited sharing within a community.
    Green,
    /// Limited — recipient-only, no further sharing without permission.
    Amber,
    /// Restricted — eyes-only, no sharing.
    Red,
}

impl fmt::Display for TlpLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::White => "TLP:WHITE",
            Self::Green => "TLP:GREEN",
            Self::Amber => "TLP:AMBER",
            Self::Red => "TLP:RED",
        };
        f.write_str(s)
    }
}

/// A structured threat intelligence report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    /// Database row identifier (absent before first persist).
    pub id: Option<u64>,
    /// Report title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// TLP handling classification.
    pub tlp: TlpLevel,
    /// `IoCs` documented in this report.
    pub iocs: Vec<IoC>,
    /// Malware family names documented in this report.
    pub malware_families: Vec<String>,
    /// Threat actor names attributed in this report.
    pub threat_actors: Vec<String>,
    /// MITRE ATT&CK TTPs observed.
    pub ttps: Vec<Ttp>,
    /// Unix timestamp when this report was created.
    pub created_at: u64,
    /// Unix timestamp when this report was last updated.
    pub updated_at: u64,
    /// Author name or handle.
    pub author: String,
    /// Classification tags.
    pub tags: Vec<String>,
}

impl ThreatReport {
    /// Create a new empty threat report.
    #[must_use]
    pub fn new(title: String, author: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id: None,
            title,
            description: String::new(),
            tlp: TlpLevel::White,
            iocs: Vec::new(),
            malware_families: Vec::new(),
            threat_actors: Vec::new(),
            ttps: Vec::new(),
            created_at: now,
            updated_at: now,
            author,
            tags: Vec::new(),
        }
    }

    /// Add an `IoC` to this report.
    pub fn add_ioc(&mut self, ioc: IoC) {
        self.iocs.push(ioc);
    }

    /// Count of `IoCs` directly attached to this report.
    #[must_use]
    pub const fn ioc_count(&self) -> usize {
        self.iocs.len()
    }

    /// Serialise this report to pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl fmt::Display for ThreatReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] \"{}\" by {} — {} IoC(s)",
            self.tlp,
            self.title,
            self.author,
            self.iocs.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::{IoC, IoCType};

    fn make_report() -> ThreatReport {
        ThreatReport::new("Test Report".to_string(), "analyst".to_string())
    }

    #[test]
    fn test_report_new_defaults() {
        let r = make_report();
        assert_eq!(r.title, "Test Report");
        assert_eq!(r.author, "analyst");
        assert_eq!(r.tlp, TlpLevel::White);
        assert!(r.iocs.is_empty());
        assert!(r.id.is_none());
    }

    #[test]
    fn test_report_add_ioc() {
        let mut r = make_report();
        r.add_ioc(IoC::new(
            IoCType::Sha256,
            "abc".to_string(),
            "test".to_string(),
        ));
        r.add_ioc(IoC::new(
            IoCType::Ip,
            "1.2.3.4".to_string(),
            "test".to_string(),
        ));
        assert_eq!(r.ioc_count(), 2);
    }

    #[test]
    fn test_tlp_ordering() {
        assert!(TlpLevel::White < TlpLevel::Green);
        assert!(TlpLevel::Green < TlpLevel::Amber);
        assert!(TlpLevel::Amber < TlpLevel::Red);
    }

    #[test]
    fn test_tlp_display() {
        assert_eq!(TlpLevel::White.to_string(), "TLP:WHITE");
        assert_eq!(TlpLevel::Green.to_string(), "TLP:GREEN");
        assert_eq!(TlpLevel::Amber.to_string(), "TLP:AMBER");
        assert_eq!(TlpLevel::Red.to_string(), "TLP:RED");
    }

    #[test]
    fn test_report_to_json() {
        let r = make_report();
        let json = r.to_json().unwrap();
        assert!(json.contains("Test Report"));
        assert!(json.contains("analyst"));
    }

    #[test]
    fn test_report_display() {
        let r = make_report();
        let s = r.to_string();
        assert!(s.contains("TLP:WHITE"));
        assert!(s.contains("Test Report"));
        assert!(s.contains("analyst"));
    }

    #[test]
    fn test_report_serialization() {
        let r = make_report();
        let json = serde_json::to_string(&r).unwrap();
        let decoded: ThreatReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.title, "Test Report");
        assert_eq!(decoded.tlp, TlpLevel::White);
    }

    #[test]
    fn test_report_families_and_actors() {
        let mut r = make_report();
        r.malware_families.push("Emotet".to_string());
        r.threat_actors.push("APT29".to_string());
        assert_eq!(r.malware_families.len(), 1);
        assert_eq!(r.threat_actors.len(), 1);
    }
}
