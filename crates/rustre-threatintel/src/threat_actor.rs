//! Threat actor and MITRE ATT&CK TTP types.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Motivation categories for a threat actor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Motivation {
    /// Financially motivated attacks.
    FinancialGain,
    /// State-sponsored espionage.
    Espionage,
    /// Destructive sabotage.
    Sabotage,
    /// Ideologically motivated hacktivism.
    Hacktivism,
    /// Academic or defensive research.
    Research,
    /// Motivation unknown.
    Unknown,
}

impl fmt::Display for Motivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FinancialGain => "Financial Gain",
            Self::Espionage => "Espionage",
            Self::Sabotage => "Sabotage",
            Self::Hacktivism => "Hacktivism",
            Self::Research => "Research",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

/// A single MITRE ATT&CK technique / sub-technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ttp {
    /// ATT&CK technique ID, e.g. `T1055`.
    pub technique_id: String,
    /// Technique display name.
    pub name: String,
    /// Parent tactic, e.g. `Defense Evasion`.
    pub tactic: String,
    /// Sub-technique identifier, e.g. `001`.
    pub sub_technique: Option<String>,
}

impl fmt::Display for Ttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(sub) = &self.sub_technique {
            write!(
                f,
                "{}.{} — {} ({})",
                self.technique_id, sub, self.name, self.tactic
            )
        } else {
            write!(f, "{} — {} ({})", self.technique_id, self.name, self.tactic)
        }
    }
}

impl Ttp {
    /// Create a new TTP entry.
    #[must_use]
    pub fn new(
        technique_id: impl Into<String>,
        name: impl Into<String>,
        tactic: impl Into<String>,
    ) -> Self {
        let tid: String = technique_id.into();
        // Auto-extract sub_technique from IDs like "T1053.001" (part after the dot).
        let sub = tid
            .split_once('.')
            .map(|(_, sub)| sub.to_string());
        Self {
            technique_id: tid,
            name: name.into(),
            tactic: tactic.into(),
            sub_technique: sub,
        }
    }

    /// Return `true` if this is a sub-technique (has a sub identifier
    /// either explicitly set or embedded in the ATT&CK ID after a `.`).
    #[must_use]
    pub fn is_sub_technique(&self) -> bool {
        self.sub_technique.is_some() || self.technique_id.contains('.')
    }
}

/// A known threat actor (APT group, criminal group, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    /// Database row identifier (absent before first persist).
    pub id: Option<u64>,
    /// Primary name (e.g. `APT29`).
    pub name: String,
    /// Alternative names / aliases.
    pub aliases: Vec<String>,
    /// Attributed primary motivation.
    pub motivation: Motivation,
    /// ISO-3166-1 alpha-2 country code of suspected origin.
    pub origin_country: Option<String>,
    /// Narrative description.
    pub description: Option<String>,
    /// Known ATT&CK techniques attributed to this actor.
    pub ttps: Vec<Ttp>,
    /// Unix timestamp of earliest known activity.
    pub first_seen: Option<u64>,
    /// Unix timestamp of most recent known activity.
    pub last_seen: Option<u64>,
    /// Analyst confidence in the attribution, [0, 100].
    pub attribution_confidence: u8,
}

impl ThreatActor {
    /// Create a minimal threat actor record.
    #[must_use]
    pub const fn new(name: String, motivation: Motivation) -> Self {
        Self {
            id: None,
            name,
            aliases: Vec::new(),
            motivation,
            origin_country: None,
            description: None,
            ttps: Vec::new(),
            first_seen: None,
            last_seen: None,
            attribution_confidence: 50,
        }
    }

    /// Builder: add a TTP.
    #[must_use]
    pub fn with_ttp(mut self, ttp: Ttp) -> Self {
        self.ttps.push(ttp);
        self
    }
}

impl fmt::Display for ThreatActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] (confidence={})",
            self.name, self.motivation, self.attribution_confidence
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_actor_new() {
        let actor = ThreatActor::new("APT29".to_string(), Motivation::Espionage);
        assert_eq!(actor.name, "APT29");
        assert_eq!(actor.motivation, Motivation::Espionage);
        assert!(actor.id.is_none());
        assert_eq!(actor.attribution_confidence, 50);
    }

    #[test]
    fn test_threat_actor_with_ttp() {
        let ttp = Ttp::new("T1055", "Process Injection", "Defense Evasion");
        let actor = ThreatActor::new("APT29".to_string(), Motivation::Espionage).with_ttp(ttp);
        assert_eq!(actor.ttps.len(), 1);
        assert_eq!(actor.ttps[0].technique_id, "T1055");
    }

    #[test]
    fn test_motivation_display() {
        assert_eq!(Motivation::FinancialGain.to_string(), "Financial Gain");
        assert_eq!(Motivation::Espionage.to_string(), "Espionage");
        assert_eq!(Motivation::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_ttp_display_no_sub() {
        let ttp = Ttp::new("T1055", "Process Injection", "Defense Evasion");
        let s = ttp.to_string();
        assert!(s.contains("T1055"));
        assert!(s.contains("Process Injection"));
        assert!(!ttp.is_sub_technique());
    }

    #[test]
    fn test_ttp_display_with_sub() {
        let ttp = Ttp {
            technique_id: "T1055".to_string(),
            name: "Dynamic-link Library Injection".to_string(),
            tactic: "Defense Evasion".to_string(),
            sub_technique: Some("001".to_string()),
        };
        assert!(ttp.is_sub_technique());
        let s = ttp.to_string();
        assert!(s.contains("T1055.001"));
    }

    #[test]
    fn test_threat_actor_display() {
        let actor = ThreatActor::new("Lazarus".to_string(), Motivation::FinancialGain);
        let s = actor.to_string();
        assert!(s.contains("Lazarus"));
        assert!(s.contains("Financial Gain"));
    }

    #[test]
    fn test_threat_actor_serialization() {
        let actor = ThreatActor::new("APT29".to_string(), Motivation::Espionage);
        let json = serde_json::to_string(&actor).unwrap();
        let decoded: ThreatActor = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "APT29");
        assert_eq!(decoded.motivation, Motivation::Espionage);
    }

    #[test]
    fn test_all_motivations() {
        let motivations = [
            Motivation::FinancialGain,
            Motivation::Espionage,
            Motivation::Sabotage,
            Motivation::Hacktivism,
            Motivation::Research,
            Motivation::Unknown,
        ];
        for m in &motivations {
            assert!(!m.to_string().is_empty());
        }
    }
}
