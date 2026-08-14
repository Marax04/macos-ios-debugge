//! MISP REST API data models.

use serde::{Deserialize, Serialize};

/// MISP event threat level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MispThreatLevel {
    High,
    Medium,
    Low,
    Undefined,
}

impl MispThreatLevel {
    /// Return the numeric MISP threat level ID.
    #[must_use]
    pub const fn as_id(self) -> u8 {
        match self {
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
            Self::Undefined => 4,
        }
    }

    /// Parse from a MISP numeric threat level ID.
    #[must_use]
    pub const fn from_id(id: u8) -> Self {
        match id {
            1 => Self::High,
            2 => Self::Medium,
            3 => Self::Low,
            _ => Self::Undefined,
        }
    }
}

/// MISP event analysis status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MispAnalysis {
    Initial,
    Ongoing,
    Completed,
}

impl MispAnalysis {
    #[must_use]
    pub const fn as_id(self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::Ongoing => 1,
            Self::Completed => 2,
        }
    }

    #[must_use]
    pub const fn from_id(id: u8) -> Self {
        match id {
            1 => Self::Ongoing,
            2 => Self::Completed,
            _ => Self::Initial,
        }
    }
}

/// MISP distribution scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MispDistribution {
    Organization,
    Community,
    Connected,
    All,
    SharingGroup,
    Inherit,
}

impl MispDistribution {
    #[must_use]
    pub const fn as_id(self) -> u8 {
        match self {
            Self::Organization => 0,
            Self::Community => 1,
            Self::Connected => 2,
            Self::All => 3,
            Self::SharingGroup => 4,
            Self::Inherit => 5,
        }
    }
}

/// A MISP tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MispTag {
    pub name: String,
    pub color: String,
}

impl MispTag {
    #[must_use]
    pub fn new(name: impl Into<String>, color: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            color: color.into(),
        }
    }

    /// Create a TLP tag.
    #[must_use]
    pub fn tlp(level: &str) -> Self {
        let color = match level.to_uppercase().as_str() {
            "WHITE" => "#FFFFFF",
            "GREEN" => "#33FF00",
            "AMBER" => "#FFC000",
            "RED" => "#FF0033",
            _ => "#CCCCCC",
        };
        Self::new(format!("tlp:{}", level.to_lowercase()), color)
    }
}

/// A MISP attribute within an event or object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttribute {
    pub id: Option<u64>,
    pub event_id: Option<u64>,
    pub category: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: String,
    pub to_ids: bool,
    pub comment: String,
    pub tags: Vec<MispTag>,
}

impl MispAttribute {
    #[must_use]
    pub fn new(
        category: impl Into<String>,
        ty: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            event_id: None,
            category: category.into(),
            ty: ty.into(),
            value: value.into(),
            to_ids: false,
            comment: String::new(),
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_to_ids(mut self, to_ids: bool) -> Self {
        self.to_ids = to_ids;
        self
    }

    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: MispTag) -> Self {
        self.tags.push(tag);
        self
    }
}

/// A MISP object grouping related attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObject {
    pub name: String,
    pub meta_category: String,
    pub description: String,
    pub attributes: Vec<MispAttribute>,
}

impl MispObject {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        meta_category: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            meta_category: meta_category.into(),
            description: description.into(),
            attributes: Vec::new(),
        }
    }
}

/// A complete MISP event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    pub id: Option<u64>,
    pub uuid: String,
    pub info: String,
    pub threat_level: MispThreatLevel,
    pub analysis: MispAnalysis,
    pub distribution: MispDistribution,
    pub attributes: Vec<MispAttribute>,
    pub objects: Vec<MispObject>,
    pub tags: Vec<MispTag>,
}

impl MispEvent {
    /// Create a new event with a generated UUID.
    #[must_use]
    pub fn new(
        info: impl Into<String>,
        threat_level: MispThreatLevel,
        analysis: MispAnalysis,
        distribution: MispDistribution,
    ) -> Self {
        Self {
            id: None,
            uuid: generate_uuid(),
            info: info.into(),
            threat_level,
            analysis,
            distribution,
            attributes: Vec::new(),
            objects: Vec::new(),
            tags: Vec::new(),
        }
    }

    pub fn add_attribute(&mut self, attr: MispAttribute) {
        self.attributes.push(attr);
    }

    pub fn add_object(&mut self, obj: MispObject) {
        self.objects.push(obj);
    }

    pub fn add_tag(&mut self, tag: MispTag) {
        self.tags.push(tag);
    }

    /// Total attribute count including object attributes.
    #[must_use]
    pub fn total_attribute_count(&self) -> usize {
        self.attributes.len()
            + self
                .objects
                .iter()
                .map(|o| o.attributes.len())
                .sum::<usize>()
    }
}

/// Payload for creating a new MISP event via the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMispEvent {
    /// Event title / info string.
    pub info: String,
    /// Threat level (1=High, 2=Medium, 3=Low, 4=Undefined).
    pub threat_level_id: u8,
    /// Analysis status (0=Initial, 1=Ongoing, 2=Completed).
    pub analysis: u8,
    /// Distribution level.
    pub distribution: MispDistribution,
    /// Optional date string (YYYY-MM-DD). If `None`, today is used by MISP.
    pub date: Option<String>,
    /// Initial tags to add to the event.
    pub tags: Vec<String>,
}

impl NewMispEvent {
    /// Create a new event payload with sensible defaults.
    #[must_use]
    pub fn new(info: impl Into<String>) -> Self {
        Self {
            info: info.into(),
            threat_level_id: 4,
            analysis: 0,
            distribution: MispDistribution::Community,
            date: None,
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_threat_level(mut self, level: MispThreatLevel) -> Self {
        self.threat_level_id = level.as_id();
        self
    }

    #[must_use]
    pub const fn with_analysis(mut self, analysis: MispAnalysis) -> Self {
        self.analysis = analysis.as_id();
        self
    }

    #[must_use]
    pub const fn with_distribution(mut self, distribution: MispDistribution) -> Self {
        self.distribution = distribution;
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// Payload for creating a new MISP attribute via the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMispAttribute {
    /// Attribute category (e.g. "Network activity", "Payload delivery").
    pub category: String,
    /// Attribute type string (e.g. "ip-dst", "sha256").
    #[serde(rename = "type")]
    pub ty: String,
    /// Attribute value.
    pub value: String,
    /// Whether to forward to IDS/SIEM.
    pub to_ids: bool,
    /// Optional free-text comment.
    pub comment: String,
    /// Distribution level for this attribute.
    pub distribution: MispDistribution,
}

impl NewMispAttribute {
    /// Create a new attribute payload.
    #[must_use]
    pub fn new(
        category: impl Into<String>,
        ty: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            category: category.into(),
            ty: ty.into(),
            value: value.into(),
            to_ids: false,
            comment: String::new(),
            distribution: MispDistribution::Inherit,
        }
    }

    #[must_use]
    pub const fn with_to_ids(mut self, to_ids: bool) -> Self {
        self.to_ids = to_ids;
        self
    }

    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    #[must_use]
    pub const fn with_distribution(mut self, distribution: MispDistribution) -> Self {
        self.distribution = distribution;
        self
    }
}

/// Simple deterministic UUID v4-like generator (not cryptographically random,
/// but sufficient for test/display purposes without external dependencies).
fn generate_uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (t & 0xffff_ffff) as u32,
        ((t >> 32) & 0xffff) as u16,
        ((t >> 48) & 0xfff) as u16,
        (0x8000 | ((t >> 60) & 0x3fff)) as u16,
        (t >> 16) & 0xffff_ffff_ffff_u128,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_roundtrip() {
        for (level, id) in [(MispThreatLevel::High, 1u8), (MispThreatLevel::Low, 3)] {
            assert_eq!(level.as_id(), id);
            assert_eq!(MispThreatLevel::from_id(id), level);
        }
    }

    #[test]
    fn test_analysis_roundtrip() {
        for (a, id) in [(MispAnalysis::Initial, 0u8), (MispAnalysis::Completed, 2)] {
            assert_eq!(a.as_id(), id);
            assert_eq!(MispAnalysis::from_id(id), a);
        }
    }

    #[test]
    fn test_event_creation() {
        let mut event = MispEvent::new(
            "Test Event",
            MispThreatLevel::High,
            MispAnalysis::Completed,
            MispDistribution::All,
        );
        event.add_attribute(
            MispAttribute::new("Network activity", "ip-dst", "1.2.3.4").with_to_ids(true),
        );
        event.add_tag(MispTag::tlp("AMBER"));
        assert_eq!(event.total_attribute_count(), 1);
        assert_eq!(event.tags.len(), 1);
        assert!(!event.uuid.is_empty());
    }

    #[test]
    fn test_misp_attribute_builder() {
        let attr = MispAttribute::new("Payload delivery", "sha256", "abc123")
            .with_to_ids(true)
            .with_comment("Malware hash")
            .with_tag(MispTag::tlp("RED"));
        assert!(attr.to_ids);
        assert_eq!(attr.comment, "Malware hash");
        assert_eq!(attr.tags.len(), 1);
    }

    #[test]
    fn test_tlp_tag_colors() {
        assert_eq!(MispTag::tlp("WHITE").color, "#FFFFFF");
        assert_eq!(MispTag::tlp("RED").color, "#FF0033");
    }

    #[test]
    fn test_event_serialization() {
        let event = MispEvent::new(
            "Test",
            MispThreatLevel::Medium,
            MispAnalysis::Initial,
            MispDistribution::Community,
        );
        let json = serde_json::to_string(&event).unwrap();
        let decoded: MispEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.info, "Test");
    }

    #[test]
    fn test_total_attribute_count_with_objects() {
        let mut event = MispEvent::new(
            "Test",
            MispThreatLevel::Low,
            MispAnalysis::Ongoing,
            MispDistribution::Organization,
        );
        event.add_attribute(MispAttribute::new("cat", "ty", "val"));
        let mut obj = MispObject::new("file", "malware", "A file");
        obj.attributes
            .push(MispAttribute::new("Payload delivery", "md5", "abc"));
        obj.attributes
            .push(MispAttribute::new("Payload delivery", "sha256", "def"));
        event.add_object(obj);
        assert_eq!(event.total_attribute_count(), 3);
    }
}
