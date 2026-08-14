//! Malpedia data models.

use serde::{Deserialize, Serialize};

/// A known malware sample on Malpedia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalpediaSample {
    pub sha256: String,
    pub status: String,
    pub version: String,
}

impl MalpediaSample {
    #[must_use]
    pub fn new(
        sha256: impl Into<String>,
        status: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            sha256: sha256.into(),
            status: status.into(),
            version: version.into(),
        }
    }

    /// Return `true` if this sample has been confirmed (status == "active").
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.eq_ignore_ascii_case("active")
    }
}

/// A malware family entry from Malpedia.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaFamily {
    /// Canonical Malpedia name (e.g. `win.emotet`).
    pub malpedia_name: String,
    /// Common display name (e.g. `Emotet`).
    pub common_name: String,
    /// Description text.
    pub description: String,
    /// Reference URLs.
    pub urls: Vec<String>,
    /// Alternative names.
    pub alt_names: Vec<String>,
    /// Associated threat actor names.
    pub actors: Vec<String>,
    /// Known samples.
    pub samples: Vec<MalpediaSample>,
}

impl MalpediaFamily {
    #[must_use]
    pub fn new(malpedia_name: impl Into<String>, common_name: impl Into<String>) -> Self {
        Self {
            malpedia_name: malpedia_name.into(),
            common_name: common_name.into(),
            description: String::new(),
            urls: Vec::new(),
            alt_names: Vec::new(),
            actors: Vec::new(),
            samples: Vec::new(),
        }
    }

    /// Return `true` if the given SHA-256 matches any known sample.
    #[must_use]
    pub fn has_sample(&self, sha256: &str) -> bool {
        self.samples
            .iter()
            .any(|s| s.sha256.eq_ignore_ascii_case(sha256))
    }

    /// Return the number of associated samples.
    #[must_use]
    pub const fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

/// A threat actor entry from Malpedia.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaActor {
    /// Primary actor name.
    pub name: String,
    /// Two-letter country code of suspected origin.
    pub country: String,
    /// Narrative description.
    pub description: String,
    /// Malware families attributed to this actor.
    pub families: Vec<String>,
}

impl MalpediaActor {
    #[must_use]
    pub fn new(name: impl Into<String>, country: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            country: country.into(),
            description: String::new(),
            families: Vec::new(),
        }
    }
}

/// Type alias: `MalpediaThreatActor` is the same as [`MalpediaActor`].
pub type MalpediaThreatActor = MalpediaActor;

/// Lightweight summary of a Malpedia malware family (returned by `list_families`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaFamilySummary {
    /// Canonical Malpedia name (e.g. `win.emotet`).
    pub malpedia_name: String,
    /// Common display name (e.g. `Emotet`).
    pub common_name: String,
}

impl MalpediaFamilySummary {
    #[must_use]
    pub fn new(malpedia_name: impl Into<String>, common_name: impl Into<String>) -> Self {
        Self {
            malpedia_name: malpedia_name.into(),
            common_name: common_name.into(),
        }
    }
}

impl From<&MalpediaFamily> for MalpediaFamilySummary {
    fn from(f: &MalpediaFamily) -> Self {
        Self::new(f.malpedia_name.clone(), f.common_name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_family_has_sample() {
        let mut fam = MalpediaFamily::new("win.emotet", "Emotet");
        fam.samples
            .push(MalpediaSample::new("DEADBEEF", "active", "1.0"));
        assert!(fam.has_sample("deadbeef"));
        assert!(fam.has_sample("DEADBEEF"));
        assert!(!fam.has_sample("nothere"));
    }

    #[test]
    fn test_sample_is_active() {
        let s = MalpediaSample::new("abc", "active", "1.0");
        assert!(s.is_active());
        let s2 = MalpediaSample::new("abc", "deprecated", "0.9");
        assert!(!s2.is_active());
    }

    #[test]
    fn test_family_serialization() {
        let fam = MalpediaFamily::new("win.wannacry", "WannaCry");
        let json = serde_json::to_string(&fam).unwrap();
        let decoded: MalpediaFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.malpedia_name, "win.wannacry");
    }

    #[test]
    fn test_actor_serialization() {
        let actor = MalpediaActor::new("Lazarus Group", "KP");
        let json = serde_json::to_string(&actor).unwrap();
        let decoded: MalpediaActor = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.country, "KP");
    }
}
