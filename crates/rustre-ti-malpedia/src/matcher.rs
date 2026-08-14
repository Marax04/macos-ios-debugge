//! Deterministic family matching helpers.

use crate::models::MalpediaFamily;

/// Match Malpedia families by hash, canonical name, common name, or aliases.
#[derive(Debug, Clone)]
pub struct FamilyMatcher {
    families: Vec<MalpediaFamily>,
}

impl FamilyMatcher {
    /// Build a matcher from an already-loaded family set.
    #[must_use]
    pub const fn new(families: Vec<MalpediaFamily>) -> Self {
        Self { families }
    }

    /// Return all families that contain the given SHA-256 sample hash.
    #[must_use]
    pub fn by_sha256(&self, sha256: &str) -> Vec<&MalpediaFamily> {
        self.families
            .iter()
            .filter(|family| family.has_sample(sha256))
            .collect()
    }

    /// Return families matching canonical/common names or aliases.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Vec<&MalpediaFamily> {
        let needle = normalize_name(name);
        self.families
            .iter()
            .filter(|family| {
                normalize_name(&family.malpedia_name) == needle
                    || normalize_name(&family.common_name) == needle
                    || family
                        .alt_names
                        .iter()
                        .any(|alias| normalize_name(alias) == needle)
            })
            .collect()
    }

    /// Return the number of indexed families.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.families.len()
    }

    /// Return true when the matcher has no families.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.families.is_empty()
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace([' ', '_'], ".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MalpediaSample;

    #[test]
    fn matches_hash_and_alias() {
        let mut family = MalpediaFamily::new("win.emotet", "Emotet");
        family.alt_names.push("Heodo".to_string());
        family
            .samples
            .push(MalpediaSample::new("ABCDEF", "active", "1"));

        let matcher = FamilyMatcher::new(vec![family]);
        assert_eq!(matcher.by_sha256("abcdef").len(), 1);
        assert_eq!(matcher.by_name("heodo").len(), 1);
        assert_eq!(matcher.by_name("win_emotet").len(), 1);
    }
}
