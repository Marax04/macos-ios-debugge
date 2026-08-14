//! Malpedia database statistics and analytics.
//!
//! Computes aggregate statistics over cached Malpedia data including
//! family distribution by type, actor attribution coverage, and sample
//! timeline analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::models::{MalpediaActor, MalpediaFamily};

// ---------------------------------------------------------------------------
// DatabaseStats
// ---------------------------------------------------------------------------

/// High-level statistics about a Malpedia cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    /// Total number of malware families.
    pub family_count: usize,
    /// Total number of threat actors.
    pub actor_count: usize,
    /// Total number of samples across all families.
    pub sample_count: usize,
    /// Number of active samples.
    pub active_sample_count: usize,
    /// Fraction of samples that are active.
    pub active_fraction: f64,
    /// Number of families with at least one attribution.
    pub families_with_actors: usize,
    /// Average samples per family.
    pub avg_samples_per_family: f64,
    /// Families with the most samples.
    pub top_families_by_sample_count: Vec<(String, usize)>,
    /// Actors attributed to the most families.
    pub top_actors_by_family_count: Vec<(String, usize)>,
}

impl DatabaseStats {
    /// Compute statistics from slices of families and actors.
    #[must_use]
    pub fn compute(families: &[MalpediaFamily], actors: &[MalpediaActor]) -> Self {
        let family_count = families.len();
        let actor_count = actors.len();

        let sample_count: usize = families.iter().map(|f| f.samples.len()).sum();
        let active_sample_count: usize = families
            .iter()
            .flat_map(|f| &f.samples)
            .filter(|s| s.is_active())
            .count();

        let active_fraction = if sample_count == 0 {
            0.0
        } else {
            f64::from(u32::try_from(active_sample_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(sample_count).unwrap_or(u32::MAX))
        };

        let families_with_actors = families.iter().filter(|f| !f.actors.is_empty()).count();

        let avg_samples_per_family = if family_count == 0 {
            0.0
        } else {
            f64::from(u32::try_from(sample_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(family_count).unwrap_or(u32::MAX))
        };

        // Top 5 families by sample count
        let mut family_sample_counts: Vec<(String, usize)> = families
            .iter()
            .map(|f| (f.malpedia_name.clone(), f.samples.len()))
            .collect();
        family_sample_counts.sort_by(|a, b| b.1.cmp(&a.1));
        family_sample_counts.truncate(5);

        // Top 5 actors by attributed family count
        let mut actor_family_counts: Vec<(String, usize)> = actors
            .iter()
            .map(|a| (a.name.clone(), a.families.len()))
            .collect();
        actor_family_counts.sort_by(|a, b| b.1.cmp(&a.1));
        actor_family_counts.truncate(5);

        Self {
            family_count,
            actor_count,
            sample_count,
            active_sample_count,
            active_fraction,
            families_with_actors,
            avg_samples_per_family,
            top_families_by_sample_count: family_sample_counts,
            top_actors_by_family_count: actor_family_counts,
        }
    }

    /// Attribution coverage as a fraction of families with at least one actor.
    #[must_use]
    pub fn attribution_coverage(&self) -> f64 {
        if self.family_count == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.families_with_actors).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.family_count).unwrap_or(u32::MAX))
        }
    }
}

impl fmt::Display for DatabaseStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Malpedia: {} families / {} actors / {} samples ({:.0}% active)",
            self.family_count,
            self.actor_count,
            self.sample_count,
            self.active_fraction * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// FamilyDistribution
// ---------------------------------------------------------------------------

/// Distribution of malware families by a categorical dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyDistribution {
    /// Label of the distribution (e.g. `"platform"`, `"country"`).
    pub dimension: String,
    /// Category → count mapping.
    pub buckets: HashMap<String, usize>,
}

impl FamilyDistribution {
    /// Create an empty distribution.
    #[must_use]
    pub fn new(dimension: impl Into<String>) -> Self {
        Self {
            dimension: dimension.into(),
            buckets: HashMap::new(),
        }
    }

    /// Increment the counter for `category`.
    pub fn record(&mut self, category: impl Into<String>) {
        *self.buckets.entry(category.into()).or_insert(0) += 1;
    }

    /// Return the most common category.
    #[must_use]
    pub fn mode(&self) -> Option<(&str, usize)> {
        self.buckets
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(k, c)| (k.as_str(), *c))
    }

    /// Total count across all buckets.
    #[must_use]
    pub fn total(&self) -> usize {
        self.buckets.values().sum()
    }

    /// Return buckets sorted by count (descending).
    #[must_use]
    pub fn sorted_buckets(&self) -> Vec<(&str, usize)> {
        let mut v: Vec<(&str, usize)> =
            self.buckets.iter().map(|(k, &c)| (k.as_str(), c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

impl fmt::Display for FamilyDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Distribution({}) — {} buckets, {} total",
            self.dimension,
            self.buckets.len(),
            self.total()
        )
    }
}

/// Compute the platform distribution from Malpedia family names.
///
/// Extracts the platform prefix (e.g. `win`, `elf`, `osx`) from the canonical
/// Malpedia name format `<platform>.<name>`.
#[must_use]
pub fn platform_distribution(families: &[MalpediaFamily]) -> FamilyDistribution {
    let mut dist = FamilyDistribution::new("platform");
    for fam in families {
        let platform = fam
            .malpedia_name
            .split('.')
            .next()
            .unwrap_or("unknown")
            .to_string();
        dist.record(platform);
    }
    dist
}

/// Compute the country distribution from actor records.
#[must_use]
pub fn actor_country_distribution(actors: &[MalpediaActor]) -> FamilyDistribution {
    let mut dist = FamilyDistribution::new("actor_country");
    for actor in actors {
        dist.record(actor.country.clone());
    }
    dist
}

// ---------------------------------------------------------------------------
// FamilyTimeline
// ---------------------------------------------------------------------------

/// Timeline entry for a malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Malpedia family name.
    pub family: String,
    /// Year of first observation (from Malpedia metadata).
    pub first_year: Option<u32>,
    /// Year of most recent observation.
    pub last_year: Option<u32>,
    /// Number of samples.
    pub sample_count: usize,
}

impl TimelineEntry {
    /// Construct from a `MalpediaFamily` and optional year metadata.
    #[must_use]
    pub fn new(family: &MalpediaFamily, first_year: Option<u32>, last_year: Option<u32>) -> Self {
        Self {
            family: family.malpedia_name.clone(),
            first_year,
            last_year,
            sample_count: family.samples.len(),
        }
    }

    /// Return duration in years if both years are set.
    #[must_use]
    pub const fn duration_years(&self) -> Option<u32> {
        match (self.first_year, self.last_year) {
            (Some(f), Some(l)) if l >= f => Some(l - f),
            _ => None,
        }
    }
}

impl fmt::Display for TimelineEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({:?}–{:?}) — {} samples",
            self.family, self.first_year, self.last_year, self.sample_count
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{MalpediaActor, MalpediaFamily, MalpediaSample};

    fn make_family(name: &str, n_samples: usize, active: bool) -> MalpediaFamily {
        let mut f = MalpediaFamily::new(name, name);
        let status = if active { "active" } else { "deprecated" };
        for i in 0..n_samples {
            f.samples.push(MalpediaSample::new(
                format!("{name}_hash{i}"),
                status,
                "1.0",
            ));
        }
        f
    }

    fn make_actor(name: &str, country: &str, families: &[&str]) -> MalpediaActor {
        let mut a = MalpediaActor::new(name, country);
        a.families = families.iter().map(std::string::ToString::to_string).collect();
        a
    }

    #[test]
    fn test_database_stats_empty() {
        let s = DatabaseStats::compute(&[], &[]);
        assert_eq!(s.family_count, 0);
        assert_eq!(s.actor_count, 0);
        assert_eq!(s.sample_count, 0);
        assert!((s.active_fraction).abs() < f64::EPSILON);
    }

    #[test]
    fn test_database_stats_counts() {
        let families = vec![
            make_family("win.a", 5, true),
            make_family("win.b", 3, false),
        ];
        let actors = vec![make_actor("APT29", "RU", &["win.a"])];
        let s = DatabaseStats::compute(&families, &actors);
        assert_eq!(s.family_count, 2);
        assert_eq!(s.actor_count, 1);
        assert_eq!(s.sample_count, 8);
        assert_eq!(s.active_sample_count, 5);
    }

    #[test]
    fn test_database_stats_active_fraction() {
        let families = vec![
            make_family("win.a", 2, true),
            make_family("win.b", 2, false),
        ];
        let s = DatabaseStats::compute(&families, &[]);
        assert!((s.active_fraction - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_database_stats_avg_samples() {
        let families = vec![make_family("win.a", 4, true), make_family("win.b", 6, true)];
        let s = DatabaseStats::compute(&families, &[]);
        assert!((s.avg_samples_per_family - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_database_stats_top_families() {
        let families = vec![
            make_family("win.big", 10, true),
            make_family("win.small", 2, true),
        ];
        let s = DatabaseStats::compute(&families, &[]);
        assert_eq!(s.top_families_by_sample_count[0].0, "win.big");
    }

    #[test]
    fn test_database_stats_attribution_coverage() {
        let mut fam_with_actor = make_family("win.a", 1, true);
        fam_with_actor.actors.push("APT29".to_string());
        let fam_no_actor = make_family("win.b", 1, true);
        let s = DatabaseStats::compute(&[fam_with_actor, fam_no_actor], &[]);
        assert!((s.attribution_coverage() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_database_stats_display() {
        let s = DatabaseStats::compute(&[], &[]);
        let out = s.to_string();
        assert!(out.contains("Malpedia"));
    }

    #[test]
    fn test_family_distribution_record_and_mode() {
        let mut dist = FamilyDistribution::new("platform");
        dist.record("win");
        dist.record("win");
        dist.record("elf");
        let (mode, count) = dist.mode().unwrap();
        assert_eq!(mode, "win");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_family_distribution_total() {
        let mut dist = FamilyDistribution::new("platform");
        dist.record("win");
        dist.record("elf");
        dist.record("osx");
        assert_eq!(dist.total(), 3);
    }

    #[test]
    fn test_family_distribution_sorted_buckets() {
        let mut dist = FamilyDistribution::new("x");
        dist.record("a");
        dist.record("b");
        dist.record("b");
        dist.record("c");
        dist.record("c");
        dist.record("c");
        let sorted = dist.sorted_buckets();
        assert_eq!(sorted[0].0, "c");
        assert_eq!(sorted[0].1, 3);
    }

    #[test]
    fn test_family_distribution_display() {
        let dist = FamilyDistribution::new("platform");
        let s = dist.to_string();
        assert!(s.contains("platform"));
    }

    #[test]
    fn test_platform_distribution() {
        let families = vec![
            make_family("win.emotet", 1, true),
            make_family("win.trickbot", 1, true),
            make_family("elf.mirai", 1, true),
        ];
        let dist = platform_distribution(&families);
        let mode = dist.mode().unwrap();
        assert_eq!(mode.0, "win");
        assert_eq!(mode.1, 2);
    }

    #[test]
    fn test_actor_country_distribution() {
        let actors = vec![
            make_actor("APT29", "RU", &[]),
            make_actor("APT28", "RU", &[]),
            make_actor("Lazarus", "KP", &[]),
        ];
        let dist = actor_country_distribution(&actors);
        assert_eq!(dist.mode().unwrap().0, "RU");
        assert_eq!(dist.mode().unwrap().1, 2);
    }

    #[test]
    fn test_timeline_entry_duration() {
        let fam = make_family("win.x", 0, true);
        let entry = TimelineEntry::new(&fam, Some(2018), Some(2023));
        assert_eq!(entry.duration_years(), Some(5));
    }

    #[test]
    fn test_timeline_entry_no_dates() {
        let fam = make_family("win.x", 0, true);
        let entry = TimelineEntry::new(&fam, None, None);
        assert!(entry.duration_years().is_none());
    }

    #[test]
    fn test_timeline_entry_display() {
        let fam = make_family("win.test", 3, true);
        let entry = TimelineEntry::new(&fam, Some(2020), Some(2022));
        let s = entry.to_string();
        assert!(s.contains("win.test"));
        assert!(s.contains("3 samples"));
    }

    #[test]
    fn test_database_stats_serialization() {
        let s = DatabaseStats::compute(&[], &[]);
        let json = serde_json::to_string(&s).unwrap();
        let decoded: DatabaseStats = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.family_count, 0);
    }
}
