//! Known packer entropy fingerprints and matching logic.
//!
//! Maintains a database of entropy profiles for well-known PE packers
//! (UPX, Themida, `VMProtect`, Enigma, MPRESS, `ASPack`, `PEtite`, Obsidium, etc.)
//! and provides pattern-matching against a binary's per-section entropy values.

use crate::{SectionEntropy, casts};
use serde::{Deserialize, Serialize};
use std::fmt;

// ─── PackerKind ───────────────────────────────────────────────────────────────

/// Well-known packer / protector identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackerKind {
    Upx,
    Themida,
    Vmprotect,
    Enigma,
    Mpress,
    Aspack,
    Petite,
    Obsidium,
    NsPack,
    Safengine,
    Armadillo,
    ExeCryptor,
    Xtreme,
    Morphine,
    Custom(String),
}

impl PackerKind {
    /// Short human-readable name.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Upx => "UPX",
            Self::Themida => "Themida",
            Self::Vmprotect => "VMProtect",
            Self::Enigma => "Enigma Protector",
            Self::Mpress => "MPRESS",
            Self::Aspack => "ASPack",
            Self::Petite => "PEtite",
            Self::Obsidium => "Obsidium",
            Self::NsPack => "NsPack",
            Self::Safengine => "Safengine Shielden",
            Self::Armadillo => "Armadillo",
            Self::ExeCryptor => "ExeCryptor",
            Self::Xtreme => "Xtreme-Protector",
            Self::Morphine => "Morphine",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for PackerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── SectionEntropyRange ──────────────────────────────────────────────────────

/// Expected entropy range for a section matching a packer's fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropyRange {
    /// Section name pattern to match (prefix or exact).
    pub name_pattern: String,
    /// Minimum expected entropy.
    pub min_entropy: f32,
    /// Maximum expected entropy.
    pub max_entropy: f32,
    /// Whether the match on this section is required for the fingerprint to fire.
    pub required: bool,
}

impl SectionEntropyRange {
    /// Create a required range entry.
    #[must_use]
    pub fn required(name_pattern: impl Into<String>, min: f32, max: f32) -> Self {
        Self {
            name_pattern: name_pattern.into(),
            min_entropy: min,
            max_entropy: max,
            required: true,
        }
    }

    /// Create an optional range entry.
    #[must_use]
    pub fn optional(name_pattern: impl Into<String>, min: f32, max: f32) -> Self {
        Self {
            name_pattern: name_pattern.into(),
            min_entropy: min,
            max_entropy: max,
            required: false,
        }
    }

    /// Check if `entropy` is within this range.
    #[must_use]
    pub fn matches_entropy(&self, entropy: f32) -> bool {
        entropy >= self.min_entropy && entropy <= self.max_entropy
    }

    /// Check if `section_name` matches the pattern (prefix or exact).
    #[must_use]
    pub fn matches_name(&self, section_name: &str) -> bool {
        if self.name_pattern == "*" {
            return true;
        }
        section_name.eq_ignore_ascii_case(&self.name_pattern)
            || section_name
                .to_lowercase()
                .starts_with(&self.name_pattern.to_lowercase())
    }
}

// ─── PackerFingerprint ────────────────────────────────────────────────────────

/// A complete entropy-based fingerprint for a packer/protector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerFingerprint {
    /// Packer identifier.
    pub packer: PackerKind,
    /// Per-section entropy patterns that define this fingerprint.
    pub section_patterns: Vec<SectionEntropyRange>,
    /// Overall file entropy range (if applicable).
    pub overall_entropy_range: Option<(f32, f32)>,
    /// Known section names for this packer (used as additional hints).
    pub known_section_names: Vec<String>,
    /// Minimum number of required patterns that must match.
    pub min_required_matches: usize,
    /// Short description.
    pub description: String,
}

impl PackerFingerprint {
    /// Score how well this fingerprint matches the provided sections.
    ///
    /// Returns a score in [0, 100] where 100 = perfect match.
    #[must_use]
    pub fn score(&self, sections: &[SectionEntropy], overall_entropy: f32) -> u8 {
        let mut required_matched = 0usize;
        let mut optional_matched = 0usize;
        let total_required = self
            .section_patterns
            .iter()
            .filter(|p| p.required)
            .count();
        let total_optional = self
            .section_patterns
            .iter()
            .filter(|p| !p.required)
            .count();

        for pattern in &self.section_patterns {
            let sec_match = sections.iter().any(|sec| {
                pattern.matches_name(&sec.name) && pattern.matches_entropy(casts::f64_to_f32(sec.entropy))
            });
            if sec_match {
                if pattern.required {
                    required_matched += 1;
                } else {
                    optional_matched += 1;
                }
            }
        }

        // Check overall entropy range.
        let overall_ok = self
            .overall_entropy_range
            .is_none_or(|(lo, hi)| overall_entropy >= lo && overall_entropy <= hi);

        if !overall_ok {
            return 0;
        }

        // Check required minimum.
        if required_matched < self.min_required_matches {
            return 0;
        }

        // Base score from required matches.
        let req_score = if total_required == 0 {
            50u32
        } else {
            (casts::usize_to_u32(required_matched) * 80) / casts::usize_to_u32(total_required)
        };

        // Bonus from optional matches.
        let opt_score = if total_optional == 0 {
            20u32
        } else {
            (casts::usize_to_u32(optional_matched) * 20) / casts::usize_to_u32(total_optional)
        };

        // Name hint bonus.
        let name_bonus_count: usize = sections
            .iter()
            .filter(|sec| {
                self.known_section_names
                    .iter()
                    .any(|kn| kn.eq_ignore_ascii_case(&sec.name))
            })
            .count()
            .min(1);
        let name_bonus: u32 = casts::usize_to_u32(name_bonus_count) * 10;

        u8::try_from((req_score + opt_score + name_bonus).min(100)).unwrap_or(100)
    }
}

// ─── PackerFingerprintDatabase ────────────────────────────────────────────────

/// Database of known packer entropy fingerprints.
pub struct PackerFingerprintDatabase {
    fingerprints: Vec<PackerFingerprint>,
}

impl PackerFingerprintDatabase {
    /// Build the built-in fingerprint database.
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            fingerprints: builtin_fingerprints(),
        }
    }

    /// Create an empty database.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            fingerprints: Vec::new(),
        }
    }

    /// Add a custom fingerprint.
    pub fn add(&mut self, fingerprint: PackerFingerprint) {
        self.fingerprints.push(fingerprint);
    }

    /// Match all fingerprints against the provided section entropy data.
    ///
    /// Returns a sorted list of `(PackerKind, score)` with score > 0.
    #[must_use]
    pub fn match_all(
        &self,
        sections: &[SectionEntropy],
        overall_entropy: f32,
    ) -> Vec<PackerMatch> {
        let mut results: Vec<PackerMatch> = self
            .fingerprints
            .iter()
            .filter_map(|fp| {
                let score = fp.score(sections, overall_entropy);
                if score > 0 {
                    Some(PackerMatch {
                        packer: fp.packer.clone(),
                        score,
                        description: fp.description.clone(),
                        matched_sections: sections
                            .iter()
                            .filter(|sec| {
                                fp.section_patterns.iter().any(|p| {
                                    p.matches_name(&sec.name)
                                        && p.matches_entropy(casts::f64_to_f32(sec.entropy))
                                })
                            })
                            .map(|s| s.name.clone())
                            .collect(),
                    })
                } else {
                    None
                }
            })
            .collect();

        results.sort_unstable_by(|a, b| b.score.cmp(&a.score));
        results
    }

    /// Return the best match (highest score), or `None` if nothing scores > 0.
    #[must_use]
    pub fn best_match(
        &self,
        sections: &[SectionEntropy],
        overall_entropy: f32,
    ) -> Option<PackerMatch> {
        self.match_all(sections, overall_entropy).into_iter().next()
    }

    /// Number of registered fingerprints.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Whether the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Iterate over all fingerprints.
    pub fn iter(&self) -> impl Iterator<Item = &PackerFingerprint> {
        self.fingerprints.iter()
    }
}

// ─── PackerMatch ──────────────────────────────────────────────────────────────

/// A fingerprint match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerMatch {
    /// The matched packer.
    pub packer: PackerKind,
    /// Match score 0–100.
    pub score: u8,
    /// Description from the fingerprint.
    pub description: String,
    /// Section names that contributed to the match.
    pub matched_sections: Vec<String>,
}

impl PackerMatch {
    /// Whether this match is considered high-confidence (score >= 70).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.score >= 70
    }

    /// Whether this match is at least medium confidence (score >= 40).
    #[must_use]
    pub const fn is_medium_confidence(&self) -> bool {
        self.score >= 40
    }
}

impl fmt::Display for PackerMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackerMatch {{ packer={}, score={}, sections=[{}] }}",
            self.packer,
            self.score,
            self.matched_sections.join(", ")
        )
    }
}

// ─── PackerDetectionReport ────────────────────────────────────────────────────

/// Full packer detection report for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerDetectionReport {
    /// All matches with score > 0, sorted by score descending.
    pub matches: Vec<PackerMatch>,
    /// Overall file entropy used for matching.
    pub overall_entropy: f32,
    /// Whether any high-confidence match was found.
    pub packed: bool,
    /// Best match (if any).
    pub best_match: Option<PackerKind>,
    /// Best match score.
    pub best_score: u8,
}

impl PackerDetectionReport {
    /// Build a report from section entropies.
    #[must_use]
    pub fn generate(sections: &[SectionEntropy], overall_entropy: f32) -> Self {
        let db = PackerFingerprintDatabase::builtin();
        let matches = db.match_all(sections, overall_entropy);
        let packed = matches.iter().any(PackerMatch::is_high_confidence);
        let best_match = matches.first().map(|m| m.packer.clone());
        let best_score = matches.first().map_or(0, |m| m.score);
        Self {
            matches,
            overall_entropy,
            packed,
            best_match,
            best_score,
        }
    }
}

impl fmt::Display for PackerDetectionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Packer Detection Report ===")?;
        writeln!(f, "  Overall entropy : {:.3}", self.overall_entropy)?;
        writeln!(f, "  Packed          : {}", self.packed)?;
        if let Some(best) = &self.best_match {
            writeln!(f, "  Best match      : {} (score={})", best, self.best_score)?;
        }
        writeln!(f, "  All matches:")?;
        for m in &self.matches {
            writeln!(f, "    {m}")?;
        }
        Ok(())
    }
}

// ─── Built-in fingerprint database ───────────────────────────────────────────

fn builtin_fingerprints() -> Vec<PackerFingerprint> {
    let mut fps = builtin_fingerprints_common();
    fps.extend(builtin_fingerprints_extended());
    fps
}

fn builtin_fingerprints_common() -> Vec<PackerFingerprint> {
    vec![
        // ── UPX ──────────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Upx,
            section_patterns: vec![
                SectionEntropyRange::required("UPX0", 0.0, 2.0),
                SectionEntropyRange::required("UPX1", 7.0, 8.0),
                SectionEntropyRange::optional("UPX2", 6.0, 8.0),
            ],
            overall_entropy_range: Some((6.0, 8.0)),
            known_section_names: vec!["UPX0".into(), "UPX1".into(), "UPX2".into()],
            min_required_matches: 2,
            description: "UPX packer — characteristic UPX0 (zero) + UPX1 (high entropy)".into(),
        },
        // ── MPRESS ────────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Mpress,
            section_patterns: vec![
                SectionEntropyRange::required(".MPRESS1", 7.0, 8.0),
                SectionEntropyRange::optional(".MPRESS2", 6.0, 8.0),
            ],
            overall_entropy_range: Some((6.5, 8.0)),
            known_section_names: vec![".MPRESS1".into(), ".MPRESS2".into()],
            min_required_matches: 1,
            description: "MPRESS packer — high-entropy .MPRESS1 section".into(),
        },
        // ── Themida ───────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Themida,
            section_patterns: vec![
                SectionEntropyRange::required(".themida", 7.0, 8.0),
                SectionEntropyRange::optional(".text", 7.2, 8.0),
                SectionEntropyRange::optional(".data", 7.0, 8.0),
            ],
            overall_entropy_range: Some((6.8, 8.0)),
            known_section_names: vec![".themida".into(), ".winlice".into()],
            min_required_matches: 1,
            description: "Themida / WinLicense protector".into(),
        },
        // ── VMProtect ─────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Vmprotect,
            section_patterns: vec![
                SectionEntropyRange::required(".vmp0", 7.0, 8.0),
                SectionEntropyRange::optional(".vmp1", 7.0, 8.0),
                SectionEntropyRange::optional(".vmp2", 6.5, 8.0),
            ],
            overall_entropy_range: Some((6.5, 8.0)),
            known_section_names: vec![".vmp0".into(), ".vmp1".into(), ".vmp2".into()],
            min_required_matches: 1,
            description: "VMProtect — virtual machine protection with .vmp sections".into(),
        },
        // ── Enigma Protector ─────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Enigma,
            section_patterns: vec![
                SectionEntropyRange::required(".enigma1", 7.0, 8.0),
                SectionEntropyRange::optional(".enigma2", 6.5, 8.0),
            ],
            overall_entropy_range: Some((6.5, 8.0)),
            known_section_names: vec![".enigma1".into(), ".enigma2".into()],
            min_required_matches: 1,
            description: "Enigma Protector — .enigma1/.enigma2 sections".into(),
        },
        // ── NsPack ────────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::NsPack,
            section_patterns: vec![
                SectionEntropyRange::required(".nsp0", 0.0, 2.0),
                SectionEntropyRange::required(".nsp1", 7.0, 8.0),
                SectionEntropyRange::optional(".nsp2", 6.5, 8.0),
            ],
            overall_entropy_range: Some((5.5, 8.0)),
            known_section_names: vec![".nsp0".into(), ".nsp1".into(), ".nsp2".into()],
            min_required_matches: 2,
            description: "NsPack — .nsp0 (empty) + .nsp1 (compressed) sections".into(),
        },
    ]
}

fn builtin_fingerprints_extended() -> Vec<PackerFingerprint> {
    vec![
        // ── ASPack ────────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Aspack,
            section_patterns: vec![
                SectionEntropyRange::required(".aspack", 7.0, 8.0),
                SectionEntropyRange::optional(".adata", 0.0, 3.0),
            ],
            overall_entropy_range: Some((6.0, 8.0)),
            known_section_names: vec![".aspack".into(), ".adata".into()],
            min_required_matches: 1,
            description: "ASPack packer — .aspack high-entropy section".into(),
        },
        // ── PEtite ───────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Petite,
            section_patterns: vec![
                SectionEntropyRange::required(".petite", 7.0, 8.0),
            ],
            overall_entropy_range: Some((6.0, 8.0)),
            known_section_names: vec![".petite".into()],
            min_required_matches: 1,
            description: "PEtite packer — .petite section with very high entropy".into(),
        },
        // ── Obsidium ─────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Obsidium,
            section_patterns: vec![
                SectionEntropyRange::required(".obsidium", 7.0, 8.0),
            ],
            overall_entropy_range: Some((6.5, 8.0)),
            known_section_names: vec![".obsidium".into()],
            min_required_matches: 1,
            description: "Obsidium protector — .obsidium section".into(),
        },
        // ── Safengine ─────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Safengine,
            section_patterns: vec![
                SectionEntropyRange::required(".safengine", 7.0, 8.0),
                SectionEntropyRange::optional(".sdata", 6.5, 8.0),
            ],
            overall_entropy_range: Some((6.5, 8.0)),
            known_section_names: vec![".safengine".into(), ".sdata".into()],
            min_required_matches: 1,
            description: "Safengine Shielden protector".into(),
        },
        // ── Armadillo ─────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Armadillo,
            section_patterns: vec![
                SectionEntropyRange::optional(".text", 7.2, 8.0),
                SectionEntropyRange::optional(".data", 7.0, 8.0),
                SectionEntropyRange::optional(".rdata", 3.0, 6.0),
            ],
            overall_entropy_range: Some((6.8, 8.0)),
            known_section_names: vec![".text".into()],
            min_required_matches: 0,
            description: "Armadillo — inferred from high overall entropy pattern (no unique section names)".into(),
        },
        // ── ExeCryptor ────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::ExeCryptor,
            section_patterns: vec![
                SectionEntropyRange::required(".ExeCryptor", 7.0, 8.0),
            ],
            overall_entropy_range: Some((6.5, 8.0)),
            known_section_names: vec![".ExeCryptor".into()],
            min_required_matches: 1,
            description: "ExeCryptor — .ExeCryptor section".into(),
        },
        // ── Morphine ──────────────────────────────────────────────────────────
        PackerFingerprint {
            packer: PackerKind::Morphine,
            section_patterns: vec![
                SectionEntropyRange::required(".morphine", 7.0, 8.0),
            ],
            overall_entropy_range: Some((6.5, 8.0)),
            known_section_names: vec![".morphine".into()],
            min_required_matches: 1,
            description: "Morphine packer — .morphine section".into(),
        },
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EntropyRating, SectionEntropy};

    fn make_section(name: &str, entropy: f64) -> SectionEntropy {
        SectionEntropy {
            name: name.to_string(),
            entropy,
            size: 4096,
            offset: 0,
            rating: EntropyRating::from_entropy(entropy),
        }
    }

    // ── PackerKind ────────────────────────────────────────────────────────

    #[test]
    fn test_packer_kind_name() {
        assert_eq!(PackerKind::Upx.name(), "UPX");
        assert_eq!(PackerKind::Themida.name(), "Themida");
        assert_eq!(PackerKind::Vmprotect.name(), "VMProtect");
    }

    #[test]
    fn test_packer_kind_display() {
        assert_eq!(PackerKind::Mpress.to_string(), "MPRESS");
    }

    #[test]
    fn test_packer_kind_custom() {
        let k = PackerKind::Custom("MyPacker".into());
        assert_eq!(k.name(), "MyPacker");
    }

    // ── SectionEntropyRange ───────────────────────────────────────────────

    #[test]
    fn test_section_range_matches_name_exact() {
        let r = SectionEntropyRange::required("UPX0", 0.0, 2.0);
        assert!(r.matches_name("UPX0"));
        assert!(r.matches_name("upx0")); // case-insensitive
        assert!(!r.matches_name(".text"));
    }

    #[test]
    fn test_section_range_wildcard() {
        let r = SectionEntropyRange::required("*", 0.0, 8.0);
        assert!(r.matches_name("anything"));
        assert!(r.matches_name(".text"));
    }

    #[test]
    fn test_section_range_matches_entropy() {
        let r = SectionEntropyRange::required("UPX0", 0.0, 2.0);
        assert!(r.matches_entropy(0.0));
        assert!(r.matches_entropy(1.5));
        assert!(!r.matches_entropy(2.1));
    }

    // ── Database ──────────────────────────────────────────────────────────

    #[test]
    fn test_database_builtin_not_empty() {
        let db = PackerFingerprintDatabase::builtin();
        assert!(db.len() >= 10);
    }

    #[test]
    fn test_database_empty() {
        let db = PackerFingerprintDatabase::empty();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
    }

    #[test]
    fn test_database_add_custom() {
        let mut db = PackerFingerprintDatabase::empty();
        db.add(PackerFingerprint {
            packer: PackerKind::Custom("TestPacker".into()),
            section_patterns: vec![SectionEntropyRange::required(".test", 7.0, 8.0)],
            overall_entropy_range: None,
            known_section_names: vec![],
            min_required_matches: 1,
            description: "Test".into(),
        });
        assert_eq!(db.len(), 1);
    }

    // ── UPX matching ──────────────────────────────────────────────────────

    #[test]
    fn test_upx_match_high_confidence() {
        let sections = vec![
            make_section("UPX0", 0.5), // near-zero entropy
            make_section("UPX1", 7.8), // high entropy compressed
        ];
        let db = PackerFingerprintDatabase::builtin();
        let result = db.best_match(&sections, 7.0);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.packer, PackerKind::Upx);
        assert!(m.is_high_confidence(), "score was {}", m.score);
    }

    #[test]
    fn test_upx_no_match_wrong_entropy() {
        let sections = vec![
            make_section("UPX0", 6.0), // wrong — UPX0 should be near-zero
            make_section("UPX1", 4.0), // wrong — UPX1 should be high
        ];
        let db = PackerFingerprintDatabase::builtin();
        let result = db.best_match(&sections, 5.0);
        // Either no match or a low-score match
        if let Some(m) = result {
            assert!(!m.is_high_confidence() || m.packer != PackerKind::Upx);
        }
    }

    // ── MPRESS matching ───────────────────────────────────────────────────

    #[test]
    fn test_mpress_match() {
        let sections = vec![make_section(".MPRESS1", 7.5)];
        let db = PackerFingerprintDatabase::builtin();
        let matches = db.match_all(&sections, 7.2);
        let mpress = matches.iter().find(|m| m.packer == PackerKind::Mpress);
        assert!(mpress.is_some());
    }

    // ── VMProtect matching ────────────────────────────────────────────────

    #[test]
    fn test_vmprotect_match() {
        let sections = vec![make_section(".vmp0", 7.3), make_section(".vmp1", 7.6)];
        let db = PackerFingerprintDatabase::builtin();
        let matches = db.match_all(&sections, 7.4);
        let vmp = matches.iter().find(|m| m.packer == PackerKind::Vmprotect);
        assert!(vmp.is_some());
        assert!(vmp.unwrap().score > 50);
    }

    // ── No match for clean binary ─────────────────────────────────────────

    #[test]
    fn test_no_match_clean_binary() {
        let sections = vec![
            make_section(".text", 5.5),
            make_section(".data", 2.0),
            make_section(".rdata", 3.5),
        ];
        let db = PackerFingerprintDatabase::builtin();
        let matches = db.match_all(&sections, 4.0);
        // None should be high confidence
        assert!(matches.iter().all(|m| !m.is_high_confidence()));
    }

    // ── PackerDetectionReport ─────────────────────────────────────────────

    #[test]
    fn test_report_generate_packed() {
        let sections = vec![
            make_section("UPX0", 0.3),
            make_section("UPX1", 7.9),
        ];
        let report = PackerDetectionReport::generate(&sections, 7.5);
        assert!(report.packed);
        assert_eq!(report.best_match, Some(PackerKind::Upx));
        assert!(report.best_score >= 70);
    }

    #[test]
    fn test_report_generate_clean() {
        let sections = vec![make_section(".text", 5.0), make_section(".data", 2.0)];
        let report = PackerDetectionReport::generate(&sections, 4.0);
        assert!(!report.packed);
    }

    #[test]
    fn test_report_display() {
        let sections = vec![make_section("UPX0", 0.3), make_section("UPX1", 7.9)];
        let report = PackerDetectionReport::generate(&sections, 7.5);
        let s = format!("{report}");
        assert!(s.contains("Packer Detection Report"));
        assert!(s.contains("Overall entropy"));
    }

    // ── PackerMatch ───────────────────────────────────────────────────────

    #[test]
    fn test_packer_match_display() {
        let m = PackerMatch {
            packer: PackerKind::Upx,
            score: 95,
            description: "UPX packer".into(),
            matched_sections: vec!["UPX0".into(), "UPX1".into()],
        };
        assert!(m.to_string().contains("UPX"));
        assert!(m.is_high_confidence());
    }

    #[test]
    fn test_packer_match_low_confidence() {
        let m = PackerMatch {
            packer: PackerKind::Enigma,
            score: 35,
            description: "low".into(),
            matched_sections: vec![],
        };
        assert!(!m.is_high_confidence());
        assert!(!m.is_medium_confidence());
    }

    #[test]
    fn test_packer_match_medium_confidence() {
        let m = PackerMatch {
            packer: PackerKind::Aspack,
            score: 50,
            description: "medium".into(),
            matched_sections: vec![".aspack".into()],
        };
        assert!(m.is_medium_confidence());
        assert!(!m.is_high_confidence());
    }
}
