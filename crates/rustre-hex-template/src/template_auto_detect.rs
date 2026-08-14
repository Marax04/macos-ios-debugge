//! `template_auto_detect` — Automatic binary format detection.
//!
//! Matches a buffer against a registry of magic-byte signatures and file
//! extensions to select the most appropriate template. Falls back gracefully
//! when no exact match is found.

use std::path::Path;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// DetectError
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("no template matched")]
    NoMatch,
    #[error("ambiguous match: {0:?}")]
    Ambiguous(Vec<String>),
}

// ─────────────────────────────────────────────────────────────────────────────
// MagicRule
// ─────────────────────────────────────────────────────────────────────────────

/// A magic-byte rule for format detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicRule {
    /// Byte offset to check.
    pub offset: usize,
    /// Expected bytes.
    pub magic: Vec<u8>,
    /// Optional mask (0xFF = exact, 0x00 = wildcard).
    pub mask: Option<Vec<u8>>,
    /// Additional confidence boost when this rule matches (0.0–1.0).
    pub confidence: f32,
}

impl MagicRule {
    /// Create a simple exact-match magic rule at offset 0.
    #[must_use]
    pub fn at_offset_0(magic: impl Into<Vec<u8>>) -> Self {
        Self {
            offset: 0,
            magic: magic.into(),
            mask: None,
            confidence: 1.0,
        }
    }

    /// Create a rule at a specific offset.
    #[must_use]
    pub fn at(offset: usize, magic: impl Into<Vec<u8>>) -> Self {
        Self {
            offset,
            magic: magic.into(),
            mask: None,
            confidence: 1.0,
        }
    }

    /// Check whether the rule matches `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        let end = self.offset + self.magic.len();
        if end > data.len() {
            return false;
        }
        for (i, &expected) in self.magic.iter().enumerate() {
            let mask = self
                .mask
                .as_ref()
                .map_or(0xFF, |m| m.get(i).copied().unwrap_or(0xFF));
            if data[self.offset + i] & mask != expected & mask {
                return false;
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplateDescriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Description of a template available for auto-detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateDescriptor {
    /// Unique identifier used to load the template.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// File extensions (without leading dot).
    pub extensions: Vec<String>,
    /// Magic byte rules — ALL must match for the template to be selected.
    pub magic_rules: Vec<MagicRule>,
    /// Any magic rule from this list is sufficient (OR logic).
    pub any_magic_rules: Vec<MagicRule>,
    /// Base priority (higher = preferred when ambiguous).
    pub priority: u32,
    /// Minimum file size for this template to apply.
    pub min_size: usize,
}

impl TemplateDescriptor {
    /// Compute a detection score for `data` with optional `file_extension`.
    /// Returns `None` if the descriptor definitively does not match.
    pub fn score(&self, data: &[u8], file_extension: Option<&str>) -> Option<f32> {
        if data.len() < self.min_size {
            return None;
        }

        // All required magic rules must match
        for rule in &self.magic_rules {
            if !rule.matches(data) {
                return None;
            }
        }

        let mut score = 0.0f32;

        // At least one any-magic rule must match (if there are any)
        if !self.any_magic_rules.is_empty() {
            let any_match = self.any_magic_rules.iter().any(|r| r.matches(data));
            if !any_match {
                return None;
            }
            for rule in &self.any_magic_rules {
                if rule.matches(data) {
                    score += rule.confidence;
                }
            }
        }

        // Bonus for required rules passing
        for rule in &self.magic_rules {
            score += rule.confidence;
        }

        // Extension bonus
        let mut ext_matched = false;
        if let Some(ext) = file_extension {
            let ext_lower = ext.to_lowercase();
            let ext_clean = ext_lower.trim_start_matches('.');
            if self.extensions.iter().any(|e| e == ext_clean) {
                score += 0.5;
                ext_matched = true;
            }
        }

        // Strong-signature bonus: a long (>= 8 byte) required magic match
        // combined with a confirming extension is effectively a perfect
        // identification and should be promoted to Certain confidence.
        let longest_magic = self
            .magic_rules
            .iter()
            .map(|r| r.magic.len())
            .max()
            .unwrap_or(0);
        if ext_matched && longest_magic >= 8 {
            score += 1.0;
        }

        // Base priority contribution
        score += self.priority as f32 * 0.01;

        Some(score)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of auto-detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub template_id: String,
    pub template_name: String,
    pub score: f32,
    pub confidence_level: ConfidenceLevel,
}

/// How confident the detector is in its choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
    /// Only magic matched, no extension.
    Low,
    /// Magic matched and extension confirmed.
    Medium,
    /// Multiple independent rules matched.
    High,
    /// Exact known signature.
    Certain,
}

impl ConfidenceLevel {
    fn from_score(score: f32) -> Self {
        if score >= 3.0 {
            Self::Certain
        } else if score >= 2.0 {
            Self::High
        } else if score >= 1.5 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AutoDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of template descriptors for auto-detection.
#[derive(Debug, Default)]
pub struct AutoDetector {
    descriptors: Vec<TemplateDescriptor>,
    /// Optional fallback template id when nothing matches.
    pub fallback_template: Option<String>,
}

impl AutoDetector {
    /// Create a new detector with built-in descriptors.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut d = Self::default();
        d.register_builtins();
        d
    }

    /// Register a template descriptor.
    pub fn register(&mut self, desc: TemplateDescriptor) {
        self.descriptors.push(desc);
    }

    /// Remove a descriptor by id.
    pub fn unregister(&mut self, id: &str) -> bool {
        let before = self.descriptors.len();
        self.descriptors.retain(|d| d.id != id);
        self.descriptors.len() < before
    }

    /// Detect the best matching template for `data`.
    /// `filename` is used to extract the extension.
    pub fn detect(
        &self,
        data: &[u8],
        filename: Option<&str>,
    ) -> Result<DetectionResult, DetectError> {
        let ext = filename
            .and_then(|f| Path::new(f).extension())
            .and_then(|e| e.to_str());

        let mut candidates: Vec<(f32, &TemplateDescriptor)> = self
            .descriptors
            .iter()
            .filter_map(|d| d.score(data, ext).map(|s| (s, d)))
            .collect();

        if candidates.is_empty() {
            if let Some(ref fb) = self.fallback_template {
                // Return fallback with zero score
                return Ok(DetectionResult {
                    template_id: fb.clone(),
                    template_name: "Generic Binary".to_string(),
                    score: 0.0,
                    confidence_level: ConfidenceLevel::Low,
                });
            }
            return Err(DetectError::NoMatch);
        }

        candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

        let best_score = candidates[0].0;
        let best = candidates[0].1;

        // Check for ambiguity (two descriptors with the same score and close priority)
        let tied: Vec<&str> = candidates
            .iter()
            .filter(|(s, d)| (*s - best_score).abs() < 0.1 && d.id != best.id)
            .map(|(_, d)| d.id.as_str())
            .collect();

        if !tied.is_empty() && best_score < 2.0 {
            // Low-confidence tie → pick by priority
            let winner = candidates
                .iter()
                .max_by_key(|(_, d)| d.priority)
                .map(|(_, d)| *d)
                .unwrap_or(best);
            return Ok(DetectionResult {
                template_id: winner.id.clone(),
                template_name: winner.name.clone(),
                score: best_score,
                confidence_level: ConfidenceLevel::from_score(best_score),
            });
        }

        Ok(DetectionResult {
            template_id: best.id.clone(),
            template_name: best.name.clone(),
            score: best_score,
            confidence_level: ConfidenceLevel::from_score(best_score),
        })
    }

    /// Detect all plausible templates (sorted by score).
    pub fn detect_all(&self, data: &[u8], filename: Option<&str>) -> Vec<DetectionResult> {
        let ext = filename
            .and_then(|f| Path::new(f).extension())
            .and_then(|e| e.to_str());

        let mut results: Vec<DetectionResult> = self
            .descriptors
            .iter()
            .filter_map(|d| {
                d.score(data, ext).map(|s| DetectionResult {
                    template_id: d.id.clone(),
                    template_name: d.name.clone(),
                    score: s,
                    confidence_level: ConfidenceLevel::from_score(s),
                })
            })
            .collect();

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        results
    }

    /// Number of registered descriptors.
    #[must_use]
    pub fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }

    // ── Built-in descriptors ─────────────────────────────────────────────────

    fn register_builtins(&mut self) {
        // PE / MZ
        self.register(TemplateDescriptor {
            id: "pe".to_string(),
            name: "PE Executable".to_string(),
            description: "Windows Portable Executable".to_string(),
            extensions: vec!["exe".to_string(), "dll".to_string(), "sys".to_string(), "ocx".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"MZ")],
            any_magic_rules: vec![],
            priority: 80,
            min_size: 64,
        });

        // ELF
        self.register(TemplateDescriptor {
            id: "elf".to_string(),
            name: "ELF Binary".to_string(),
            description: "Unix/Linux ELF executable or shared library".to_string(),
            extensions: vec!["elf".to_string(), "so".to_string(), "o".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"\x7FELF")],
            any_magic_rules: vec![],
            priority: 90,
            min_size: 64,
        });

        // Mach-O
        self.register(TemplateDescriptor {
            id: "macho".to_string(),
            name: "Mach-O Binary".to_string(),
            description: "macOS/iOS Mach-O executable".to_string(),
            extensions: vec!["macho".to_string(), "dylib".to_string(), "o".to_string()],
            magic_rules: vec![],
            any_magic_rules: vec![
                MagicRule::at_offset_0(b"\xCE\xFA\xED\xFE"),
                MagicRule::at_offset_0(b"\xCF\xFA\xED\xFE"),
                MagicRule::at_offset_0(b"\xFE\xED\xFA\xCE"),
                MagicRule::at_offset_0(b"\xFE\xED\xFA\xCF"),
                MagicRule::at_offset_0(b"\xCA\xFE\xBA\xBE"), // fat
            ],
            priority: 90,
            min_size: 28,
        });

        // ZIP
        self.register(TemplateDescriptor {
            id: "zip".to_string(),
            name: "ZIP Archive".to_string(),
            description: "ZIP compressed archive".to_string(),
            extensions: vec!["zip".to_string(), "jar".to_string(), "apk".to_string(), "docx".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"PK\x03\x04")],
            any_magic_rules: vec![],
            priority: 85,
            min_size: 30,
        });

        // PNG
        self.register(TemplateDescriptor {
            id: "png".to_string(),
            name: "PNG Image".to_string(),
            description: "Portable Network Graphics".to_string(),
            extensions: vec!["png".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"\x89PNG\r\n\x1a\n")],
            any_magic_rules: vec![],
            priority: 95,
            min_size: 8,
        });

        // JPEG
        self.register(TemplateDescriptor {
            id: "jpeg".to_string(),
            name: "JPEG Image".to_string(),
            description: "JPEG compressed image".to_string(),
            extensions: vec!["jpg".to_string(), "jpeg".to_string(), "jpe".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"\xFF\xD8\xFF")],
            any_magic_rules: vec![],
            priority: 90,
            min_size: 3,
        });

        // GIF
        self.register(TemplateDescriptor {
            id: "gif".to_string(),
            name: "GIF Image".to_string(),
            description: "Graphics Interchange Format".to_string(),
            extensions: vec!["gif".to_string()],
            magic_rules: vec![],
            any_magic_rules: vec![
                MagicRule::at_offset_0(b"GIF87a"),
                MagicRule::at_offset_0(b"GIF89a"),
            ],
            priority: 90,
            min_size: 6,
        });

        // GZIP
        self.register(TemplateDescriptor {
            id: "gzip".to_string(),
            name: "GZIP Compressed".to_string(),
            description: "GNU zip compressed data".to_string(),
            extensions: vec!["gz".to_string(), "tgz".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"\x1F\x8B")],
            any_magic_rules: vec![],
            priority: 85,
            min_size: 10,
        });

        // PDF
        self.register(TemplateDescriptor {
            id: "pdf".to_string(),
            name: "PDF Document".to_string(),
            description: "Portable Document Format".to_string(),
            extensions: vec!["pdf".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"%PDF-")],
            any_magic_rules: vec![],
            priority: 90,
            min_size: 5,
        });

        // SQLite
        self.register(TemplateDescriptor {
            id: "sqlite".to_string(),
            name: "SQLite Database".to_string(),
            description: "SQLite version 3 database".to_string(),
            extensions: vec!["sqlite".to_string(), "sqlite3".to_string(), "db".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"SQLite format 3\x00")],
            any_magic_rules: vec![],
            priority: 95,
            min_size: 16,
        });

        // LNK (Windows shortcut)
        self.register(TemplateDescriptor {
            id: "lnk".to_string(),
            name: "Windows Shortcut".to_string(),
            description: "Windows Shell Link (.lnk)".to_string(),
            extensions: vec!["lnk".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(
                b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46",
            )],
            any_magic_rules: vec![],
            priority: 90,
            min_size: 20,
        });

        // BMP
        self.register(TemplateDescriptor {
            id: "bmp".to_string(),
            name: "BMP Image".to_string(),
            description: "Windows Bitmap".to_string(),
            extensions: vec!["bmp".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"BM")],
            any_magic_rules: vec![],
            priority: 75,
            min_size: 54,
        });

        // DEX (Android)
        self.register(TemplateDescriptor {
            id: "dex".to_string(),
            name: "Android DEX".to_string(),
            description: "Dalvik Executable Format".to_string(),
            extensions: vec!["dex".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"dex\n")],
            any_magic_rules: vec![],
            priority: 95,
            min_size: 112,
        });

        // Class (Java)
        self.register(TemplateDescriptor {
            id: "class".to_string(),
            name: "Java Class".to_string(),
            description: "Java bytecode class file".to_string(),
            extensions: vec!["class".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"\xCA\xFE\xBA\xBE")],
            any_magic_rules: vec![],
            priority: 70, // Lower than Mach-O fat which has same magic
            min_size: 8,
        });

        // WASM
        self.register(TemplateDescriptor {
            id: "wasm".to_string(),
            name: "WebAssembly".to_string(),
            description: "WebAssembly binary module".to_string(),
            extensions: vec!["wasm".to_string()],
            magic_rules: vec![MagicRule::at_offset_0(b"\x00asm")],
            any_magic_rules: vec![],
            priority: 95,
            min_size: 8,
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_elf() {
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"\x7FELF");
        let d = AutoDetector::with_builtins();
        let r = d.detect(&data, Some("binary.elf")).unwrap();
        assert_eq!(r.template_id, "elf");
    }

    #[test]
    fn detect_png() {
        let magic = b"\x89PNG\r\n\x1a\n";
        let mut data = vec![0u8; 64];
        data[..8].copy_from_slice(magic);
        let d = AutoDetector::with_builtins();
        let r = d.detect(&data, Some("image.png")).unwrap();
        assert_eq!(r.template_id, "png");
        assert_eq!(r.confidence_level, ConfidenceLevel::Certain);
    }

    #[test]
    fn detect_zip() {
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"PK\x03\x04");
        let d = AutoDetector::with_builtins();
        let r = d.detect(&data, None).unwrap();
        assert_eq!(r.template_id, "zip");
    }

    #[test]
    fn fallback_when_no_match() {
        let mut d = AutoDetector::with_builtins();
        d.fallback_template = Some("generic".to_string());
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let r = d.detect(&data, None).unwrap();
        assert_eq!(r.template_id, "generic");
    }

    #[test]
    fn detect_all_returns_sorted() {
        let data = b"MZ\x00\x00";
        let d = AutoDetector::with_builtins();
        let all = d.detect_all(data, Some("test.exe"));
        if all.len() > 1 {
            assert!(all[0].score >= all[1].score);
        }
    }

    #[test]
    fn magic_rule_with_mask() {
        let rule = MagicRule {
            offset: 0,
            magic: vec![0xF0],
            mask: Some(vec![0xF0]),
            confidence: 1.0,
        };
        assert!(rule.matches(&[0xFF]));
        assert!(rule.matches(&[0xF0]));
        assert!(!rule.matches(&[0x0F]));
    }

    #[test]
    fn descriptor_count() {
        let d = AutoDetector::with_builtins();
        assert!(d.descriptor_count() >= 10);
    }
}
