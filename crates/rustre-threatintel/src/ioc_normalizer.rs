//! `IoC` normalizer — defanging, validation, deduplication, canonicalization.
//!
//! # Pipeline
//!
//! 1. **Defang** — decode obfuscation used in threat reports
//!    (`hxxp` → `http`, `[.]` → `.`, `[@]` → `@`, etc.).
//! 2. **Validate** — check structural correctness (valid IP, FQDN, hash length,
//!    URL schema, etc.).
//! 3. **Canonicalize** — bring a valid `IoC` to a stable, comparable form
//!    (lowercase domain, strip trailing dot, normalize IPv6, uppercase hash).
//! 4. **Deduplicate** — given a batch, remove duplicates *after*
//!    canonicalization so `hxxps://Evil[.]com` and `https://evil.com` collapse.
//! 5. **Confidence scoring** — assign a baseline confidence score based on the
//!    reporting source tier.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ioc::IoCType;

// ── Source tiers ─────────────────────────────────────────────────────────────

/// Tier of the source providing an `IoC`; higher tier → higher baseline confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum SourceTier {
    /// Automated community feed with minimal vetting (e.g. open OSINT lists).
    #[default]
    Community = 1,
    /// Vendor or ISAC-vetted feed (e.g. MISP community, OTX).
    Vendor = 2,
    /// Premium commercial threat intelligence (e.g. Recorded Future, Mandiant).
    Commercial = 3,
    /// First-hand analysis by the operator (highest confidence).
    FirstParty = 4,
}

impl SourceTier {
    /// Baseline confidence score `[0.0, 1.0]` for this tier.
    #[must_use] 
    pub const fn baseline_confidence(self) -> f32 {
        match self {
            Self::Community => 0.40,
            Self::Vendor => 0.65,
            Self::Commercial => 0.80,
            Self::FirstParty => 0.95,
        }
    }
}


// ── Validation errors ─────────────────────────────────────────────────────────

/// Reason an `IoC` failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationError {
    /// The value is empty or whitespace-only.
    Empty,
    /// IP address string is not parseable.
    InvalidIp(String),
    /// Domain contains illegal characters or labels.
    InvalidDomain(String),
    /// Hash has unexpected length for its declared type.
    WrongHashLength { expected: usize, actual: usize },
    /// URL is structurally invalid.
    InvalidUrl(String),
    /// Email is structurally invalid.
    InvalidEmail(String),
    /// Generic structural error.
    Malformed(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "value is empty"),
            Self::InvalidIp(s) => write!(f, "invalid IP: {s}"),
            Self::InvalidDomain(s) => write!(f, "invalid domain: {s}"),
            Self::WrongHashLength { expected, actual } => {
                write!(f, "hash length {actual} != expected {expected}")
            }
            Self::InvalidUrl(s) => write!(f, "invalid URL: {s}"),
            Self::InvalidEmail(s) => write!(f, "invalid email: {s}"),
            Self::Malformed(s) => write!(f, "malformed: {s}"),
        }
    }
}

// ── Normalized IoC ────────────────────────────────────────────────────────────

/// An `IoC` after the full normalization pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedIoC {
    /// Original (possibly defanged) value as received.
    pub raw: String,
    /// Canonical form after normalization.
    pub canonical: String,
    /// `IoC` type inferred or declared.
    pub ioc_type: IoCType,
    /// Confidence score after source-tier adjustment `[0.0, 1.0]`.
    pub confidence: f32,
    /// Source tier used for confidence scoring.
    pub source_tier: SourceTier,
    /// Tags copied from the original `IoC`, if any.
    pub tags: Vec<String>,
}

// ── Defanger ─────────────────────────────────────────────────────────────────

/// Decodes common threat-report obfuscations.
///
/// Obfuscations handled:
/// * `hxxp://` / `hxxps://` → `http://` / `https://`
/// * `[.]` / `(.)` / `{.}` → `.`
/// * `[@]` / `(@)` / `{@}` → `@`
/// * `[:]` → `:`
/// * `[/]` → `/`
/// * Double-bracket variants like `[[.]]`
pub struct Defanger;

impl Defanger {
    /// Defang a single value string, returning the decoded form.
    #[must_use] 
    pub fn defang(value: &str) -> String {
        let mut s = value.trim().to_string();

        // Protocol obfuscation
        for (obf, real) in [
            ("hxxps://", "https://"),
            ("hxxp://", "http://"),
            ("hXXps://", "https://"),
            ("hXXp://", "http://"),
            ("h**ps://", "https://"),
            ("h**p://", "http://"),
        ] {
            s = s.replace(obf, real);
        }

        // Dot obfuscation — order matters: longest first
        for obf in ["[[.]]", "[.]", "(.)", "{.}", "[dot]", "(dot)", "{dot}"] {
            s = s.replace(obf, ".");
        }

        // At-sign obfuscation
        for obf in ["[@]", "(@)", "{@}", "[at]", "(at)"] {
            s = s.replace(obf, "@");
        }

        // Colon obfuscation (port separators)
        s = s.replace("[:]", ":");

        // Slash obfuscation
        s = s.replace("[/]", "/");

        // Strip zero-width spaces and other invisible Unicode
        s.retain(|c| !matches!(c as u32, 0x200B | 0x200C | 0x200D | 0xFEFF | 0x00AD));

        s.trim().to_string()
    }

    /// Defang a batch, returning pairs `(original, defanged)`.
    #[must_use] 
    pub fn defang_batch(values: &[String]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|v| (v.clone(), Self::defang(v)))
            .collect()
    }
}

// ── Validator ─────────────────────────────────────────────────────────────────

/// Validates `IoC` values for structural correctness.
pub struct IoCValidator;

impl IoCValidator {
    /// Validate a value for the given [`IoCType`].
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when the value is empty or does not match the format
    /// expected for `ioc_type`.
    pub fn validate(value: &str, ioc_type: &IoCType) -> Result<(), ValidationError> {
        let v = value.trim();
        if v.is_empty() {
            return Err(ValidationError::Empty);
        }
        match ioc_type {
            IoCType::Ip => Self::validate_ip(v),
            IoCType::Domain => Self::validate_domain(v),
            IoCType::Url => Self::validate_url(v),
            IoCType::Email => Self::validate_email(v),
            IoCType::Md5 => Self::validate_hash(v, 32),
            IoCType::Sha1 => Self::validate_hash(v, 40),
            IoCType::Sha256 => Self::validate_hash(v, 64),
            IoCType::Sha512 => Self::validate_hash(v, 128),
            // Filenames, registry, mutex, YARA — accept non-empty
            _ => Ok(()),
        }
    }

    fn validate_ip(value: &str) -> Result<(), ValidationError> {
        IpAddr::from_str(value)
            .map(|_| ())
            .map_err(|_| ValidationError::InvalidIp(value.to_string()))
    }

    fn validate_domain(value: &str) -> Result<(), ValidationError> {
        let domain = value.trim_end_matches('.');
        if domain.is_empty() {
            return Err(ValidationError::InvalidDomain("empty".into()));
        }
        for label in domain.split('.') {
            if label.is_empty() {
                return Err(ValidationError::InvalidDomain(format!(
                    "empty label in '{value}'"
                )));
            }
            if label.len() > 63 {
                return Err(ValidationError::InvalidDomain(format!(
                    "label too long in '{value}'"
                )));
            }
            if !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ValidationError::InvalidDomain(format!(
                    "illegal chars in label '{label}'"
                )));
            }
        }
        if domain.len() > 253 {
            return Err(ValidationError::InvalidDomain(format!(
                "domain too long: {}", domain.len()
            )));
        }
        Ok(())
    }

    fn validate_url(value: &str) -> Result<(), ValidationError> {
        if !value.contains("://") {
            return Err(ValidationError::InvalidUrl(format!(
                "missing scheme in '{value}'"
            )));
        }
        let scheme = value.split("://").next().unwrap_or("");
        if !["http", "https", "ftp", "ftps"].contains(&scheme) {
            return Err(ValidationError::InvalidUrl(format!(
                "unsupported scheme '{scheme}'"
            )));
        }
        Ok(())
    }

    fn validate_email(value: &str) -> Result<(), ValidationError> {
        let parts: Vec<&str> = value.splitn(2, '@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(ValidationError::InvalidEmail(value.to_string()));
        }
        Ok(())
    }

    fn validate_hash(value: &str, expected_len: usize) -> Result<(), ValidationError> {
        if value.len() != expected_len {
            return Err(ValidationError::WrongHashLength {
                expected: expected_len,
                actual: value.len(),
            });
        }
        if !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ValidationError::Malformed(format!(
                "non-hex characters in hash '{value}'"
            )));
        }
        Ok(())
    }
}

// ── Canonicalizer ────────────────────────────────────────────────────────────

/// Brings a valid `IoC` to a stable, comparable canonical form.
pub struct IoCCanonicalizer;

impl IoCCanonicalizer {
    /// Canonicalize `value` according to its `ioc_type`.
    #[must_use] 
    pub fn canonicalize(value: &str, ioc_type: &IoCType) -> String {
        match ioc_type {
            IoCType::Domain => Self::canonicalize_domain(value),
            IoCType::Ip => Self::canonicalize_ip(value),
            IoCType::Url => Self::canonicalize_url(value),
            IoCType::Email => value.to_lowercase(),
            IoCType::Md5 | IoCType::Sha1 | IoCType::Sha256 | IoCType::Sha512 => {
                value.to_lowercase()
            }
            _ => value.to_string(),
        }
    }

    fn canonicalize_domain(value: &str) -> String {
        value.trim_end_matches('.').to_lowercase()
    }

    fn canonicalize_ip(value: &str) -> String {
        match IpAddr::from_str(value) {
            Ok(IpAddr::V4(ip)) => ip.to_string(),
            Ok(IpAddr::V6(ip)) => ip.to_string(),
            Err(_) => value.to_string(),
        }
    }

    fn canonicalize_url(value: &str) -> String {
        // Lowercase scheme + host, preserve path case
        value.find("://").map_or_else(|| value.to_string(), |pos| {
            let scheme = &value[..pos].to_lowercase();
            let rest = &value[pos + 3..];
            // Split off path
            let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
            let canon_authority = authority.to_lowercase();
            if path.is_empty() {
                format!("{scheme}://{canon_authority}")
            } else {
                format!("{scheme}://{canon_authority}/{path}")
            }
        })
    }
}

// ── Deduplicator ─────────────────────────────────────────────────────────────

/// Removes duplicate `IoCs` from a batch (after canonicalization).
pub struct IoCDeduplicator;

impl IoCDeduplicator {
    /// Deduplicate a batch of normalized `IoCs` by `(ioc_type, canonical)`.
    /// When duplicates exist, the one with the highest confidence is kept.
    ///
    /// # Panics
    ///
    /// Panics if the internal confidence comparator encounters NaN.
    #[must_use]
    pub fn deduplicate(iocs: Vec<NormalizedIoC>) -> Vec<NormalizedIoC> {
        let mut map: HashMap<(IoCType, String), NormalizedIoC> = HashMap::new();
        for ioc in iocs {
            let key = (ioc.ioc_type.clone(), ioc.canonical.clone());
            map.entry(key)
                .and_modify(|existing| {
                    if ioc.confidence > existing.confidence {
                        *existing = ioc.clone();
                    }
                })
                .or_insert(ioc);
        }
        let mut result: Vec<NormalizedIoC> = map.into_values().collect();
        result.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        result
    }
}

// ── Confidence scorer ─────────────────────────────────────────────────────────

/// Adjusts confidence based on source tier and optional quality signals.
pub struct SourceConfidenceScorer;

impl SourceConfidenceScorer {
    /// Compute confidence given a source tier and optional quality multiplier `[0.0, 1.0]`.
    #[must_use] 
    pub fn score(tier: SourceTier, quality_multiplier: Option<f32>) -> f32 {
        let base = tier.baseline_confidence();
        let mult = quality_multiplier.unwrap_or(1.0).clamp(0.0, 1.0);
        (base * mult).clamp(0.0, 1.0)
    }

    /// Combine scores from multiple sources using weighted average.
    #[must_use] 
    pub fn combine(scores: &[(f32, f32)]) -> f32 {
        // scores: Vec<(confidence, weight)>
        let total_weight: f32 = scores.iter().map(|(_, w)| w).sum();
        // `!(x > 0.0)` rather than `x == 0.0`: `scores` is caller-supplied and
        // every comparison with NaN is false, so the equality form would let a
        // NaN weight through and `clamp` propagates NaN rather than bounding it.
        if !(total_weight > 0.0) {
            return 0.0;
        }
        let weighted_sum: f32 = scores.iter().map(|(c, w)| c * w).sum();
        let combined = (weighted_sum / total_weight).clamp(0.0, 1.0);
        // A NaN confidence in the input poisons the numerator on its own.
        if combined.is_finite() { combined } else { 0.0 }
    }
}

// ── Main normalization pipeline ───────────────────────────────────────────────

/// Configuration for the normalization pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizerConfig {
    /// Skip `IoCs` that fail validation instead of returning an error.
    pub skip_invalid: bool,
    /// Default source tier when none is specified.
    pub default_tier: SourceTier,
    /// Quality multiplier applied to all `IoCs` from this source `[0.0, 1.0]`.
    pub source_quality: f32,
}

impl Default for NormalizerConfig {
    fn default() -> Self {
        Self {
            skip_invalid: true,
            default_tier: SourceTier::Community,
            source_quality: 1.0,
        }
    }
}

/// Result of processing one `IoC` through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NormalizationResult {
    /// Successfully normalized.
    Ok(NormalizedIoC),
    /// Validation failed; contains the original value and the error.
    Invalid { raw: String, error: ValidationError },
}

/// Full normalization pipeline: defang → validate → canonicalize → score.
pub struct IoCNormalizer {
    config: NormalizerConfig,
}

impl Default for IoCNormalizer {
    fn default() -> Self {
        Self::new(NormalizerConfig::default())
    }
}

impl IoCNormalizer {
    /// Create a new normalizer with the given configuration.
    #[must_use]
    pub const fn new(config: NormalizerConfig) -> Self {
        Self { config }
    }

    /// Process a single `IoC` value.
    #[must_use] 
    pub fn normalize_one(
        &self,
        raw: &str,
        ioc_type: IoCType,
        tier: Option<SourceTier>,
        tags: Vec<String>,
    ) -> NormalizationResult {
        // Step 1: defang
        let defanged = Defanger::defang(raw);

        // Step 2: validate
        if let Err(e) = IoCValidator::validate(&defanged, &ioc_type) {
            return NormalizationResult::Invalid {
                raw: raw.to_string(),
                error: e,
            };
        }

        // Step 3: canonicalize
        let canonical = IoCCanonicalizer::canonicalize(&defanged, &ioc_type);

        // Step 4: confidence scoring
        let effective_tier = tier.unwrap_or(self.config.default_tier);
        let confidence =
            SourceConfidenceScorer::score(effective_tier, Some(self.config.source_quality));

        NormalizationResult::Ok(NormalizedIoC {
            raw: raw.to_string(),
            canonical,
            ioc_type,
            confidence,
            source_tier: effective_tier,
            tags,
        })
    }

    /// Process a batch of `(raw_value, ioc_type)` pairs.
    #[must_use] 
    pub fn normalize_batch(
        &self,
        inputs: Vec<(String, IoCType, Option<SourceTier>, Vec<String>)>,
    ) -> (Vec<NormalizedIoC>, Vec<(String, ValidationError)>) {
        let mut valid = Vec::new();
        let mut invalid = Vec::new();

        for (raw, ioc_type, tier, tags) in inputs {
            match self.normalize_one(&raw, ioc_type, tier, tags) {
                NormalizationResult::Ok(n) => valid.push(n),
                NormalizationResult::Invalid { raw, error } => {
                    if !self.config.skip_invalid {
                        invalid.push((raw, error));
                    }
                }
            }
        }

        (valid, invalid)
    }

    /// Full pipeline including deduplication.
    #[must_use] 
    pub fn normalize_and_deduplicate(
        &self,
        inputs: Vec<(String, IoCType, Option<SourceTier>, Vec<String>)>,
    ) -> (Vec<NormalizedIoC>, Vec<(String, ValidationError)>) {
        let (valid, invalid) = self.normalize_batch(inputs);
        (IoCDeduplicator::deduplicate(valid), invalid)
    }
}

// ── Utility: infer type from value ───────────────────────────────────────────

/// Attempt to infer the [`IoCType`] of a value from its structure.
#[must_use] 
pub fn infer_ioc_type(value: &str) -> Option<IoCType> {
    let v = Defanger::defang(value);
    let v = v.trim();

    // Hash detection by length + hex
    if v.len() == 32 && v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IoCType::Md5);
    }
    if v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IoCType::Sha1);
    }
    if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IoCType::Sha256);
    }
    if v.len() == 128 && v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IoCType::Sha512);
    }

    // IP detection
    if IpAddr::from_str(v).is_ok() {
        return Some(IoCType::Ip);
    }

    // URL detection
    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://") {
        return Some(IoCType::Url);
    }

    // Email detection
    if v.contains('@') && v.contains('.') {
        return Some(IoCType::Email);
    }

    // Domain detection (simple heuristic)
    if v.contains('.') && !v.contains('/') && !v.contains(' ')
        && IoCValidator::validate_domain(v).is_ok() {
            return Some(IoCType::Domain);
        }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defang_hxxp() {
        assert_eq!(Defanger::defang("hxxp://evil[.]com/path"), "http://evil.com/path");
    }

    #[test]
    fn defang_brackets() {
        assert_eq!(Defanger::defang("evil[.]com"), "evil.com");
    }

    #[test]
    fn validate_ip_ok() {
        assert!(IoCValidator::validate("192.168.1.1", &IoCType::Ip).is_ok());
        assert!(IoCValidator::validate("::1", &IoCType::Ip).is_ok());
    }

    #[test]
    fn validate_ip_err() {
        assert!(IoCValidator::validate("999.1.1.1", &IoCType::Ip).is_err());
    }

    #[test]
    fn validate_sha256_ok() {
        let h = "a".repeat(64);
        assert!(IoCValidator::validate(&h, &IoCType::Sha256).is_ok());
    }

    #[test]
    fn canonicalize_domain() {
        assert_eq!(
            IoCCanonicalizer::canonicalize("Evil.COM.", &IoCType::Domain),
            "evil.com"
        );
    }

    #[test]
    fn dedup_keeps_highest_confidence() {
        let a = NormalizedIoC {
            raw: "a".into(),
            canonical: "evil.com".into(),
            ioc_type: IoCType::Domain,
            confidence: 0.5,
            source_tier: SourceTier::Community,
            tags: vec![],
        };
        let b = NormalizedIoC {
            raw: "b".into(),
            canonical: "evil.com".into(),
            ioc_type: IoCType::Domain,
            confidence: 0.9,
            source_tier: SourceTier::Commercial,
            tags: vec![],
        };
        let result = IoCDeduplicator::deduplicate(vec![a, b]);
        assert_eq!(result.len(), 1);
        assert!((result[0].confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn infer_md5() {
        assert_eq!(infer_ioc_type(&"d".repeat(32)), Some(IoCType::Md5));
    }

    #[test]
    fn pipeline_full() {
        let norm = IoCNormalizer::new(NormalizerConfig {
            skip_invalid: true,
            default_tier: SourceTier::Vendor,
            source_quality: 1.0,
        });
        let inputs = vec![
            (
                "hxxp://Evil[.]com/malware".to_string(),
                IoCType::Url,
                None,
                vec![],
            ),
            (
                "hxxp://Evil[.]com/malware".to_string(), // duplicate
                IoCType::Url,
                None,
                vec![],
            ),
            (
                "not-valid-!!".to_string(),
                IoCType::Ip,
                None,
                vec![],
            ),
        ];
        let (valid, _invalid) = norm.normalize_and_deduplicate(inputs);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].canonical, "http://evil.com/malware");
    }
}
