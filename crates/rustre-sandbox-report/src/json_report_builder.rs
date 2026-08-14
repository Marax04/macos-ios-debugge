//! `json_report_builder` — Structured JSON report builder for sandbox analysis results.
//!
//! Provides a typed JSON schema, field-by-field builder API, partial-report
//! serialisation, diff generation between two reports, and STIX-2.1 indicator
//! export helpers.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AttackMapping, AttackTechnique, Behavior, Indicator, IndicatorCategory, IocSet,
    SandboxReport, Severity, Verdict,
};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum JsonReportError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("invalid field value for '{field}': {reason}")]
    InvalidField { field: String, reason: String },
}

// ─── JsonReportVersion ────────────────────────────────────────────────────────

/// Schema version for the JSON report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum JsonReportVersion {
    V1,
    #[default]
    V2,
}

impl JsonReportVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "1.0",
            Self::V2 => "2.0",
        }
    }
}

// ─── JsonMetadata ─────────────────────────────────────────────────────────────

/// Top-level report metadata block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonMetadata {
    pub schema_version: String,
    pub report_id: String,
    pub generated_at: String,
    pub generator: String,
    pub analysis_engine: String,
    pub duration_ms: u64,
}

impl JsonMetadata {
    #[must_use]
    pub fn new(report_id: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            schema_version: JsonReportVersion::V2.as_str().to_owned(),
            report_id: report_id.into(),
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            generator: "rustre-sandbox-report".to_owned(),
            analysis_engine: "RustRE Sandbox".to_owned(),
            duration_ms,
        }
    }

    #[must_use]
    pub fn with_timestamp(mut self, ts: impl Into<String>) -> Self {
        self.generated_at = ts.into();
        self
    }
}

// ─── JsonSampleInfo ───────────────────────────────────────────────────────────

/// Information about the analyzed sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSampleInfo {
    pub name: String,
    pub sha256: String,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub size_bytes: Option<u64>,
    pub file_type: Option<String>,
    pub arch: Option<String>,
    pub platform: Option<String>,
    pub compile_time: Option<String>,
    pub packer: Option<String>,
}

impl JsonSampleInfo {
    #[must_use]
    pub fn new(name: impl Into<String>, sha256: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sha256: sha256.into(),
            sha1: None,
            md5: None,
            size_bytes: None,
            file_type: None,
            arch: None,
            platform: None,
            compile_time: None,
            packer: None,
        }
    }

    #[must_use]
    pub fn with_hashes(mut self, sha1: Option<String>, md5: Option<String>) -> Self {
        self.sha1 = sha1;
        self.md5 = md5;
        self
    }

    #[must_use]
    pub fn with_file_info(
        mut self,
        size: u64,
        file_type: impl Into<String>,
        arch: impl Into<String>,
    ) -> Self {
        self.size_bytes = Some(size);
        self.file_type = Some(file_type.into());
        self.arch = Some(arch.into());
        self
    }
}

// ─── JsonVerdict ──────────────────────────────────────────────────────────────

/// Verdict block in the JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonVerdict {
    pub verdict: String,
    pub score: u32,
    pub family: String,
    pub tags: Vec<String>,
    pub confidence: u8,
}

impl JsonVerdict {
    #[must_use]
    pub fn from_report(report: &SandboxReport) -> Self {
        let confidence = match &report.verdict {
            Verdict::Malicious => 90,
            Verdict::Suspicious => 60,
            Verdict::Low => 40,
            Verdict::Clean => 95,
            Verdict::Unknown => 20,
        };
        Self {
            verdict: report.verdict.to_string(),
            score: report.score,
            family: report.family.clone(),
            tags: report.tags.clone(),
            confidence,
        }
    }
}

// ─── JsonIndicatorEntry ───────────────────────────────────────────────────────

/// A single indicator entry in JSON form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonIndicatorEntry {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub technique_ids: Vec<String>,
    pub ioc: Option<String>,
}

impl JsonIndicatorEntry {
    #[must_use]
    pub fn from_indicator(ind: &Indicator) -> Self {
        Self {
            name: ind.name.clone(),
            description: ind.desc.clone(),
            severity: ind.severity.to_string(),
            category: ind.category.to_string(),
            technique_ids: ind.technique_ids.clone(),
            ioc: ind.ioc.clone(),
        }
    }
}

// ─── JsonBehaviorEntry ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonBehaviorEntry {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub apis: Vec<String>,
    pub pid: u32,
    pub first_seen_ms: u64,
}

impl JsonBehaviorEntry {
    #[must_use]
    pub fn from_behavior(b: &Behavior) -> Self {
        Self {
            name: b.name.clone(),
            description: b.desc.clone(),
            severity: b.severity.to_string(),
            category: b.category.clone(),
            apis: b.apis.clone(),
            pid: b.pid,
            first_seen_ms: b.first_seen_ms,
        }
    }
}

// ─── JsonAttackEntry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonAttackEntry {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

impl JsonAttackEntry {
    #[must_use]
    pub fn from_technique(t: &AttackTechnique) -> Self {
        Self {
            id: t.full_id().to_owned(),
            name: t.name.clone(),
            tactic: t.tactic.to_string(),
            confidence: t.confidence,
            evidence: t.evidence.clone(),
        }
    }
}

// ─── JsonIocEntry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonIocEntry {
    pub ioc_type: String,
    pub value: String,
    pub confidence: u8,
    pub context: String,
}

// ─── JsonReport ───────────────────────────────────────────────────────────────

/// Complete JSON report structure ready for serialisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub metadata: JsonMetadata,
    pub sample: JsonSampleInfo,
    pub verdict: JsonVerdict,
    pub indicators: Vec<JsonIndicatorEntry>,
    pub behaviors: Vec<JsonBehaviorEntry>,
    pub iocs: Vec<JsonIocEntry>,
    pub attack_techniques: Vec<JsonAttackEntry>,
    pub sections: Vec<JsonSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_score_breakdown: Option<ScoreBreakdown>,
}

/// A text section within the JSON report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSection {
    pub title: String,
    pub content: String,
    pub order: u32,
}

/// Per-category score breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub by_category: HashMap<String, u32>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl ScoreBreakdown {
    /// Compute the breakdown from a list of indicators.
    #[must_use]
    pub fn compute(indicators: &[Indicator]) -> Self {
        let mut by_category: HashMap<String, u32> = HashMap::new();
        let mut critical_count = 0usize;
        let mut high_count = 0usize;
        let mut medium_count = 0usize;
        let mut low_count = 0usize;
        let mut info_count = 0usize;

        for ind in indicators {
            *by_category
                .entry(ind.category.to_string())
                .or_default() += u32::from(ind.severity.score());
            match ind.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
                Severity::Info => info_count += 1,
            }
        }

        Self {
            by_category,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
        }
    }
}

impl JsonReport {
    /// Build a `JsonReport` from a `SandboxReport`.
    #[must_use]
    pub fn from_sandbox_report(report: &SandboxReport) -> Self {
        let metadata = JsonMetadata::new(&report.sha256, report.analysis_ms);
        let sample = JsonSampleInfo::new(&report.sample, &report.sha256);
        let verdict = JsonVerdict::from_report(report);
        let indicators = report
            .indicators
            .iter()
            .map(JsonIndicatorEntry::from_indicator)
            .collect();
        let behaviors = report
            .behaviors
            .iter()
            .map(JsonBehaviorEntry::from_behavior)
            .collect();
        let iocs = report
            .iocs
            .iocs
            .iter()
            .map(|i| JsonIocEntry {
                ioc_type: i.kind.to_string(),
                value: i.value.clone(),
                confidence: i.confidence,
                context: i.context.clone(),
            })
            .collect();
        let attack_techniques = report
            .attack
            .techniques
            .iter()
            .map(JsonAttackEntry::from_technique)
            .collect();
        let sections = report
            .sections
            .iter()
            .map(|s| JsonSection {
                title: s.title.clone(),
                content: s.content.clone(),
                order: s.order,
            })
            .collect();
        let raw_score_breakdown = Some(ScoreBreakdown::compute(&report.indicators));

        Self {
            metadata,
            sample,
            verdict,
            indicators,
            behaviors,
            iocs,
            attack_techniques,
            sections,
            raw_score_breakdown,
        }
    }

    /// Serialize to a pretty-printed JSON string.
    ///
    /// # Errors
    /// Returns `JsonReportError::Serialization` on failure.
    pub fn to_json_pretty(&self) -> Result<String, JsonReportError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| JsonReportError::Serialization(e.to_string()))
    }

    /// Serialize to a compact JSON string.
    ///
    /// # Errors
    /// Returns `JsonReportError::Serialization` on failure.
    pub fn to_json_compact(&self) -> Result<String, JsonReportError> {
        serde_json::to_string(self).map_err(|e| JsonReportError::Serialization(e.to_string()))
    }

    /// Return the count of high-or-critical indicators.
    #[must_use]
    pub fn high_critical_count(&self) -> usize {
        self.indicators
            .iter()
            .filter(|i| matches!(i.severity.as_str(), "critical" | "high"))
            .count()
    }

    /// Return a sorted list of all unique tactic strings.
    #[must_use]
    pub fn unique_tactics(&self) -> Vec<String> {
        let mut tactics: Vec<String> = self
            .attack_techniques
            .iter()
            .map(|t| t.tactic.clone())
            .collect();
        tactics.sort();
        tactics.dedup();
        tactics
    }

    /// Return all IOC values of a given type.
    #[must_use]
    pub fn iocs_of_type(&self, ioc_type: &str) -> Vec<&str> {
        self.iocs
            .iter()
            .filter(|i| i.ioc_type == ioc_type)
            .map(|i| i.value.as_str())
            .collect()
    }

    /// Build a STIX-2.1 bundle (JSON string) from the IOCs in this report.
    ///
    /// Each IOC becomes a STIX `indicator` domain object with a simple
    /// pattern string. The bundle is returned as a compact JSON string.
    ///
    /// # Errors
    /// Returns `JsonReportError::Serialization` on failure.
    pub fn to_stix_bundle(&self) -> Result<String, JsonReportError> {
        let mut objects = Vec::new();

        for (idx, ioc) in self.iocs.iter().enumerate() {
            let pattern = stix_pattern_for_ioc(&ioc.ioc_type, &ioc.value);
            if pattern.is_empty() {
                continue;
            }
            let obj = serde_json::json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": format!("indicator--{:08x}-0000-0000-0000-{:012x}", idx, idx),
                "created": &self.metadata.generated_at,
                "modified": &self.metadata.generated_at,
                "name": format!("{} indicator", ioc.ioc_type),
                "description": &ioc.context,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": &self.metadata.generated_at,
                "confidence": ioc.confidence,
                "labels": [&ioc.ioc_type]
            });
            objects.push(obj);
        }

        let bundle = serde_json::json!({
            "type": "bundle",
            "id": format!("bundle--{}", &self.metadata.report_id),
            "spec_version": "2.1",
            "objects": objects,
        });

        serde_json::to_string(&bundle)
            .map_err(|e| JsonReportError::Serialization(e.to_string()))
    }
}

/// Generate a STIX-2.1 pattern string for an IOC.
fn stix_pattern_for_ioc(ioc_type: &str, value: &str) -> String {
    match ioc_type {
        "ip" => format!("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{value}']"),
        "domain" => format!("[domain-name:value = '{value}']"),
        "url" => format!("[url:value = '{value}']"),
        "filehash" => {
            if value.len() == 64 {
                format!("[file:hashes.'SHA-256' = '{value}']")
            } else if value.len() == 40 {
                format!("[file:hashes.'SHA-1' = '{value}']")
            } else {
                format!("[file:hashes.'MD5' = '{value}']")
            }
        }
        "filepath" => format!("[file:name = '{value}']"),
        "registry_key" => format!("[windows-registry-key:key = '{value}']"),
        "mutex" => format!("[mutex:name = '{value}']"),
        "email" => format!("[email-addr:value = '{value}']"),
        _ => String::new(),
    }
}

// ─── JsonReportDiff ───────────────────────────────────────────────────────────

/// Differences between two JSON reports (e.g. baseline vs. new run).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReportDiff {
    pub new_indicators: Vec<JsonIndicatorEntry>,
    pub removed_indicators: Vec<JsonIndicatorEntry>,
    pub new_iocs: Vec<JsonIocEntry>,
    pub removed_iocs: Vec<JsonIocEntry>,
    pub score_delta: i32,
    pub verdict_changed: bool,
    pub new_techniques: Vec<String>,
    pub removed_techniques: Vec<String>,
}

impl JsonReportDiff {
    /// Compute the diff between `before` and `after`.
    #[must_use]
    pub fn compute(before: &JsonReport, after: &JsonReport) -> Self {
        let before_ind_names: std::collections::HashSet<&str> =
            before.indicators.iter().map(|i| i.name.as_str()).collect();
        let after_ind_names: std::collections::HashSet<&str> =
            after.indicators.iter().map(|i| i.name.as_str()).collect();

        let new_indicators = after
            .indicators
            .iter()
            .filter(|i| !before_ind_names.contains(i.name.as_str()))
            .cloned()
            .collect();
        let removed_indicators = before
            .indicators
            .iter()
            .filter(|i| !after_ind_names.contains(i.name.as_str()))
            .cloned()
            .collect();

        let before_ioc_vals: std::collections::HashSet<&str> =
            before.iocs.iter().map(|i| i.value.as_str()).collect();
        let after_ioc_vals: std::collections::HashSet<&str> =
            after.iocs.iter().map(|i| i.value.as_str()).collect();

        let new_iocs = after
            .iocs
            .iter()
            .filter(|i| !before_ioc_vals.contains(i.value.as_str()))
            .cloned()
            .collect();
        let removed_iocs = before
            .iocs
            .iter()
            .filter(|i| !after_ioc_vals.contains(i.value.as_str()))
            .cloned()
            .collect();

        let before_score = before.verdict.score;
        let after_score = after.verdict.score;
        let score_delta = after_score.cast_signed() - before_score.cast_signed();
        let verdict_changed = before.verdict.verdict != after.verdict.verdict;

        let before_ttps: std::collections::HashSet<&str> = before
            .attack_techniques
            .iter()
            .map(|t| t.id.as_str())
            .collect();
        let after_ttps: std::collections::HashSet<&str> = after
            .attack_techniques
            .iter()
            .map(|t| t.id.as_str())
            .collect();

        let new_techniques = after_ttps
            .difference(&before_ttps)
            .map(ToString::to_string)
            .collect();
        let removed_techniques = before_ttps
            .difference(&after_ttps)
            .map(ToString::to_string)
            .collect();

        Self {
            new_indicators,
            removed_indicators,
            new_iocs,
            removed_iocs,
            score_delta,
            verdict_changed,
            new_techniques,
            removed_techniques,
        }
    }

    /// Returns `true` if there are any meaningful differences.
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        !self.new_indicators.is_empty()
            || !self.removed_indicators.is_empty()
            || !self.new_iocs.is_empty()
            || !self.removed_iocs.is_empty()
            || self.verdict_changed
            || self.score_delta != 0
    }

    /// Summarise the diff as a one-line string.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.new_indicators.is_empty() {
            parts.push(format!("+{} indicators", self.new_indicators.len()));
        }
        if !self.removed_indicators.is_empty() {
            parts.push(format!("-{} indicators", self.removed_indicators.len()));
        }
        if !self.new_iocs.is_empty() {
            parts.push(format!("+{} iocs", self.new_iocs.len()));
        }
        if self.score_delta != 0 {
            parts.push(format!("score {:+}", self.score_delta));
        }
        if self.verdict_changed {
            parts.push("verdict changed".to_string());
        }
        if parts.is_empty() {
            "no changes".to_string()
        } else {
            parts.join(", ")
        }
    }
}

// ─── JsonReportBuilder ────────────────────────────────────────────────────────

/// Fluent builder for `JsonReport`.
#[derive(Debug, Clone, Default)]
pub struct JsonReportBuilder {
    metadata: Option<JsonMetadata>,
    sample: Option<JsonSampleInfo>,
    verdict: Option<JsonVerdict>,
    indicators: Vec<JsonIndicatorEntry>,
    behaviors: Vec<JsonBehaviorEntry>,
    iocs: Vec<JsonIocEntry>,
    attack_techniques: Vec<JsonAttackEntry>,
    sections: Vec<JsonSection>,
    score_breakdown: bool,
}

impl JsonReportBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn metadata(mut self, m: JsonMetadata) -> Self {
        self.metadata = Some(m);
        self
    }

    #[must_use]
    pub fn sample(mut self, s: JsonSampleInfo) -> Self {
        self.sample = Some(s);
        self
    }

    #[must_use]
    pub fn verdict(mut self, v: JsonVerdict) -> Self {
        self.verdict = Some(v);
        self
    }

    #[must_use]
    pub fn add_indicator(mut self, i: JsonIndicatorEntry) -> Self {
        self.indicators.push(i);
        self
    }

    #[must_use]
    pub fn add_behavior(mut self, b: JsonBehaviorEntry) -> Self {
        self.behaviors.push(b);
        self
    }

    #[must_use]
    pub fn add_ioc(mut self, ioc: JsonIocEntry) -> Self {
        self.iocs.push(ioc);
        self
    }

    #[must_use]
    pub fn add_attack_technique(mut self, t: JsonAttackEntry) -> Self {
        self.attack_techniques.push(t);
        self
    }

    #[must_use]
    pub fn add_section(mut self, s: JsonSection) -> Self {
        self.sections.push(s);
        self
    }

    #[must_use]
    pub const fn with_score_breakdown(mut self) -> Self {
        self.score_breakdown = true;
        self
    }

    /// Build the `JsonReport`.
    ///
    /// # Errors
    /// Returns `JsonReportError::MissingField` if metadata, sample or verdict are absent.
    pub fn build(self) -> Result<JsonReport, JsonReportError> {
        let metadata = self
            .metadata
            .ok_or_else(|| JsonReportError::MissingField("metadata".to_owned()))?;
        let sample = self
            .sample
            .ok_or_else(|| JsonReportError::MissingField("sample".to_owned()))?;
        let verdict = self
            .verdict
            .ok_or_else(|| JsonReportError::MissingField("verdict".to_owned()))?;

        // raw_score_breakdown would be populated from indicators in a full implementation.
        let raw_score_breakdown = None;

        Ok(JsonReport {
            metadata,
            sample,
            verdict,
            indicators: self.indicators,
            behaviors: self.behaviors,
            iocs: self.iocs,
            attack_techniques: self.attack_techniques,
            sections: self.sections,
            raw_score_breakdown,
        })
    }
}

// ─── convenience function ─────────────────────────────────────────────────────

/// Build and serialise a `JsonReport` from a `SandboxReport` in one call.
///
/// # Errors
/// Returns `JsonReportError::Serialization` on failure.
pub fn build_json_report(report: &SandboxReport) -> Result<String, JsonReportError> {
    JsonReport::from_sandbox_report(report).to_json_pretty()
}

/// Build a compact JSON report from a `SandboxReport`.
///
/// # Errors
/// Returns `JsonReportError::Serialization` on failure.
pub fn build_json_report_compact(report: &SandboxReport) -> Result<String, JsonReportError> {
    JsonReport::from_sandbox_report(report).to_json_compact()
}

// ─── Public summary helpers wiring crate-level types into the JSON builder ───

/// Format a textual one-line summary of an [`AttackMapping`] using
/// [`std::fmt::Write`] for efficient concatenation.
#[must_use]
pub fn attack_mapping_summary_line(mapping: &AttackMapping) -> String {
    let mut out = String::from("ATT&CK:");
    for t in &mapping.techniques {
        let _ = write!(out, " {}", t.id);
    }
    out
}

/// Format the [`IndicatorCategory`] distribution from an iterator of indicators.
#[must_use]
pub fn indicator_category_counts(indicators: &[crate::Indicator]) -> std::collections::HashMap<String, usize> {
    let mut map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for ind in indicators {
        let key: &IndicatorCategory = &ind.category;
        *map.entry(key.to_string()).or_insert(0) += 1;
    }
    map
}

/// Compute the total IOC count across an [`IocSet`].
#[must_use]
pub const fn ioc_set_total(set: &IocSet) -> usize {
    set.iocs.len()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxReport;

    fn mock_report() -> SandboxReport {
        SandboxReport::mock()
    }

    #[test]
    fn json_metadata_new() {
        let m = JsonMetadata::new("abc123", 30_000);
        assert_eq!(m.report_id, "abc123");
        assert_eq!(m.duration_ms, 30_000);
        assert_eq!(m.schema_version, "2.0");
    }

    #[test]
    fn json_metadata_with_timestamp() {
        let m = JsonMetadata::new("id", 0).with_timestamp("2026-01-01T12:00:00Z");
        assert_eq!(m.generated_at, "2026-01-01T12:00:00Z");
    }

    #[test]
    fn json_sample_info_new() {
        let s = JsonSampleInfo::new("malware.exe", "deadbeef");
        assert_eq!(s.name, "malware.exe");
        assert_eq!(s.sha256, "deadbeef");
        assert!(s.sha1.is_none());
    }

    #[test]
    fn json_sample_info_with_hashes() {
        let s = JsonSampleInfo::new("a.exe", "0000")
            .with_hashes(Some("sha1val".into()), Some("md5val".into()));
        assert_eq!(s.sha1.unwrap(), "sha1val");
    }

    #[test]
    fn json_verdict_from_report() {
        let report = mock_report();
        let v = JsonVerdict::from_report(&report);
        assert!(!v.verdict.is_empty());
        assert!(v.score <= 100);
    }

    #[test]
    fn json_report_from_sandbox_report() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        assert!(!jr.indicators.is_empty());
        assert!(!jr.iocs.is_empty());
        assert_eq!(jr.sample.sha256, report.sha256);
    }

    #[test]
    fn json_report_to_pretty() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let s = jr.to_json_pretty().unwrap();
        assert!(s.contains("\"schema_version\""));
        assert!(s.contains("\"verdict\""));
    }

    #[test]
    fn json_report_to_compact() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let s = jr.to_json_compact().unwrap();
        assert!(!s.contains("  ")); // compact should not have indentation
    }

    #[test]
    fn build_json_report_fn() {
        let report = mock_report();
        let s = build_json_report(&report).unwrap();
        assert!(s.contains("indicators"));
    }

    #[test]
    fn json_report_high_critical_count() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let count = jr.high_critical_count();
        assert!(count > 0);
    }

    #[test]
    fn json_report_unique_tactics() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let tactics = jr.unique_tactics();
        // should be deduplicated
        let mut sorted = tactics.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(tactics.len(), sorted.len());
    }

    #[test]
    fn json_report_iocs_of_type_ip() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let ips = jr.iocs_of_type("ip");
        // mock report has at least one IP IOC
        assert!(!ips.is_empty());
    }

    #[test]
    fn stix_bundle_generation() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let bundle = jr.to_stix_bundle().unwrap();
        assert!(bundle.contains("bundle"));
        assert!(bundle.contains("indicator"));
    }

    #[test]
    fn json_report_diff_no_changes() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let diff = JsonReportDiff::compute(&jr, &jr);
        assert!(!diff.has_changes());
    }

    #[test]
    fn json_report_diff_summary_no_changes() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        let diff = JsonReportDiff::compute(&jr, &jr);
        assert_eq!(diff.summary(), "no changes");
    }

    #[test]
    fn json_report_diff_with_added_ioc() {
        let report = mock_report();
        let mut jr1 = JsonReport::from_sandbox_report(&report);
        let jr2 = jr1.clone();
        jr1.iocs.clear();
        let diff = JsonReportDiff::compute(&jr1, &jr2);
        assert!(!diff.new_iocs.is_empty());
        assert!(diff.has_changes());
    }

    #[test]
    fn score_breakdown_compute() {
        let report = mock_report();
        let breakdown = ScoreBreakdown::compute(&report.indicators);
        assert!(!breakdown.by_category.is_empty());
        assert!(breakdown.critical_count + breakdown.high_count > 0);
    }

    #[test]
    fn builder_missing_metadata() {
        let err = JsonReportBuilder::new()
            .sample(JsonSampleInfo::new("a", "b"))
            .verdict(JsonVerdict {
                verdict: "unknown".into(),
                score: 0,
                family: String::new(),
                tags: vec![],
                confidence: 0,
            })
            .build();
        assert!(matches!(err, Err(JsonReportError::MissingField(_))));
    }

    #[test]
    fn builder_full_build() {
        let jr = JsonReportBuilder::new()
            .metadata(JsonMetadata::new("id1", 1000))
            .sample(JsonSampleInfo::new("test.exe", "abc"))
            .verdict(JsonVerdict {
                verdict: "malicious".into(),
                score: 90,
                family: "trojan".into(),
                tags: vec![],
                confidence: 85,
            })
            .build()
            .unwrap();
        assert_eq!(jr.sample.name, "test.exe");
        assert_eq!(jr.verdict.score, 90);
    }

    #[test]
    fn stix_pattern_ip() {
        let p = stix_pattern_for_ioc("ip", "1.2.3.4");
        assert!(p.contains("ipv4-addr"));
        assert!(p.contains("1.2.3.4"));
    }

    #[test]
    fn stix_pattern_domain() {
        let p = stix_pattern_for_ioc("domain", "evil.com");
        assert!(p.contains("domain-name"));
        assert!(p.contains("evil.com"));
    }

    #[test]
    fn stix_pattern_sha256() {
        let sha = "a".repeat(64);
        let p = stix_pattern_for_ioc("filehash", &sha);
        assert!(p.contains("SHA-256"));
    }

    #[test]
    fn stix_pattern_unknown_returns_empty() {
        let p = stix_pattern_for_ioc("banana", "value");
        assert!(p.is_empty());
    }

    #[test]
    fn json_report_version_str() {
        assert_eq!(JsonReportVersion::V1.as_str(), "1.0");
        assert_eq!(JsonReportVersion::V2.as_str(), "2.0");
    }

    #[test]
    fn json_report_contains_breakdown() {
        let report = mock_report();
        let jr = JsonReport::from_sandbox_report(&report);
        assert!(jr.raw_score_breakdown.is_some());
    }
}
