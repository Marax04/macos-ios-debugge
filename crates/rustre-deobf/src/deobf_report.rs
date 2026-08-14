//! `deobf_report` — Statistics-centric deobfuscation report generation.
//!
//! Tracks per-pass transformation counts, before/after obfuscation scores
//! (`ObfScore`), and exports to plain text, JSON, HTML, CSV, and Markdown.
//! Does not depend on `serde`; JSON is hand-rolled.
//!
//! # Relation to `report` and `deobf_report_extended`
//! This module is **statistics-centric**: its `DeobfReport` carries an
//! `ObfScore` (entropy, CFG complexity, anti-analysis components) and a
//! `ReportAggregator` for batch analysis. Multi-format export is built-in.
//!
//! [`report`](crate::report) is **pass-centric** with `Finding`/`Severity`
//! classification and serde-backed JSON/HTML export.
//!
//! [`deobf_report_extended`](crate::deobf_report_extended) is
//! **technique-centric** with a 50+ entry taxonomy, byte-level timelines, and
//! a per-technique confidence matrix.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Report format enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    PlainText,
    Json,
    Html,
    Csv,
    Markdown,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlainText => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::Html => write!(f, "html"),
            Self::Csv => write!(f, "csv"),
            Self::Markdown => write!(f, "markdown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Transform stat — one category of change
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TransformStat {
    pub category: String,
    pub count: u64,
    pub bytes_affected: u64,
    pub description: String,
}

impl TransformStat {
    #[must_use]
    pub fn new(category: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            count: 0,
            bytes_affected: 0,
            description: description.into(),
        }
    }

    pub const fn increment(&mut self, bytes: u64) {
        self.count += 1;
        self.bytes_affected += bytes;
    }

    pub const fn add(&mut self, count: u64, bytes: u64) {
        self.count += count;
        self.bytes_affected += bytes;
    }
}

// ---------------------------------------------------------------------------
// PassSummary — per-pass results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PassSummary {
    pub pass_id: String,
    pub pass_name: String,
    pub executed: bool,
    pub succeeded: bool,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub duration_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub transforms: Vec<TransformStat>,
    pub error_message: Option<String>,
    pub strings_recovered: u64,
    pub branches_simplified: u64,
    pub instructions_modified: u64,
    pub patches_applied: u64,
    pub notes: Vec<String>,
}

impl PassSummary {
    #[must_use]
    pub fn new(pass_id: impl Into<String>, pass_name: impl Into<String>) -> Self {
        Self {
            pass_id: pass_id.into(),
            pass_name: pass_name.into(),
            executed: false,
            succeeded: false,
            skipped: false,
            skip_reason: None,
            duration_ms: 0,
            bytes_in: 0,
            bytes_out: 0,
            transforms: Vec::new(),
            error_message: None,
            strings_recovered: 0,
            branches_simplified: 0,
            instructions_modified: 0,
            patches_applied: 0,
            notes: Vec::new(),
        }
    }

    pub fn mark_skipped(&mut self, reason: impl Into<String>) {
        self.skipped = true;
        self.skip_reason = Some(reason.into());
    }

    pub const fn mark_executed(&mut self, succeeded: bool, duration_ms: u64, bytes_in: u64, bytes_out: u64) {
        self.executed = true;
        self.succeeded = succeeded;
        self.duration_ms = duration_ms;
        self.bytes_in = bytes_in;
        self.bytes_out = bytes_out;
    }

    pub fn add_transform(&mut self, stat: TransformStat) {
        self.transforms.push(stat);
    }

    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    #[must_use]
    pub fn total_transforms(&self) -> u64 {
        self.transforms.iter().map(|t| t.count).sum()
    }

    #[must_use]
    pub fn bytes_delta(&self) -> i64 {
        let out = i64::try_from(self.bytes_out).unwrap_or(i64::MAX);
        let inp = i64::try_from(self.bytes_in).unwrap_or(i64::MAX);
        out.saturating_sub(inp)
    }

    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_in == 0 {
            1.0
        } else {
            let out = f64::from(u32::try_from(self.bytes_out).unwrap_or(u32::MAX));
            let inp = f64::from(u32::try_from(self.bytes_in).unwrap_or(u32::MAX));
            out / inp
        }
    }
}

// ---------------------------------------------------------------------------
// ObfScore — obfuscation score before/after
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ObfScore {
    /// 0.0 = clean, 1.0 = maximally obfuscated
    pub score: f64,
    pub entropy_component: f64,
    pub control_flow_component: f64,
    pub string_obfuscation_component: f64,
    pub anti_analysis_component: f64,
    pub packing_component: f64,
    pub label: ObfLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfLabel {
    Clean,
    LightObfuscation,
    ModerateObfuscation,
    HeavyObfuscation,
    Packed,
    Virtualized,
}

impl fmt::Display for ObfLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::LightObfuscation => write!(f, "Lightly Obfuscated"),
            Self::ModerateObfuscation => write!(f, "Moderately Obfuscated"),
            Self::HeavyObfuscation => write!(f, "Heavily Obfuscated"),
            Self::Packed => write!(f, "Packed"),
            Self::Virtualized => write!(f, "Virtualized"),
        }
    }
}

impl ObfScore {
    #[must_use]
    pub fn compute(
        entropy: f64,
        cfg_complexity: f64,
        string_obf_ratio: f64,
        anti_analysis_count: u32,
        is_packed: bool,
        is_virtualized: bool,
    ) -> Self {
        let entropy_component = ((entropy - 4.5) / 3.5).clamp(0.0, 1.0);
        let control_flow_component = (cfg_complexity / 100.0).min(1.0);
        let string_obfuscation_component = string_obf_ratio.min(1.0);
        let anti_analysis_component = (f64::from(anti_analysis_count) / 10.0).min(1.0);
        let packing_component = if is_packed { 1.0 } else { 0.0 };

        let score = entropy_component * 0.25
            + control_flow_component * 0.20
            + string_obfuscation_component * 0.25
            + anti_analysis_component * 0.15
            + packing_component * 0.15;

        let label = if is_virtualized {
            ObfLabel::Virtualized
        } else if is_packed {
            ObfLabel::Packed
        } else if score >= 0.65 {
            ObfLabel::HeavyObfuscation
        } else if score >= 0.40 {
            ObfLabel::ModerateObfuscation
        } else if score >= 0.20 {
            ObfLabel::LightObfuscation
        } else {
            ObfLabel::Clean
        };

        Self {
            score,
            entropy_component,
            control_flow_component,
            string_obfuscation_component,
            anti_analysis_component,
            packing_component,
            label,
        }
    }

    #[must_use]
    pub fn score_pct(&self) -> f64 {
        self.score * 100.0
    }

    #[must_use]
    pub fn improvement_over(&self, baseline: &Self) -> f64 {
        baseline.score - self.score
    }
}

// ---------------------------------------------------------------------------
// DeobfReport — top-level report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DeobfReport {
    pub binary_name: String,
    pub binary_hash_sha256: String,
    pub binary_size_bytes: u64,
    pub timestamp_unix: u64,
    pub total_duration_ms: u64,

    pub passes: Vec<PassSummary>,

    pub score_before: ObfScore,
    pub score_after: ObfScore,

    pub total_strings_recovered: u64,
    pub total_branches_simplified: u64,
    pub total_instructions_modified: u64,
    pub total_patches_applied: u64,
    pub total_bytes_removed: i64,

    pub global_notes: Vec<String>,
    pub warnings: Vec<String>,

    /// Aggregate transform stats across all passes
    pub aggregate_transforms: HashMap<String, u64>,
}

impl DeobfReport {
    #[must_use]
    pub fn new(binary_name: impl Into<String>, binary_size_bytes: u64) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        Self {
            binary_name: binary_name.into(),
            binary_hash_sha256: String::new(),
            binary_size_bytes,
            timestamp_unix: ts,
            total_duration_ms: 0,
            passes: Vec::new(),
            score_before: ObfScore::compute(5.0, 0.0, 0.0, 0, false, false),
            score_after: ObfScore::compute(5.0, 0.0, 0.0, 0, false, false),
            total_strings_recovered: 0,
            total_branches_simplified: 0,
            total_instructions_modified: 0,
            total_patches_applied: 0,
            total_bytes_removed: 0,
            global_notes: Vec::new(),
            warnings: Vec::new(),
            aggregate_transforms: HashMap::new(),
        }
    }

    pub fn set_hash(&mut self, sha256: impl Into<String>) {
        self.binary_hash_sha256 = sha256.into();
    }

    pub const fn set_scores(&mut self, before: ObfScore, after: ObfScore) {
        self.score_before = before;
        self.score_after = after;
    }

    pub fn add_pass(&mut self, summary: PassSummary) {
        self.total_duration_ms += summary.duration_ms;
        self.total_strings_recovered += summary.strings_recovered;
        self.total_branches_simplified += summary.branches_simplified;
        self.total_instructions_modified += summary.instructions_modified;
        self.total_patches_applied += summary.patches_applied;
        self.total_bytes_removed += -summary.bytes_delta();

        for t in &summary.transforms {
            *self.aggregate_transforms.entry(t.category.clone()).or_insert(0) += t.count;
        }

        self.passes.push(summary);
    }

    pub fn add_note(&mut self, note: impl Into<String>) {
        self.global_notes.push(note.into());
    }

    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    #[must_use]
    pub fn executed_passes(&self) -> Vec<&PassSummary> {
        self.passes.iter().filter(|p| p.executed).collect()
    }

    #[must_use]
    pub fn failed_passes(&self) -> Vec<&PassSummary> {
        self.passes.iter().filter(|p| p.executed && !p.succeeded).collect()
    }

    #[must_use]
    pub fn skipped_passes(&self) -> Vec<&PassSummary> {
        self.passes.iter().filter(|p| p.skipped).collect()
    }

    #[must_use]
    pub fn score_improvement(&self) -> f64 {
        self.score_after.improvement_over(&self.score_before)
    }

    #[must_use]
    pub fn export(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::PlainText => self.export_text(),
            ReportFormat::Json => self.export_json(),
            ReportFormat::Html => self.export_html(),
            ReportFormat::Csv => self.export_csv(),
            ReportFormat::Markdown => self.export_markdown(),
        }
    }

    // -------------------------------------------------------------------
    // Plain text export
    // -------------------------------------------------------------------

    fn export_text(&self) -> String {
        let mut out = String::new();
        out.push_str("=== DEOBFUSCATION REPORT ===\n");
        writeln!(out, "Binary : {}", self.binary_name).unwrap();
        if !self.binary_hash_sha256.is_empty() {
            writeln!(out, "SHA256 : {}", self.binary_hash_sha256).unwrap();
        }
        writeln!(out, "Size   : {} bytes", self.binary_size_bytes).unwrap();
        write!(out, "Time   : {} ms\n\n", self.total_duration_ms).unwrap();

        out.push_str("--- Obfuscation Scores ---\n");
        writeln!(out, "Before : {:.1}% ({})", self.score_before.score_pct(), self.score_before.label).unwrap();
        writeln!(out, "After  : {:.1}% ({})", self.score_after.score_pct(), self.score_after.label).unwrap();
        write!(out, "Improvement: {:.1}%\n\n", self.score_improvement() * 100.0).unwrap();

        out.push_str("--- Totals ---\n");
        writeln!(out, "Strings recovered    : {}", self.total_strings_recovered).unwrap();
        writeln!(out, "Branches simplified  : {}", self.total_branches_simplified).unwrap();
        writeln!(out, "Instructions modified: {}", self.total_instructions_modified).unwrap();
        writeln!(out, "Patches applied      : {}", self.total_patches_applied).unwrap();
        write!(out, "Bytes removed        : {}\n\n", self.total_bytes_removed).unwrap();

        out.push_str("--- Pass Results ---\n");
        for p in &self.passes {
            let status = if p.skipped {
                "SKIP"
            } else if p.succeeded {
                "OK  "
            } else {
                "FAIL"
            };
            writeln!(out, "[{}] {} ({} ms, {} transforms)", status, p.pass_name, p.duration_ms, p.total_transforms()).unwrap();
            if let Some(ref reason) = p.skip_reason {
                writeln!(out, "      Skipped: {reason}").unwrap();
            }
            if let Some(ref err) = p.error_message {
                writeln!(out, "      Error: {err}").unwrap();
            }
            for note in &p.notes {
                writeln!(out, "      Note: {note}").unwrap();
            }
        }

        if !self.warnings.is_empty() {
            out.push_str("\n--- Warnings ---\n");
            for w in &self.warnings {
                writeln!(out, "  ! {w}").unwrap();
            }
        }

        if !self.global_notes.is_empty() {
            out.push_str("\n--- Notes ---\n");
            for n in &self.global_notes {
                writeln!(out, "  * {n}").unwrap();
            }
        }

        out
    }

    // -------------------------------------------------------------------
    // JSON export (hand-rolled, no serde dependency)
    // -------------------------------------------------------------------

    fn export_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        writeln!(out, "  \"binary_name\": {},", json_str(&self.binary_name)).unwrap();
        writeln!(out, "  \"binary_hash_sha256\": {},", json_str(&self.binary_hash_sha256)).unwrap();
        writeln!(out, "  \"binary_size_bytes\": {},", self.binary_size_bytes).unwrap();
        writeln!(out, "  \"timestamp_unix\": {},", self.timestamp_unix).unwrap();
        writeln!(out, "  \"total_duration_ms\": {},", self.total_duration_ms).unwrap();
        writeln!(out, "  \"score_before\": {},", json_obf_score(&self.score_before)).unwrap();
        writeln!(out, "  \"score_after\": {},", json_obf_score(&self.score_after)).unwrap();
        writeln!(out, "  \"score_improvement\": {:.4},", self.score_improvement()).unwrap();
        writeln!(out, "  \"total_strings_recovered\": {},", self.total_strings_recovered).unwrap();
        writeln!(out, "  \"total_branches_simplified\": {},", self.total_branches_simplified).unwrap();
        writeln!(out, "  \"total_instructions_modified\": {},", self.total_instructions_modified).unwrap();
        writeln!(out, "  \"total_patches_applied\": {},", self.total_patches_applied).unwrap();
        writeln!(out, "  \"total_bytes_removed\": {},", self.total_bytes_removed).unwrap();

        out.push_str("  \"passes\": [\n");
        for (i, p) in self.passes.iter().enumerate() {
            out.push_str(&json_pass_summary(p, 4));
            if i + 1 < self.passes.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ],\n");

        out.push_str("  \"warnings\": [");
        let w_parts: Vec<String> = self.warnings.iter().map(|w| json_str(w)).collect();
        out.push_str(&w_parts.join(", "));
        out.push_str("],\n");

        out.push_str("  \"global_notes\": [");
        let n_parts: Vec<String> = self.global_notes.iter().map(|n| json_str(n)).collect();
        out.push_str(&n_parts.join(", "));
        out.push_str("]\n");

        out.push('}');
        out
    }

    // -------------------------------------------------------------------
    // HTML export
    // -------------------------------------------------------------------

    fn export_html(&self) -> String {
        let mut out = String::new();
        out.push_str("<!DOCTYPE html><html><head><meta charset='utf-8'>");
        out.push_str("<title>Deobfuscation Report</title>");
        out.push_str("<style>");
        out.push_str("body{{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:20px}}");
        out.push_str("h1,h2{{color:#9cdcfe}}table{{border-collapse:collapse;width:100%}}");
        out.push_str("th{{background:#2d2d2d;color:#ce9178;padding:6px}}");
        out.push_str("td{{padding:5px;border-bottom:1px solid #333}}");
        out.push_str(".ok{{color:#4ec9b0}}.fail{{color:#f44747}}.skip{{color:#888}}");
        out.push_str(".score-bar{{height:12px;background:#264f78;border-radius:4px}}");
        out.push_str(".score-fill{{height:12px;background:#4ec9b0;border-radius:4px}}");
        out.push_str("</style></head><body>");

        write!(out, "<h1>Deobfuscation Report: {}</h1>", html_esc(&self.binary_name)).unwrap();

        out.push_str("<h2>Overview</h2><table>");
        let rows = [
            ("Binary", html_esc(&self.binary_name)),
            ("SHA256", html_esc(&self.binary_hash_sha256)),
            ("Size", format!("{} bytes", self.binary_size_bytes)),
            ("Duration", format!("{} ms", self.total_duration_ms)),
            ("Strings Recovered", self.total_strings_recovered.to_string()),
            ("Branches Simplified", self.total_branches_simplified.to_string()),
            ("Instructions Modified", self.total_instructions_modified.to_string()),
            ("Patches Applied", self.total_patches_applied.to_string()),
        ];
        for (k, v) in &rows {
            write!(out, "<tr><th>{k}</th><td>{v}</td></tr>").unwrap();
        }
        out.push_str("</table>");

        out.push_str("<h2>Obfuscation Score</h2>");
        let before_pct = self.score_before.score_pct().clamp(0.0, 100.0);
        let after_pct = self.score_after.score_pct().clamp(0.0, 100.0);
        write!(out,
            "<p>Before: {:.1}% ({}) \u{2192} After: {:.1}% ({})</p>",
            self.score_before.score_pct(),
            self.score_before.label,
            self.score_after.score_pct(),
            self.score_after.label
        ).unwrap();
        write!(out, "<div class='score-bar'><div class='score-fill' style='width:{before_pct:.0}%'></div></div>").unwrap();
        write!(out, "<div class='score-bar'><div class='score-fill' style='width:{after_pct:.0}%'></div></div>").unwrap();

        out.push_str("<h2>Pass Results</h2><table>");
        out.push_str("<tr><th>Pass</th><th>Status</th><th>Duration</th><th>Transforms</th><th>Strings</th><th>Branches</th><th>Notes</th></tr>");
        for p in &self.passes {
            let (cls, status) = if p.skipped {
                ("skip", "SKIPPED")
            } else if p.succeeded {
                ("ok", "OK")
            } else {
                ("fail", "FAILED")
            };
            write!(out,
                "<tr><td>{}</td><td class='{cls}'>{status}</td><td>{} ms</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(&p.pass_name),
                p.duration_ms,
                p.total_transforms(),
                p.strings_recovered,
                p.branches_simplified,
                p.notes.join("; ")
            ).unwrap();
        }
        out.push_str("</table>");

        if !self.warnings.is_empty() {
            out.push_str("<h2>Warnings</h2><ul>");
            for w in &self.warnings {
                write!(out, "<li class='fail'>{}</li>", html_esc(w)).unwrap();
            }
            out.push_str("</ul>");
        }

        out.push_str("</body></html>");
        out
    }

    // -------------------------------------------------------------------
    // CSV export
    // -------------------------------------------------------------------

    fn export_csv(&self) -> String {
        let mut out = String::new();
        out.push_str("pass_id,pass_name,status,duration_ms,bytes_in,bytes_out,transforms,strings_recovered,branches_simplified,instructions_modified,patches_applied\n");
        for p in &self.passes {
            let status = if p.skipped {
                "skipped"
            } else if p.succeeded {
                "ok"
            } else {
                "failed"
            };
            writeln!(out,
                "{},{},{},{},{},{},{},{},{},{},{}",
                csv_esc(&p.pass_id),
                csv_esc(&p.pass_name),
                status,
                p.duration_ms,
                p.bytes_in,
                p.bytes_out,
                p.total_transforms(),
                p.strings_recovered,
                p.branches_simplified,
                p.instructions_modified,
                p.patches_applied,
            ).unwrap();
        }
        out
    }

    // -------------------------------------------------------------------
    // Markdown export
    // -------------------------------------------------------------------

    fn export_markdown(&self) -> String {
        let mut out = String::new();
        write!(out, "# Deobfuscation Report: {}\n\n", self.binary_name).unwrap();

        out.push_str("## Overview\n\n");
        out.push_str("| Field | Value |\n|---|---|\n");
        writeln!(out, "| Binary | `{}` |", self.binary_name).unwrap();
        writeln!(out, "| Size | {} bytes |", self.binary_size_bytes).unwrap();
        writeln!(out, "| Duration | {} ms |", self.total_duration_ms).unwrap();
        writeln!(out, "| Strings Recovered | {} |", self.total_strings_recovered).unwrap();
        writeln!(out, "| Branches Simplified | {} |", self.total_branches_simplified).unwrap();
        writeln!(out, "| Instructions Modified | {} |", self.total_instructions_modified).unwrap();
        write!(out, "| Patches Applied | {} |\n\n", self.total_patches_applied).unwrap();

        out.push_str("## Obfuscation Score\n\n");
        writeln!(out, "- **Before**: {:.1}% \u{2014} {}", self.score_before.score_pct(), self.score_before.label).unwrap();
        writeln!(out, "- **After**: {:.1}% \u{2014} {}", self.score_after.score_pct(), self.score_after.label).unwrap();
        write!(out, "- **Improvement**: {:.1}%\n\n", self.score_improvement() * 100.0).unwrap();

        out.push_str("## Pass Results\n\n");
        out.push_str("| Pass | Status | Duration | Transforms | Strings | Branches |\n");
        out.push_str("|---|---|---|---|---|---|\n");
        for p in &self.passes {
            let status = if p.skipped {
                "\u{23ed} SKIPPED"
            } else if p.succeeded {
                "\u{2705} OK"
            } else {
                "\u{274c} FAILED"
            };
            writeln!(out,
                "| `{}` | {} | {} ms | {} | {} | {} |",
                p.pass_name,
                status,
                p.duration_ms,
                p.total_transforms(),
                p.strings_recovered,
                p.branches_simplified,
            ).unwrap();
        }

        if !self.warnings.is_empty() {
            out.push_str("\n## Warnings\n\n");
            for w in &self.warnings {
                writeln!(out, "- \u{26a0}\u{fe0f} {w}").unwrap();
            }
        }

        if !self.global_notes.is_empty() {
            out.push_str("\n## Notes\n\n");
            for n in &self.global_notes {
                writeln!(out, "- {n}").unwrap();
            }
        }

        out
    }
}

// ---------------------------------------------------------------------------
// ReportBuilder — fluent API
// ---------------------------------------------------------------------------

pub struct ReportBuilder {
    report: DeobfReport,
}

impl ReportBuilder {
    #[must_use]
    pub fn new(binary_name: impl Into<String>, binary_size_bytes: u64) -> Self {
        Self {
            report: DeobfReport::new(binary_name, binary_size_bytes),
        }
    }

    #[must_use]
    pub fn hash(mut self, sha256: impl Into<String>) -> Self {
        self.report.set_hash(sha256);
        self
    }

    #[must_use]
    pub const fn scores(mut self, before: ObfScore, after: ObfScore) -> Self {
        self.report.set_scores(before, after);
        self
    }

    #[must_use]
    pub fn pass(mut self, summary: PassSummary) -> Self {
        self.report.add_pass(summary);
        self
    }

    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.report.add_note(note);
        self
    }

    #[must_use]
    pub fn warning(mut self, warning: impl Into<String>) -> Self {
        self.report.add_warning(warning);
        self
    }

    #[must_use]
    pub fn build(self) -> DeobfReport {
        self.report
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_obf_score(s: &ObfScore) -> String {
    format!(
        "{{\"score\":{:.4},\"entropy\":{:.4},\"control_flow\":{:.4},\"string_obf\":{:.4},\"anti_analysis\":{:.4},\"packing\":{:.4},\"label\":\"{}\"}}",
        s.score,
        s.entropy_component,
        s.control_flow_component,
        s.string_obfuscation_component,
        s.anti_analysis_component,
        s.packing_component,
        s.label
    )
}

fn json_pass_summary(p: &PassSummary, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = format!("{pad}{{\n");
    writeln!(out, "{pad}  \"pass_id\": {},", json_str(&p.pass_id)).unwrap();
    writeln!(out, "{pad}  \"pass_name\": {},", json_str(&p.pass_name)).unwrap();
    writeln!(out, "{pad}  \"executed\": {},", p.executed).unwrap();
    writeln!(out, "{pad}  \"succeeded\": {},", p.succeeded).unwrap();
    writeln!(out, "{pad}  \"skipped\": {},", p.skipped).unwrap();
    writeln!(out, "{pad}  \"duration_ms\": {},", p.duration_ms).unwrap();
    writeln!(out, "{pad}  \"bytes_in\": {},", p.bytes_in).unwrap();
    writeln!(out, "{pad}  \"bytes_out\": {},", p.bytes_out).unwrap();
    writeln!(out, "{pad}  \"strings_recovered\": {},", p.strings_recovered).unwrap();
    writeln!(out, "{pad}  \"branches_simplified\": {},", p.branches_simplified).unwrap();
    writeln!(out, "{pad}  \"instructions_modified\": {},", p.instructions_modified).unwrap();
    writeln!(out, "{pad}  \"patches_applied\": {},", p.patches_applied).unwrap();
    writeln!(out, "{pad}  \"total_transforms\": {}", p.total_transforms()).unwrap();
    write!(out, "{pad}}}").unwrap();
    out
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn csv_esc(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Aggregate statistics helper
// ---------------------------------------------------------------------------

pub struct ReportAggregator {
    reports: Vec<DeobfReport>,
}

impl ReportAggregator {
    #[must_use]
    pub const fn new() -> Self {
        Self { reports: Vec::new() }
    }

    pub fn add(&mut self, report: DeobfReport) {
        self.reports.push(report);
    }

    #[must_use]
    pub fn total_strings_recovered(&self) -> u64 {
        self.reports.iter().map(|r| r.total_strings_recovered).sum()
    }

    #[must_use]
    pub fn total_instructions_modified(&self) -> u64 {
        self.reports.iter().map(|r| r.total_instructions_modified).sum()
    }

    #[must_use]
    pub fn average_score_improvement(&self) -> f64 {
        if self.reports.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.reports.iter().map(DeobfReport::score_improvement).sum();
        sum / f64::from(u32::try_from(self.reports.len()).unwrap_or(u32::MAX))
    }

    #[must_use]
    pub fn most_effective_pass(&self) -> Option<String> {
        let mut counts: HashMap<String, u64> = HashMap::new();
        for r in &self.reports {
            for p in &r.passes {
                if p.succeeded {
                    *counts.entry(p.pass_name.clone()).or_insert(0) += p.total_transforms();
                }
            }
        }
        counts.into_iter().max_by_key(|(_, v)| *v).map(|(k, _)| k)
    }

    #[must_use]
    pub fn summary_text(&self) -> String {
        format!(
            "Aggregated {} reports: {} strings recovered, {} instructions modified, avg improvement {:.1}%",
            self.reports.len(),
            self.total_strings_recovered(),
            self.total_instructions_modified(),
            self.average_score_improvement() * 100.0
        )
    }
}

impl Default for ReportAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pass(name: &str, succeeded: bool) -> PassSummary {
        let mut p = PassSummary::new(name, name);
        p.mark_executed(succeeded, 100, 1024, 1000);
        p.strings_recovered = 5;
        p.branches_simplified = 2;
        p.instructions_modified = 10;
        p.patches_applied = 3;
        let mut stat = TransformStat::new("xor", "XOR decryption");
        stat.add(5, 50);
        p.add_transform(stat);
        p
    }

    #[test]
    fn test_pass_summary() {
        let p = make_pass("xor-decrypt", true);
        assert_eq!(p.total_transforms(), 5);
        assert_eq!(p.bytes_delta(), -24);
    }

    #[test]
    fn test_obf_score() {
        let s = ObfScore::compute(7.5, 80.0, 0.9, 5, false, false);
        assert!(s.score > 0.5);
        assert_eq!(s.label, ObfLabel::HeavyObfuscation);
    }

    #[test]
    fn test_obf_score_packed() {
        let s = ObfScore::compute(7.8, 10.0, 0.1, 0, true, false);
        assert_eq!(s.label, ObfLabel::Packed);
    }

    #[test]
    fn test_report_totals() {
        let mut report = DeobfReport::new("test.exe", 65536);
        report.add_pass(make_pass("pass1", true));
        report.add_pass(make_pass("pass2", true));
        assert_eq!(report.total_strings_recovered, 10);
        assert_eq!(report.total_branches_simplified, 4);
        assert_eq!(report.total_duration_ms, 200);
    }

    #[test]
    fn test_export_text() {
        let mut report = DeobfReport::new("sample.exe", 4096);
        report.add_pass(make_pass("xor-decrypt", true));
        let txt = report.export(ReportFormat::PlainText);
        assert!(txt.contains("DEOBFUSCATION REPORT"));
        assert!(txt.contains("xor-decrypt"));
        assert!(txt.contains("OK"));
    }

    #[test]
    fn test_export_json() {
        let mut report = DeobfReport::new("sample.exe", 4096);
        report.add_pass(make_pass("xor-decrypt", true));
        let json = report.export(ReportFormat::Json);
        assert!(json.contains("\"binary_name\""));
        assert!(json.contains("xor-decrypt"));
    }

    #[test]
    fn test_export_html() {
        let mut report = DeobfReport::new("sample.exe", 4096);
        report.add_pass(make_pass("xor-decrypt", true));
        let html = report.export(ReportFormat::Html);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("xor-decrypt"));
    }

    #[test]
    fn test_export_csv() {
        let mut report = DeobfReport::new("sample.exe", 4096);
        report.add_pass(make_pass("xor-decrypt", true));
        let csv = report.export(ReportFormat::Csv);
        assert!(csv.contains("pass_id,pass_name"));
        assert!(csv.contains("xor-decrypt"));
    }

    #[test]
    fn test_export_markdown() {
        let mut report = DeobfReport::new("sample.exe", 4096);
        report.add_pass(make_pass("xor-decrypt", true));
        let md = report.export(ReportFormat::Markdown);
        assert!(md.contains("# Deobfuscation Report"));
        assert!(md.contains("xor-decrypt"));
    }

    #[test]
    fn test_builder() {
        let before = ObfScore::compute(7.0, 60.0, 0.8, 3, false, false);
        let after = ObfScore::compute(4.0, 20.0, 0.1, 0, false, false);
        let report = ReportBuilder::new("test.exe", 8192)
            .hash("abc123")
            .scores(before, after)
            .pass(make_pass("pass1", true))
            .note("analyzed successfully")
            .warning("missing imports section")
            .build();
        assert_eq!(report.binary_hash_sha256, "abc123");
        assert!(!report.warnings.is_empty());
        assert!(report.score_improvement() > 0.0);
    }

    #[test]
    fn test_aggregator() {
        let mut agg = ReportAggregator::new();
        let mut r1 = DeobfReport::new("a.exe", 1024);
        r1.add_pass(make_pass("p1", true));
        let mut r2 = DeobfReport::new("b.exe", 2048);
        r2.add_pass(make_pass("p2", true));
        agg.add(r1);
        agg.add(r2);
        assert_eq!(agg.total_strings_recovered(), 10);
        let summary = agg.summary_text();
        assert!(summary.contains("2 reports"));
    }

    #[test]
    fn test_skipped_pass() {
        let mut p = PassSummary::new("nop-remove", "NOP Remover");
        p.mark_skipped("not applicable to this binary");
        let mut report = DeobfReport::new("test.exe", 512);
        report.add_pass(p);
        assert_eq!(report.skipped_passes().len(), 1);
        assert_eq!(report.executed_passes().len(), 0);
    }

    #[test]
    fn test_failed_pass() {
        let mut p = PassSummary::new("upx-unpack", "UPX Unpacker");
        p.mark_executed(false, 50, 4096, 0);
        p.error_message = Some("invalid UPX stub".to_string());
        let mut report = DeobfReport::new("test.exe", 4096);
        report.add_pass(p);
        assert_eq!(report.failed_passes().len(), 1);
    }
}
