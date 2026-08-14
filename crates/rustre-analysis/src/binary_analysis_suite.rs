//! `binary_analysis_suite` — Coordinating suite that runs 10+ analysis passes
//! in a configurable pipeline, aggregating findings into a `SuiteReport`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ────────────────────────────────────────────────────────────────────

/// Errors produced by the analysis suite.
#[derive(Debug, Error)]
pub enum SuiteError {
    #[error("phase {0} failed: {1}")]
    PhaseFailed(String, String),
    #[error("inter-pass data missing key '{0}'")]
    MissingInterPassData(String),
    #[error("configuration invalid: {0}")]
    ConfigInvalid(String),
    #[error("timeout after {0}ms")]
    Timeout(u64),
    #[error("pipeline aborted: {0}")]
    Aborted(String),
}

// ─── AnalysisPhase ──────────────────────────────────────────────────────────────

/// Execution phase within the analysis pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AnalysisPhase {
    /// Initial format detection and mapping.
    Discovery,
    /// Type recovery and data classification.
    Typing,
    /// Control-flow graph construction.
    ControlFlow,
    /// Data-flow / def-use chain analysis.
    DataFlow,
    /// Taint propagation.
    Taint,
    /// Symbolic execution.
    Symbolic,
    /// Cross-reference recovery.
    CrossRef,
    /// String recovery.
    StringRecovery,
    /// Signature matching (FLIRT, pattern libraries).
    SignatureMatch,
    /// Vulnerability scanning pass.
    VulnScan,
    /// Reporting / post-processing.
    Reporting,
}

impl AnalysisPhase {
    /// Human-readable name for this phase.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Typing => "typing",
            Self::ControlFlow => "control_flow",
            Self::DataFlow => "data_flow",
            Self::Taint => "taint",
            Self::Symbolic => "symbolic",
            Self::CrossRef => "cross_ref",
            Self::StringRecovery => "string_recovery",
            Self::SignatureMatch => "signature_match",
            Self::VulnScan => "vuln_scan",
            Self::Reporting => "reporting",
        }
    }

    /// All phases in execution order.
    #[must_use]
    pub const fn ordered() -> &'static [Self] {
        &[
            Self::Discovery,
            Self::Typing,
            Self::ControlFlow,
            Self::DataFlow,
            Self::Taint,
            Self::Symbolic,
            Self::CrossRef,
            Self::StringRecovery,
            Self::SignatureMatch,
            Self::VulnScan,
            Self::Reporting,
        ]
    }
}

impl std::fmt::Display for AnalysisPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ─── SuiteConfig ──────────────────────────────────────────────────────────────

/// Configuration for the `BinaryAnalysisSuite`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteConfig {
    /// Phases to execute (in order). Defaults to all phases.
    pub phases: Vec<AnalysisPhase>,
    /// Per-phase timeout in milliseconds (0 = unlimited).
    pub phase_timeout_ms: u64,
    /// Overall pipeline timeout in milliseconds (0 = unlimited).
    pub total_timeout_ms: u64,
    /// Whether to abort the pipeline on the first phase failure.
    pub abort_on_error: bool,
    /// Maximum call depth for recursive passes.
    pub max_depth: usize,
    /// Maximum number of findings per phase.
    pub max_findings_per_phase: usize,
    /// Extra key-value configuration for individual passes.
    pub extra: HashMap<String, String>,
}

impl Default for SuiteConfig {
    fn default() -> Self {
        Self {
            phases: AnalysisPhase::ordered().to_vec(),
            phase_timeout_ms: 30_000,
            total_timeout_ms: 0,
            abort_on_error: false,
            max_depth: 256,
            max_findings_per_phase: 10_000,
            extra: HashMap::new(),
        }
    }
}

impl SuiteConfig {
    /// Create a configuration that only runs the specified phases.
    #[must_use]
    pub fn for_phases(phases: Vec<AnalysisPhase>) -> Self {
        Self { phases, ..Default::default() }
    }

    /// Create a fast, shallow configuration (discovery + control-flow only).
    #[must_use]
    pub fn fast() -> Self {
        Self::for_phases(vec![
            AnalysisPhase::Discovery,
            AnalysisPhase::ControlFlow,
            AnalysisPhase::StringRecovery,
        ])
    }

    /// Validate the configuration for internal consistency.
    ///
    /// # Errors
    /// Returns `SuiteError::ConfigInvalid` if the configuration is malformed.
    pub fn validate(&self) -> Result<(), SuiteError> {
        if self.phases.is_empty() {
            return Err(SuiteError::ConfigInvalid("no phases configured".into()));
        }
        if self.max_depth == 0 {
            return Err(SuiteError::ConfigInvalid("max_depth must be > 0".into()));
        }
        Ok(())
    }

    /// Return the value for an extra key, or `None`.
    #[must_use]
    pub fn get_extra(&self, key: &str) -> Option<&str> {
        self.extra.get(key).map(String::as_str)
    }
}

// ─── Finding ──────────────────────────────────────────────────────────────────

/// Severity of an analysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// A single finding produced by an analysis pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Human-readable title.
    pub title: String,
    /// Detailed description.
    pub description: String,
    /// Severity level.
    pub severity: FindingSeverity,
    /// Phase that produced this finding.
    pub phase: AnalysisPhase,
    /// Optional virtual address associated with the finding.
    pub address: Option<u64>,
    /// Optional function name context.
    pub function: Option<String>,
    /// Confidence score 0–100.
    pub confidence: u8,
    /// Arbitrary metadata.
    pub tags: Vec<String>,
}

impl Finding {
    /// Create a new finding.
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: FindingSeverity,
        phase: AnalysisPhase,
    ) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            severity,
            phase,
            address: None,
            function: None,
            confidence: 80,
            tags: vec![],
        }
    }

    /// Builder: set the address.
    #[must_use]
    pub const fn at_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Builder: set the function name.
    #[must_use]
    pub fn in_function(mut self, func: impl Into<String>) -> Self {
        self.function = Some(func.into());
        self
    }

    /// Builder: set the confidence.
    #[must_use]
    pub const fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }

    /// Builder: add a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Return `true` if the finding is considered high severity.
    #[must_use]
    pub fn is_high_severity(&self) -> bool {
        self.severity >= FindingSeverity::High
    }
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}][{}] {}",
            self.severity, self.phase, self.title
        )
    }
}

// ─── InterPassData ────────────────────────────────────────────────────────────

/// Shared mutable state passed between analysis phases.
///
/// Each phase can read from and write to the map. Keys use a
/// `"phase/key"` convention (e.g. `"discovery/functions"`) to avoid conflicts.
#[derive(Debug, Default, Clone)]
pub struct InterPassData {
    data: HashMap<String, Vec<u8>>,
    counters: HashMap<String, u64>,
}

impl InterPassData {
    /// Create an empty `InterPassData`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store raw bytes under a key.
    pub fn set(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.data.insert(key.into(), value);
    }

    /// Store a JSON-serialisable value.
    ///
    /// # Errors
    /// Returns `SuiteError::PhaseFailed` if serialisation fails.
    pub fn set_json<T: serde::Serialize>(
        &mut self,
        key: impl Into<String>,
        value: &T,
    ) -> Result<(), SuiteError> {
        let bytes = serde_json::to_vec(value).map_err(|e| {
            SuiteError::PhaseFailed("serialize".into(), e.to_string())
        })?;
        self.set(key, bytes);
        Ok(())
    }

    /// Retrieve raw bytes by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.data.get(key).map(Vec::as_slice)
    }

    /// Retrieve and deserialise a JSON value.
    ///
    /// # Errors
    /// Returns `SuiteError::MissingInterPassData` if the key is absent,
    /// or `SuiteError::PhaseFailed` on deserialisation failure.
    pub fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T, SuiteError> {
        let bytes = self
            .data
            .get(key)
            .ok_or_else(|| SuiteError::MissingInterPassData(key.to_string()))?;
        serde_json::from_slice(bytes)
            .map_err(|e| SuiteError::PhaseFailed("deserialize".into(), e.to_string()))
    }

    /// Increment a named counter and return the new value.
    pub fn increment(&mut self, key: impl Into<String>) -> u64 {
        let entry = self.counters.entry(key.into()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Read a counter.
    #[must_use]
    pub fn counter(&self, key: &str) -> u64 {
        self.counters.get(key).copied().unwrap_or(0)
    }

    /// Return `true` if the key is present.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Number of keys stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if no data has been stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ─── PhaseResult ──────────────────────────────────────────────────────────────

/// Result of a single analysis phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    /// Which phase this result is from.
    pub phase: AnalysisPhase,
    /// Whether the phase completed without errors.
    pub success: bool,
    /// Wall-clock time taken.
    pub duration_ms: u64,
    /// Findings produced by this phase.
    pub findings: Vec<Finding>,
    /// Metrics gathered (arbitrary key → value).
    pub metrics: HashMap<String, u64>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Error message if `!success`.
    pub error: Option<String>,
}

impl PhaseResult {
    /// Create a successful phase result.
    #[must_use]
    pub fn success(phase: AnalysisPhase, duration_ms: u64) -> Self {
        Self {
            phase,
            success: true,
            duration_ms,
            findings: vec![],
            metrics: HashMap::new(),
            warnings: vec![],
            error: None,
        }
    }

    /// Create a failed phase result.
    #[must_use]
    pub fn failure(phase: AnalysisPhase, duration_ms: u64, error: String) -> Self {
        Self {
            phase,
            success: false,
            duration_ms,
            findings: vec![],
            metrics: HashMap::new(),
            warnings: vec![],
            error: Some(error),
        }
    }

    /// Add a finding to this result.
    pub fn add_finding(&mut self, f: Finding) {
        self.findings.push(f);
    }

    /// Record a metric.
    pub fn record_metric(&mut self, key: impl Into<String>, value: u64) {
        self.metrics.insert(key.into(), value);
    }

    /// Number of findings.
    #[must_use]
    pub const fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Number of high-severity findings.
    #[must_use]
    pub fn high_severity_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.is_high_severity())
            .count()
    }
}

// ─── SuiteReport ──────────────────────────────────────────────────────────────

/// Aggregated report from the entire analysis suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteReport {
    /// Path / URI of the analysed binary.
    pub binary_uri: String,
    /// Configuration used.
    pub config: SuiteConfig,
    /// Per-phase results.
    pub phase_results: Vec<PhaseResult>,
    /// All findings merged across all phases.
    pub all_findings: Vec<Finding>,
    /// Total wall-clock time.
    pub total_duration_ms: u64,
    /// Whether all phases succeeded.
    pub all_succeeded: bool,
    /// Summary statistics.
    pub stats: SuiteStats,
}

/// Summary statistics for a `SuiteReport`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuiteStats {
    pub functions_found: usize,
    pub strings_found: usize,
    pub xrefs_found: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub phases_run: usize,
    pub phases_succeeded: usize,
    pub phases_failed: usize,
}

impl SuiteStats {
    /// Compute stats from a slice of phase results.
    #[must_use]
    pub fn compute(results: &[PhaseResult]) -> Self {
        let mut s = Self { phases_run: results.len(), ..Default::default() };
        for r in results {
            if r.success {
                s.phases_succeeded += 1;
            } else {
                s.phases_failed += 1;
            }
            s.functions_found += usize::try_from(r.metrics.get("functions_found").copied().unwrap_or(0)).unwrap_or(usize::MAX);
            s.strings_found += usize::try_from(r.metrics.get("strings_found").copied().unwrap_or(0)).unwrap_or(usize::MAX);
            s.xrefs_found += usize::try_from(r.metrics.get("xrefs_found").copied().unwrap_or(0)).unwrap_or(usize::MAX);
            for f in &r.findings {
                s.total_findings += 1;
                match f.severity {
                    FindingSeverity::Critical => s.critical_findings += 1,
                    FindingSeverity::High => s.high_findings += 1,
                    FindingSeverity::Medium => s.medium_findings += 1,
                    FindingSeverity::Low => s.low_findings += 1,
                    FindingSeverity::Info => s.info_findings += 1,
                }
            }
        }
        s
    }
}

impl SuiteReport {
    /// Build a report from phase results.
    #[must_use]
    pub fn build(
        binary_uri: impl Into<String>,
        config: SuiteConfig,
        phase_results: Vec<PhaseResult>,
        total_duration_ms: u64,
    ) -> Self {
        let all_succeeded = phase_results.iter().all(|r| r.success);
        let all_findings: Vec<Finding> = phase_results
            .iter()
            .flat_map(|r| r.findings.iter().cloned())
            .collect();
        let stats = SuiteStats::compute(&phase_results);
        Self {
            binary_uri: binary_uri.into(),
            config,
            phase_results,
            all_findings,
            total_duration_ms,
            all_succeeded,
            stats,
        }
    }

    /// Return findings with severity >= `min_severity`.
    #[must_use]
    pub fn findings_above(&self, min_severity: FindingSeverity) -> Vec<&Finding> {
        self.all_findings
            .iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }

    /// Return all critical findings.
    #[must_use]
    pub fn critical_findings(&self) -> Vec<&Finding> {
        self.findings_above(FindingSeverity::Critical)
    }

    /// Return findings for a specific phase.
    #[must_use]
    pub fn findings_for_phase(&self, phase: AnalysisPhase) -> Vec<&Finding> {
        self.all_findings
            .iter()
            .filter(|f| f.phase == phase)
            .collect()
    }

    /// Serialise the report to pretty-printed JSON.
    ///
    /// # Errors
    /// Returns an error string if serialisation fails.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// One-line summary of this report.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "binary={} phases={}/{} findings={} (critical={} high={}) time={}ms",
            self.binary_uri,
            self.stats.phases_succeeded,
            self.stats.phases_run,
            self.stats.total_findings,
            self.stats.critical_findings,
            self.stats.high_findings,
            self.total_duration_ms,
        )
    }
}

// ─── ProgressCallback ────────────────────────────────────────────────────────

/// Progress notification sent to the caller during analysis.
#[derive(Debug, Clone)]
pub struct ProgressEvent {
    /// The phase that just started or finished.
    pub phase: AnalysisPhase,
    /// How many phases have been completed so far.
    pub phases_completed: usize,
    /// Total number of phases to run.
    pub phases_total: usize,
    /// Whether the phase succeeded (`None` = just started).
    pub succeeded: Option<bool>,
    /// Duration of the phase if it just completed.
    pub duration_ms: Option<u64>,
}

impl ProgressEvent {
    /// Completion percentage in [0, 100].
    #[must_use]
    pub fn percent(&self) -> u8 {
        if self.phases_total == 0 {
            return 100;
        }
        let completed = u32::try_from(self.phases_completed).unwrap_or(u32::MAX);
        let total = u32::try_from(self.phases_total).unwrap_or(1);
        u8::try_from((completed * 100 / total).min(100)).unwrap_or(100)
    }
}

/// Callback type for receiving progress events.
pub type ProgressCallback = Arc<dyn Fn(ProgressEvent) + Send + Sync>;

// ─── AnalysisPassFn ───────────────────────────────────────────────────────────

/// A single analysis pass function: takes a binary blob, a config reference,
/// and a mutable `InterPassData`, and returns a `PhaseResult`.
pub type AnalysisPassFn = Arc<
    dyn Fn(&[u8], &SuiteConfig, &mut InterPassData) -> PhaseResult + Send + Sync,
>;

// ─── SuitePipeline ─────────────────────────────────────────────────────────

/// A sequence of named passes that are invoked in order.
pub struct SuitePipeline {
    passes: Vec<(AnalysisPhase, AnalysisPassFn)>,
}

impl SuitePipeline {
    /// Create a new empty pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self { passes: vec![] }
    }

    /// Register a pass for a specific phase.
    pub fn register(&mut self, phase: AnalysisPhase, pass: AnalysisPassFn) {
        self.passes.push((phase, pass));
    }

    /// Return the number of registered passes.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Execute all passes for phases in `config.phases`, in order.
    ///
    /// Passes whose phase is not in `config.phases` are skipped.
    #[must_use]
    pub fn execute(
        &self,
        data: &[u8],
        config: &SuiteConfig,
        inter_pass: &mut InterPassData,
        callback: Option<&ProgressCallback>,
    ) -> Vec<PhaseResult> {
        let total = config.phases.len();
        let mut results = Vec::with_capacity(total);

        for (idx, phase) in config.phases.iter().enumerate() {
            // Find the pass for this phase, if registered.
            let pass_opt = self.passes.iter().find(|(p, _)| p == phase);

            let t0 = Instant::now();

            if let Some(callback) = callback.as_ref() {
                callback(ProgressEvent {
                    phase: *phase,
                    phases_completed: idx,
                    phases_total: total,
                    succeeded: None,
                    duration_ms: None,
                });
            }

            let result = if let Some((_, pass_fn)) = pass_opt {
                let mut r = pass_fn(data, config, inter_pass);
                let elapsed = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                r.duration_ms = elapsed;
                // Enforce the per-phase findings cap so that a runaway pass
                // cannot exhaust memory by accumulating unbounded findings
                // (dos-memory-exhaustion: untrusted input controls finding count).
                if r.findings.len() > config.max_findings_per_phase {
                    r.findings.truncate(config.max_findings_per_phase);
                    r.warnings.push(format!(
                        "findings truncated to {} (max_findings_per_phase limit)",
                        config.max_findings_per_phase
                    ));
                }
                r
            } else {
                // No pass registered for this phase — emit an empty success.
                PhaseResult::success(*phase, t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX))
            };

            let succeeded = result.success;
            let duration_ms = result.duration_ms;

            if let Some(callback) = callback.as_ref() {
                callback(ProgressEvent {
                    phase: *phase,
                    phases_completed: idx + 1,
                    phases_total: total,
                    succeeded: Some(succeeded),
                    duration_ms: Some(duration_ms),
                });
            }

            let should_abort = !succeeded && config.abort_on_error;
            results.push(result);

            if should_abort {
                break;
            }
        }

        results
    }
}

impl Default for SuitePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SuitePipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SuitePipeline({} passes)", self.passes.len())
    }
}

// ─── BinaryAnalysisSuite ─────────────────────────────────────────────────────

/// Top-level coordinator that runs 10+ analysis passes over a binary blob
/// and produces a `SuiteReport`.
pub struct BinaryAnalysisSuite {
    config: SuiteConfig,
    pipeline: SuitePipeline,
    progress: Option<ProgressCallback>,
}

impl BinaryAnalysisSuite {
    /// Create a suite with the given config and a default set of built-in passes.
    #[must_use]
    pub fn new(config: SuiteConfig) -> Self {
        let mut suite = Self {
            config,
            pipeline: SuitePipeline::new(),
            progress: None,
        };
        suite.register_builtin_passes();
        suite
    }

    /// Create a suite with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SuiteConfig::default())
    }

    /// Attach a progress callback.
    #[must_use]
    pub fn with_progress(mut self, cb: ProgressCallback) -> Self {
        self.progress = Some(cb);
        self
    }

    /// Override the pipeline with a custom one.
    #[must_use]
    pub fn with_pipeline(mut self, pipeline: SuitePipeline) -> Self {
        self.pipeline = pipeline;
        self
    }

    /// Validate the suite configuration.
    ///
    /// # Errors
    /// Returns `SuiteError::ConfigInvalid` if the configuration is malformed.
    pub fn validate(&self) -> Result<(), SuiteError> {
        self.config.validate()
    }

    /// Run the analysis suite on the provided binary data.
    ///
    /// # Errors
    /// Returns `SuiteError::ConfigInvalid` if the config is invalid.
    pub fn run(&self, binary_uri: &str, data: &[u8]) -> Result<SuiteReport, SuiteError> {
        self.config.validate()?;

        let t0 = Instant::now();
        let mut inter_pass = InterPassData::new();

        let phase_results = self.pipeline.execute(
            data,
            &self.config,
            &mut inter_pass,
            self.progress.as_ref(),
        );

        let total_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        Ok(SuiteReport::build(
            binary_uri,
            self.config.clone(),
            phase_results,
            total_ms,
        ))
    }

    // ── Internal pass registration ────────────────────────────────────────────

    fn register_builtin_passes(&mut self) {
        self.register_core_passes();
        self.register_scan_passes();
        self.register_report_passes();
    }

    fn register_core_passes(&mut self) {
        // Discovery pass
        self.pipeline.register(
            AnalysisPhase::Discovery,
            Arc::new(|data, _config, _ip| {
                let t0 = Instant::now();
                let mut result = PhaseResult::success(
                    AnalysisPhase::Discovery,
                    0,
                );
                // Detect format from magic bytes
                let format = if data.starts_with(b"\x7fELF") {
                    "ELF"
                } else if data.starts_with(b"MZ") {
                    "PE"
                } else if data.len() >= 4
                    && (data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
                        || data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]))
                {
                    "MachO"
                } else {
                    "Unknown"
                };
                result.record_metric("file_size", data.len() as u64);
                result.record_metric("format_detected", 1);
                if format != "Unknown" {
                    result.add_finding(Finding::new(
                        format!("Format detected: {format}"),
                        format!("Binary format identified as {format}"),
                        FindingSeverity::Info,
                        AnalysisPhase::Discovery,
                    ));
                }
                result.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                result
            }),
        );

        // Typing pass
        self.pipeline.register(
            AnalysisPhase::Typing,
            Arc::new(|data, _config, _ip| {
                let t0 = Instant::now();
                let mut result = PhaseResult::success(AnalysisPhase::Typing, 0);
                // Count null-terminated strings as a proxy for typed data regions
                let null_count = bytecount::count(data, 0);
                result.record_metric("null_bytes", u64::try_from(null_count).unwrap_or(u64::MAX));
                result.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                result
            }),
        );

        // Control flow pass
        self.pipeline.register(
            AnalysisPhase::ControlFlow,
            Arc::new(|data, _config, _ip| {
                let t0 = Instant::now();
                let mut result = PhaseResult::success(AnalysisPhase::ControlFlow, 0);
                // Count CALL rel32 (E8) instructions as proxy for functions
                let call_count = data.windows(1).filter(|w| w[0] == 0xE8).count();
                result.record_metric("functions_found", u64::try_from(call_count).unwrap_or(u64::MAX));
                result.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                result
            }),
        );

        // Data flow pass
        self.pipeline.register(
            AnalysisPhase::DataFlow,
            Arc::new(|_data, _config, _ip| {
                let t0 = Instant::now();
                let mut r = PhaseResult::success(AnalysisPhase::DataFlow, 0);
                r.record_metric("def_use_chains", 0);
                r.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                r
            }),
        );

        // Taint pass
        self.pipeline.register(
            AnalysisPhase::Taint,
            Arc::new(|_data, _config, _ip| {
                let t0 = Instant::now();
                let mut r = PhaseResult::success(AnalysisPhase::Taint, 0);
                r.record_metric("taint_sources", 0);
                r.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                r
            }),
        );

        // Symbolic execution pass
        self.pipeline.register(
            AnalysisPhase::Symbolic,
            Arc::new(|_data, _config, _ip| {
                let t0 = Instant::now();
                let mut r = PhaseResult::success(AnalysisPhase::Symbolic, 0);
                r.record_metric("symbolic_paths", 0);
                r.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                r
            }),
        );
    }

    fn register_scan_passes(&mut self) {
        // CrossRef pass
        self.pipeline.register(
            AnalysisPhase::CrossRef,
            Arc::new(|data, _config, _ip| {
                let t0 = Instant::now();
                let mut result = PhaseResult::success(AnalysisPhase::CrossRef, 0);
                // Count RET instructions (C3) as proxy for function boundaries
                let ret_count = bytecount::count(data, 0xC3);
                result.record_metric("xrefs_found", u64::try_from(ret_count).unwrap_or(u64::MAX));
                result.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                result
            }),
        );

        // String recovery pass
        self.pipeline.register(
            AnalysisPhase::StringRecovery,
            Arc::new(|data, config, _ip| {
                let t0 = Instant::now();
                let mut result = PhaseResult::success(AnalysisPhase::StringRecovery, 0);
                let min_len = config
                    .get_extra("min_string_len")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(4);
                // Count ASCII string runs
                let mut count = 0usize;
                let mut run = 0usize;
                for &b in data {
                    if b.is_ascii_graphic() || b == b' ' {
                        run += 1;
                    } else {
                        if run >= min_len {
                            count += 1;
                        }
                        run = 0;
                    }
                }
                if run >= min_len {
                    count += 1;
                }
                result.record_metric("strings_found", u64::try_from(count).unwrap_or(u64::MAX));
                result.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                result
            }),
        );
    }

    fn register_report_passes(&mut self) {
        // Signature match pass
        self.pipeline.register(
            AnalysisPhase::SignatureMatch,
            Arc::new(|data, _config, _ip| {
                let t0 = Instant::now();
                let mut result = PhaseResult::success(AnalysisPhase::SignatureMatch, 0);
                // Check for UPX
                if data.windows(4).any(|w| w == b"UPX!") {
                    result.add_finding(
                        Finding::new(
                            "UPX packer signature",
                            "File contains UPX! magic bytes indicating UPX packing",
                            FindingSeverity::Medium,
                            AnalysisPhase::SignatureMatch,
                        )
                        .with_tag("packer")
                        .with_tag("upx"),
                    );
                }
                // Check for MZ/ELF duplicates (embedded executables)
                let mz_count = data.windows(2).filter(|w| w == b"MZ").count();
                if mz_count > 1 {
                    result.add_finding(
                        Finding::new(
                            "Multiple MZ headers",
                            format!("{mz_count} MZ headers found — potential dropper"),
                            FindingSeverity::High,
                            AnalysisPhase::SignatureMatch,
                        )
                        .with_tag("dropper"),
                    );
                }
                result.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                result
            }),
        );

        // Vuln scan pass
        self.pipeline.register(
            AnalysisPhase::VulnScan,
            Arc::new(|data, _config, _ip| {
                let t0 = Instant::now();
                let mut result = PhaseResult::success(AnalysisPhase::VulnScan, 0);
                // Look for dangerous API names in strings
                let dangerous: &[&[u8]] = &[
                    b"strcpy", b"sprintf", b"gets", b"scanf",
                    b"memcpy", b"strcat",
                ];
                for api in dangerous {
                    if data.windows(api.len()).any(|w| w == *api) {
                        result.add_finding(
                            Finding::new(
                                format!("Dangerous API: {}", std::str::from_utf8(api).unwrap_or("?")),
                                format!("Use of potentially unsafe function detected: {}", std::str::from_utf8(api).unwrap_or("?")),
                                FindingSeverity::Medium,
                                AnalysisPhase::VulnScan,
                            )
                            .with_tag("buffer-overflow")
                            .with_tag("unsafe-api"),
                        );
                    }
                }
                result.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                result
            }),
        );

        // Reporting pass
        self.pipeline.register(
            AnalysisPhase::Reporting,
            Arc::new(|_data, _config, ip| {
                let t0 = Instant::now();
                let mut r = PhaseResult::success(AnalysisPhase::Reporting, 0);
                ip.increment("reports_generated");
                r.duration_ms = t0.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                r
            }),
        );
    }
}

impl std::fmt::Debug for BinaryAnalysisSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryAnalysisSuite")
            .field("pipeline", &self.pipeline)
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: create a small fake PE blob
    fn fake_pe() -> Vec<u8> {
        let mut v = b"MZ".to_vec();
        v.extend_from_slice(&[0u8; 62]);
        v.extend_from_slice(b"PE\x00\x00");
        v.extend_from_slice(&[0u8; 200]);
        v.extend_from_slice(b"hello world\x00test string\x00");
        v.extend_from_slice(b"strcpy\x00");
        v
    }

    // ── AnalysisPhase ─────────────────────────────────────────────────────────

    #[test]
    fn test_phase_names_unique() {
        let phases = AnalysisPhase::ordered();
        let names: std::collections::HashSet<&str> =
            phases.iter().map(|p| p.name()).collect();
        assert_eq!(names.len(), phases.len());
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(AnalysisPhase::Discovery.to_string(), "discovery");
        assert_eq!(AnalysisPhase::ControlFlow.to_string(), "control_flow");
    }

    #[test]
    fn test_phase_ordered_count() {
        assert!(AnalysisPhase::ordered().len() >= 10);
    }

    #[test]
    fn test_phase_ordering() {
        let phases = AnalysisPhase::ordered();
        assert_eq!(phases[0], AnalysisPhase::Discovery);
        assert_eq!(*phases.last().unwrap(), AnalysisPhase::Reporting);
    }

    // ── SuiteConfig ──────────────────────────────────────────────────────────

    #[test]
    fn test_config_default_valid() {
        assert!(SuiteConfig::default().validate().is_ok());
    }

    #[test]
    fn test_config_empty_phases_invalid() {
        let mut c = SuiteConfig::default();
        c.phases.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_zero_depth_invalid() {
        let mut c = SuiteConfig::default();
        c.max_depth = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_config_fast() {
        let c = SuiteConfig::fast();
        assert_eq!(c.phases.len(), 3);
        assert!(c.phases.contains(&AnalysisPhase::Discovery));
    }

    #[test]
    fn test_config_for_phases() {
        let c = SuiteConfig::for_phases(vec![AnalysisPhase::Taint]);
        assert_eq!(c.phases, vec![AnalysisPhase::Taint]);
    }

    #[test]
    fn test_config_get_extra_absent() {
        assert!(SuiteConfig::default().get_extra("nonexistent").is_none());
    }

    #[test]
    fn test_config_get_extra_present() {
        let mut c = SuiteConfig::default();
        c.extra.insert("foo".into(), "bar".into());
        assert_eq!(c.get_extra("foo"), Some("bar"));
    }

    // ── Finding ──────────────────────────────────────────────────────────────

    #[test]
    fn test_finding_new_defaults() {
        let f = Finding::new("title", "desc", FindingSeverity::High, AnalysisPhase::VulnScan);
        assert_eq!(f.title, "title");
        assert_eq!(f.severity, FindingSeverity::High);
        assert!(f.address.is_none());
        assert_eq!(f.confidence, 80);
    }

    #[test]
    fn test_finding_builders() {
        let f = Finding::new("t", "d", FindingSeverity::Low, AnalysisPhase::Taint)
            .at_address(0x1000)
            .in_function("main")
            .with_confidence(90)
            .with_tag("foo");
        assert_eq!(f.address, Some(0x1000));
        assert_eq!(f.function.as_deref(), Some("main"));
        assert_eq!(f.confidence, 90);
        assert_eq!(f.tags, vec!["foo"]);
    }

    #[test]
    fn test_finding_is_high_severity() {
        assert!(Finding::new("", "", FindingSeverity::High, AnalysisPhase::Taint).is_high_severity());
        assert!(Finding::new("", "", FindingSeverity::Critical, AnalysisPhase::Taint).is_high_severity());
        assert!(!Finding::new("", "", FindingSeverity::Medium, AnalysisPhase::Taint).is_high_severity());
    }

    #[test]
    fn test_finding_display() {
        let f = Finding::new("buf overflow", "desc", FindingSeverity::Critical, AnalysisPhase::VulnScan);
        assert!(f.to_string().contains("buf overflow"));
    }

    // ── InterPassData ─────────────────────────────────────────────────────────

    #[test]
    fn test_inter_pass_set_get() {
        let mut ip = InterPassData::new();
        ip.set("k", b"value".to_vec());
        assert_eq!(ip.get("k"), Some(b"value".as_ref()));
    }

    #[test]
    fn test_inter_pass_get_absent() {
        let ip = InterPassData::new();
        assert!(ip.get("absent").is_none());
    }

    #[test]
    fn test_inter_pass_json_roundtrip() {
        let mut ip = InterPassData::new();
        let val = vec![1u64, 2, 3];
        ip.set_json("nums", &val).unwrap();
        let out: Vec<u64> = ip.get_json("nums").unwrap();
        assert_eq!(out, val);
    }

    #[test]
    fn test_inter_pass_missing_json_error() {
        let ip = InterPassData::new();
        let result: Result<Vec<u64>, _> = ip.get_json("nope");
        assert!(result.is_err());
    }

    #[test]
    fn test_inter_pass_counter() {
        let mut ip = InterPassData::new();
        assert_eq!(ip.counter("c"), 0);
        assert_eq!(ip.increment("c"), 1);
        assert_eq!(ip.increment("c"), 2);
        assert_eq!(ip.counter("c"), 2);
    }

    #[test]
    fn test_inter_pass_contains() {
        let mut ip = InterPassData::new();
        assert!(!ip.contains("x"));
        ip.set("x", vec![]);
        assert!(ip.contains("x"));
    }

    #[test]
    fn test_inter_pass_len() {
        let mut ip = InterPassData::new();
        assert_eq!(ip.len(), 0);
        assert!(ip.is_empty());
        ip.set("a", vec![1]);
        ip.set("b", vec![2]);
        assert_eq!(ip.len(), 2);
        assert!(!ip.is_empty());
    }

    // ── PhaseResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_phase_result_success() {
        let r = PhaseResult::success(AnalysisPhase::Discovery, 42);
        assert!(r.success);
        assert_eq!(r.duration_ms, 42);
        assert!(r.error.is_none());
    }

    #[test]
    fn test_phase_result_failure() {
        let r = PhaseResult::failure(AnalysisPhase::Discovery, 10, "oom".into());
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("oom"));
    }

    #[test]
    fn test_phase_result_add_finding() {
        let mut r = PhaseResult::success(AnalysisPhase::VulnScan, 0);
        r.add_finding(Finding::new("f", "d", FindingSeverity::High, AnalysisPhase::VulnScan));
        assert_eq!(r.finding_count(), 1);
        assert_eq!(r.high_severity_count(), 1);
    }

    #[test]
    fn test_phase_result_metrics() {
        let mut r = PhaseResult::success(AnalysisPhase::ControlFlow, 0);
        r.record_metric("funcs", 42);
        assert_eq!(r.metrics["funcs"], 42);
    }

    // ── SuiteReport ───────────────────────────────────────────────────────────

    #[test]
    fn test_suite_report_build() {
        let results = vec![
            PhaseResult::success(AnalysisPhase::Discovery, 10),
            PhaseResult::success(AnalysisPhase::ControlFlow, 20),
        ];
        let report = SuiteReport::build("test.bin", SuiteConfig::default(), results, 30);
        assert!(report.all_succeeded);
        assert_eq!(report.stats.phases_run, 2);
        assert_eq!(report.stats.phases_succeeded, 2);
    }

    #[test]
    fn test_suite_report_failed_phase() {
        let results = vec![
            PhaseResult::success(AnalysisPhase::Discovery, 10),
            PhaseResult::failure(AnalysisPhase::Taint, 5, "oom".into()),
        ];
        let report = SuiteReport::build("test.bin", SuiteConfig::default(), results, 15);
        assert!(!report.all_succeeded);
        assert_eq!(report.stats.phases_failed, 1);
    }

    #[test]
    fn test_suite_report_findings_above() {
        let mut results = vec![PhaseResult::success(AnalysisPhase::VulnScan, 0)];
        results[0].add_finding(Finding::new("h", "", FindingSeverity::High, AnalysisPhase::VulnScan));
        results[0].add_finding(Finding::new("l", "", FindingSeverity::Low, AnalysisPhase::VulnScan));
        let report = SuiteReport::build("t", SuiteConfig::default(), results, 0);
        assert_eq!(report.findings_above(FindingSeverity::High).len(), 1);
        assert_eq!(report.findings_above(FindingSeverity::Low).len(), 2);
    }

    #[test]
    fn test_suite_report_summary() {
        let report = SuiteReport::build("a.bin", SuiteConfig::default(), vec![], 100);
        let s = report.summary();
        assert!(s.contains("a.bin"));
        assert!(s.contains("100ms"));
    }

    #[test]
    fn test_suite_report_to_json() {
        let report = SuiteReport::build("a.bin", SuiteConfig::default(), vec![], 0);
        assert!(report.to_json().is_ok());
    }

    // ── SuiteStats ────────────────────────────────────────────────────────────

    #[test]
    fn test_suite_stats_compute_empty() {
        let s = SuiteStats::compute(&[]);
        assert_eq!(s.phases_run, 0);
        assert_eq!(s.total_findings, 0);
    }

    #[test]
    fn test_suite_stats_compute_findings() {
        let mut r = PhaseResult::success(AnalysisPhase::VulnScan, 0);
        r.add_finding(Finding::new("c", "", FindingSeverity::Critical, AnalysisPhase::VulnScan));
        r.add_finding(Finding::new("h", "", FindingSeverity::High, AnalysisPhase::VulnScan));
        r.add_finding(Finding::new("m", "", FindingSeverity::Medium, AnalysisPhase::VulnScan));
        r.add_finding(Finding::new("l", "", FindingSeverity::Low, AnalysisPhase::VulnScan));
        r.add_finding(Finding::new("i", "", FindingSeverity::Info, AnalysisPhase::VulnScan));
        let s = SuiteStats::compute(&[r]);
        assert_eq!(s.total_findings, 5);
        assert_eq!(s.critical_findings, 1);
        assert_eq!(s.high_findings, 1);
        assert_eq!(s.medium_findings, 1);
        assert_eq!(s.low_findings, 1);
        assert_eq!(s.info_findings, 1);
    }

    // ── SuitePipeline ─────────────────────────────────────────────────────

    #[test]
    fn test_pipeline_empty() {
        let pipeline = SuitePipeline::new();
        assert_eq!(pipeline.pass_count(), 0);
    }

    #[test]
    fn test_pipeline_register_and_execute() {
        let mut pipeline = SuitePipeline::new();
        pipeline.register(
            AnalysisPhase::Discovery,
            Arc::new(|_data, _cfg, _ip| {
                PhaseResult::success(AnalysisPhase::Discovery, 1)
            }),
        );
        let config = SuiteConfig::for_phases(vec![AnalysisPhase::Discovery]);
        let mut ip = InterPassData::new();
        let results = pipeline.execute(b"hello", &config, &mut ip, None);
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_pipeline_skip_unregistered_phase() {
        let pipeline = SuitePipeline::new(); // no passes registered
        let config = SuiteConfig::for_phases(vec![AnalysisPhase::Taint]);
        let mut ip = InterPassData::new();
        let results = pipeline.execute(b"", &config, &mut ip, None);
        // Should return a success result for the unregistered phase
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }

    #[test]
    fn test_pipeline_abort_on_error() {
        let mut pipeline = SuitePipeline::new();
        pipeline.register(
            AnalysisPhase::Discovery,
            Arc::new(|_d, _c, _ip| {
                PhaseResult::failure(AnalysisPhase::Discovery, 0, "oops".into())
            }),
        );
        pipeline.register(
            AnalysisPhase::Typing,
            Arc::new(|_d, _c, _ip| PhaseResult::success(AnalysisPhase::Typing, 0)),
        );
        let mut config = SuiteConfig::for_phases(vec![
            AnalysisPhase::Discovery,
            AnalysisPhase::Typing,
        ]);
        config.abort_on_error = true;
        let mut ip = InterPassData::new();
        let results = pipeline.execute(b"", &config, &mut ip, None);
        assert_eq!(results.len(), 1); // aborted after first failure
    }

    // ── BinaryAnalysisSuite ───────────────────────────────────────────────────

    #[test]
    fn test_suite_run_on_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            .iter()
            .chain(b"hello world\x00strcpy\x00".iter())
            .copied()
            .collect::<Vec<u8>>();
        let suite = BinaryAnalysisSuite::with_defaults();
        let report = suite.run("test.elf", &data).unwrap();
        // ELF discovery should find "ELF" format
        let disc_findings = report.findings_for_phase(AnalysisPhase::Discovery);
        assert!(!disc_findings.is_empty());
    }

    #[test]
    fn test_suite_run_on_pe() {
        let data = fake_pe();
        let suite = BinaryAnalysisSuite::with_defaults();
        let report = suite.run("test.exe", &data).unwrap();
        assert!(report.stats.phases_run > 0);
    }

    #[test]
    fn test_suite_detects_strcpy() {
        let data = fake_pe();
        let suite = BinaryAnalysisSuite::with_defaults();
        let report = suite.run("test.exe", &data).unwrap();
        let vuln = report.findings_for_phase(AnalysisPhase::VulnScan);
        assert!(!vuln.is_empty(), "Expected strcpy finding");
    }

    #[test]
    fn test_suite_detects_upx() {
        let mut data = fake_pe();
        data.extend_from_slice(b"UPX!");
        let suite = BinaryAnalysisSuite::with_defaults();
        let report = suite.run("packed.exe", &data).unwrap();
        let sig = report.findings_for_phase(AnalysisPhase::SignatureMatch);
        assert!(sig.iter().any(|f| f.title.contains("UPX")));
    }

    #[test]
    fn test_suite_detects_multiple_mz() {
        let mut data = fake_pe();
        data.extend_from_slice(b"MZextra executable\x00");
        let suite = BinaryAnalysisSuite::with_defaults();
        let report = suite.run("dropper.exe", &data).unwrap();
        let sig = report.findings_for_phase(AnalysisPhase::SignatureMatch);
        assert!(sig.iter().any(|f| f.title.contains("Multiple MZ")));
    }

    #[test]
    fn test_suite_fast_config() {
        let suite = BinaryAnalysisSuite::new(SuiteConfig::fast());
        let report = suite.run("a.bin", b"MZ...").unwrap();
        assert_eq!(report.stats.phases_run, 3);
    }

    #[test]
    fn test_suite_string_recovery() {
        let data = b"hello world this is a test string\x00another string here";
        let suite = BinaryAnalysisSuite::new(SuiteConfig::for_phases(vec![
            AnalysisPhase::StringRecovery,
        ]));
        let report = suite.run("t.bin", data).unwrap();
        let r = &report.phase_results[0];
        assert!(r.metrics.get("strings_found").copied().unwrap_or(0) > 0);
    }

    #[test]
    fn test_suite_progress_callback() {
        use std::sync::Mutex;
        let events: Arc<Mutex<Vec<ProgressEvent>>> = Arc::new(Mutex::new(vec![]));
        let e2 = Arc::clone(&events);
        let cb: ProgressCallback = Arc::new(move |ev| {
            e2.lock().unwrap().push(ev);
        });
        let suite = BinaryAnalysisSuite::new(SuiteConfig::fast()).with_progress(cb);
        suite.run("t.bin", b"MZ...").unwrap();
        let evs = events.lock().unwrap();
        // Each phase emits 2 events (start + end), so fast config (3 phases) = 6
        assert!(evs.len() >= 3);
    }

    #[test]
    fn test_suite_validate_invalid_config() {
        let suite = BinaryAnalysisSuite::new(SuiteConfig { phases: vec![], ..Default::default() });
        assert!(suite.validate().is_err());
    }

    #[test]
    fn test_suite_report_to_json_full() {
        let suite = BinaryAnalysisSuite::with_defaults();
        let report = suite.run("a.bin", b"MZ\x00").unwrap();
        assert!(report.to_json().is_ok());
    }

    #[test]
    fn test_finding_severity_ordering() {
        assert!(FindingSeverity::Critical > FindingSeverity::High);
        assert!(FindingSeverity::High > FindingSeverity::Medium);
        assert!(FindingSeverity::Medium > FindingSeverity::Low);
        assert!(FindingSeverity::Low > FindingSeverity::Info);
    }

    #[test]
    fn test_progress_event_percent() {
        let ev = ProgressEvent {
            phase: AnalysisPhase::Discovery,
            phases_completed: 5,
            phases_total: 10,
            succeeded: None,
            duration_ms: None,
        };
        assert_eq!(ev.percent(), 50);
    }

    #[test]
    fn test_progress_event_percent_zero_total() {
        let ev = ProgressEvent {
            phase: AnalysisPhase::Discovery,
            phases_completed: 0,
            phases_total: 0,
            succeeded: None,
            duration_ms: None,
        };
        assert_eq!(ev.percent(), 100);
    }

    #[test]
    fn test_inter_pass_set_overwrite() {
        let mut ip = InterPassData::new();
        ip.set("k", b"v1".to_vec());
        ip.set("k", b"v2".to_vec());
        assert_eq!(ip.get("k"), Some(b"v2".as_ref()));
    }

    #[test]
    fn test_pipeline_multiple_phases() {
        let mut pipeline = SuitePipeline::new();
        for phase in AnalysisPhase::ordered() {
            let p = *phase;
            pipeline.register(p, Arc::new(move |_d, _c, _ip| PhaseResult::success(p, 1)));
        }
        let config = SuiteConfig::default();
        let mut ip = InterPassData::new();
        let results = pipeline.execute(b"data", &config, &mut ip, None);
        assert_eq!(results.len(), AnalysisPhase::ordered().len());
    }

    #[test]
    fn test_suite_report_findings_for_phase() {
        let mut r = PhaseResult::success(AnalysisPhase::VulnScan, 0);
        r.add_finding(Finding::new("v", "", FindingSeverity::High, AnalysisPhase::VulnScan));
        let report = SuiteReport::build("t", SuiteConfig::default(), vec![r], 0);
        assert_eq!(report.findings_for_phase(AnalysisPhase::VulnScan).len(), 1);
        assert_eq!(report.findings_for_phase(AnalysisPhase::Taint).len(), 0);
    }
}
