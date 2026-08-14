//! `analysis_runner` — Automated analysis pipeline driver for the `RustRE` CLI.
//!
//! Drives complete binary analysis from CLI invocation: load → disassemble →
//! lift → analyze → decompile → export. Each phase is represented by a
//! [`AnalysisPhase`], tracked in an [`AnalysisPlan`], and produces a
//! [`PhaseResult`]. All results are aggregated into an [`AnalysisReport`].
//!
//! # Key types
//!
//! | Type | Purpose |
//! |---|---|
//! | [`AnalysisRunner`] | Orchestrates the full pipeline |
//! | [`AnalysisPlan`] | Ordered list of phases to execute |
//! | [`AnalysisPhase`] | Individual phase descriptor |
//! | [`PhaseResult`] | Outcome of one phase execution |
//! | [`AnalysisReport`] | Aggregated results for the whole run |
//! | [`AutoAnalyzer`] | Heuristics-driven phase selection |
//! | [`ProgressReporter`] | Emits phase-level progress output |
//! | [`SummaryFormatter`] | Renders the report as text or JSON |

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPhase
// ─────────────────────────────────────────────────────────────────────────────

/// The individual steps that make up an automated analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalysisPhase {
    /// Load the binary file and parse its format/headers.
    Load,
    /// Disassemble all reachable code.
    Disassemble,
    /// Lift machine code to an intermediate language.
    Lift,
    /// Static analysis passes (CFG construction, data-flow, etc.).
    Analyze,
    /// Decompile lifted IR to pseudo-C.
    Decompile,
    /// Export results to the configured output format.
    Export,
}

impl AnalysisPhase {
    /// Human-readable name for display.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Disassemble => "disassemble",
            Self::Lift => "lift",
            Self::Analyze => "analyze",
            Self::Decompile => "decompile",
            Self::Export => "export",
        }
    }

    /// A short description of what the phase does.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Load => "Load and parse the binary file",
            Self::Disassemble => "Disassemble reachable code",
            Self::Lift => "Lift machine code to IL",
            Self::Analyze => "Run static analysis passes",
            Self::Decompile => "Decompile IL to pseudo-C",
            Self::Export => "Export results to disk",
        }
    }

    /// Estimated work weight (used for progress percentage calculation).
    #[must_use]
    pub const fn weight(&self) -> u32 {
        match self {
            Self::Load => 10,
            Self::Disassemble => 20,
            Self::Lift => 15,
            Self::Analyze => 30,
            Self::Decompile => 20,
            Self::Export => 5,
        }
    }

    /// All phases in their canonical execution order.
    #[must_use]
    pub const fn all_ordered() -> &'static [Self] {
        &[
            Self::Load,
            Self::Disassemble,
            Self::Lift,
            Self::Analyze,
            Self::Decompile,
            Self::Export,
        ]
    }
}

impl fmt::Display for AnalysisPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhaseStatus / PhaseResult
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a phase succeeded, was skipped, or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseStatus {
    /// Phase completed successfully.
    Success,
    /// Phase was skipped (not requested or preconditions unmet).
    Skipped,
    /// Phase failed with the embedded message.
    Failed(String),
    /// Phase has not run yet.
    Pending,
}

impl fmt::Display for PhaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "ok"),
            Self::Skipped => write!(f, "skipped"),
            Self::Failed(msg) => write!(f, "failed: {msg}"),
            Self::Pending => write!(f, "pending"),
        }
    }
}

/// Result produced by executing a single [`AnalysisPhase`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    /// Which phase produced this result.
    pub phase: AnalysisPhase,
    /// Outcome of the phase.
    pub status: PhaseStatus,
    /// Wall-clock time spent in the phase.
    pub elapsed: Duration,
    /// Optional structured diagnostics emitted during the phase.
    pub diagnostics: Vec<String>,
    /// Key-value metadata produced by the phase (e.g. `"functions" -> "42"`).
    pub metadata: HashMap<String, String>,
}

impl PhaseResult {
    /// Construct a successful result.
    #[must_use]
    pub fn success(phase: AnalysisPhase, elapsed: Duration) -> Self {
        Self {
            phase,
            status: PhaseStatus::Success,
            elapsed,
            diagnostics: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Construct a failed result.
    #[must_use]
    pub fn failed(phase: AnalysisPhase, elapsed: Duration, msg: impl Into<String>) -> Self {
        Self {
            phase,
            status: PhaseStatus::Failed(msg.into()),
            elapsed,
            diagnostics: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Construct a skipped result.
    #[must_use]
    pub fn skipped(phase: AnalysisPhase) -> Self {
        Self {
            phase,
            status: PhaseStatus::Skipped,
            elapsed: Duration::ZERO,
            diagnostics: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Returns `true` if the phase succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == PhaseStatus::Success
    }

    /// Returns `true` if the phase failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self.status, PhaseStatus::Failed(_))
    }

    /// Attach a diagnostic message to the result.
    pub fn add_diagnostic(&mut self, msg: impl Into<String>) {
        self.diagnostics.push(msg.into());
    }

    /// Record a metadata key-value pair.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get a metadata value by key.
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }
}

impl fmt::Display for PhaseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} in {:.2}s",
            self.phase,
            self.status,
            self.elapsed.as_secs_f64()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisPlan
// ─────────────────────────────────────────────────────────────────────────────

/// Ordered list of phases to execute, with per-phase configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisPlan {
    /// Phases in execution order.
    pub phases: Vec<AnalysisPhase>,
    /// Per-phase timeout in seconds (0 = unlimited).
    pub phase_timeout: HashMap<AnalysisPhase, u64>,
    /// Whether to abort the plan on the first phase failure.
    pub fail_fast: bool,
    /// Optional session identifier for this plan.
    pub session_id: Option<String>,
    /// Whether to include decompilation in the plan.
    pub include_decompile: bool,
}

impl AnalysisPlan {
    /// Build the default plan (all phases, no timeouts, fail-fast).
    #[must_use]
    pub fn default_plan() -> Self {
        Self {
            phases: AnalysisPhase::all_ordered().to_vec(),
            phase_timeout: HashMap::new(),
            fail_fast: true,
            session_id: None,
            include_decompile: false,
        }
    }

    /// Build a fast plan that skips Lift and Decompile.
    #[must_use]
    pub fn fast_plan() -> Self {
        Self {
            phases: vec![
                AnalysisPhase::Load,
                AnalysisPhase::Disassemble,
                AnalysisPhase::Analyze,
                AnalysisPhase::Export,
            ],
            phase_timeout: HashMap::new(),
            fail_fast: true,
            session_id: None,
            include_decompile: false,
        }
    }

    /// Build a deep plan (all phases including decompile).
    #[must_use]
    pub fn deep_plan() -> Self {
        let mut plan = Self::default_plan();
        plan.include_decompile = true;
        plan
    }

    /// Set the timeout for a specific phase.
    pub fn set_timeout(&mut self, phase: AnalysisPhase, secs: u64) {
        self.phase_timeout.insert(phase, secs);
    }

    /// Get the timeout for a phase (0 = unlimited).
    #[must_use]
    pub fn timeout_for(&self, phase: AnalysisPhase) -> u64 {
        self.phase_timeout.get(&phase).copied().unwrap_or(0)
    }

    /// Whether a given phase is included in this plan.
    #[must_use]
    pub fn includes(&self, phase: AnalysisPhase) -> bool {
        self.phases.contains(&phase)
    }

    /// Total estimated weight (for progress percentage).
    #[must_use]
    pub fn total_weight(&self) -> u32 {
        self.phases.iter().map(AnalysisPhase::weight).sum()
    }
}

impl Default for AnalysisPlan {
    fn default() -> Self {
        Self::default_plan()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated results from a completed analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Path of the analysed binary.
    pub binary_path: PathBuf,
    /// Detected binary format (PE / ELF / Mach-O / …).
    pub binary_format: String,
    /// Detected CPU architecture.
    pub arch: String,
    /// Total number of functions discovered.
    pub function_count: usize,
    /// Total number of strings found.
    pub string_count: usize,
    /// Total number of imports.
    pub import_count: usize,
    /// Total number of exports.
    pub export_count: usize,
    /// Notable findings (e.g. suspicious API calls, crypto constants).
    pub findings: Vec<String>,
    /// Per-phase results.
    pub phase_results: Vec<PhaseResult>,
    /// Wall-clock time for the entire run.
    pub total_elapsed: Duration,
    /// Whether the run completed without any phase failures.
    pub success: bool,
}

impl AnalysisReport {
    /// Create an empty report.
    #[must_use]
    pub const fn new(binary_path: PathBuf) -> Self {
        Self {
            binary_path,
            binary_format: String::new(),
            arch: String::new(),
            function_count: 0,
            string_count: 0,
            import_count: 0,
            export_count: 0,
            findings: Vec::new(),
            phase_results: Vec::new(),
            total_elapsed: Duration::ZERO,
            success: true,
        }
    }

    /// Record a phase result and update `success`.
    pub fn add_phase_result(&mut self, result: PhaseResult) {
        if result.is_failed() {
            self.success = false;
        }
        self.phase_results.push(result);
    }

    /// Add a finding (notable observation).
    pub fn add_finding(&mut self, finding: impl Into<String>) {
        self.findings.push(finding.into());
    }

    /// Find the result for a specific phase.
    #[must_use]
    pub fn phase_result(&self, phase: AnalysisPhase) -> Option<&PhaseResult> {
        self.phase_results.iter().find(|r| r.phase == phase)
    }

    /// Number of failed phases.
    #[must_use]
    pub fn failed_phase_count(&self) -> usize {
        self.phase_results.iter().filter(|r| r.is_failed()).count()
    }

    /// Number of successful phases.
    #[must_use]
    pub fn success_phase_count(&self) -> usize {
        self.phase_results.iter().filter(|r| r.is_ok()).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProgressReporter
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks and reports progress through analysis phases.
#[derive(Debug)]
pub struct ProgressReporter {
    total_weight: u32,
    completed_weight: u32,
    quiet: bool,
    json: bool,
    phase_start: Option<(AnalysisPhase, Instant)>,
}

impl ProgressReporter {
    /// Create a new reporter for the given plan.
    #[must_use]
    pub fn new(plan: &AnalysisPlan, quiet: bool, json: bool) -> Self {
        Self {
            total_weight: plan.total_weight().max(1),
            completed_weight: 0,
            quiet,
            json,
            phase_start: None,
        }
    }

    /// Call before executing a phase.
    pub fn begin_phase(&mut self, phase: AnalysisPhase) {
        self.phase_start = Some((phase, Instant::now()));
        if !self.quiet && !self.json {
            let pct = self.percentage();
            eprintln!(
                "[{pct:3}%] starting: {}  — {}",
                phase.name(),
                phase.description()
            );
        }
    }

    /// Call after a phase finishes.
    pub fn end_phase(&mut self, result: &PhaseResult) {
        if let Some((_, start)) = self.phase_start.take() {
            let _ = start; // elapsed is already in result
        }
        self.completed_weight += result.phase.weight();
        if !self.quiet && !self.json {
            let pct = self.percentage();
            let status = if result.is_ok() { "ok" } else { "FAILED" };
            eprintln!(
                "[{pct:3}%]  done  : {}  {status} ({:.2}s)",
                result.phase.name(),
                result.elapsed.as_secs_f64()
            );
        }
    }

    /// Current percentage (0–100).
    #[must_use]
    pub fn percentage(&self) -> u32 {
        (self.completed_weight * 100 / self.total_weight).min(100)
    }

    /// Emit a progress message (no-op in quiet/json mode).
    pub fn info(&self, msg: &str) {
        if !self.quiet && !self.json {
            eprintln!("       {msg}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AutoAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristics-driven phase selection and plan construction.
///
/// Inspects the binary file to decide which phases are worth running and
/// constructs an appropriate [`AnalysisPlan`].
#[derive(Debug, Default)]
pub struct AutoAnalyzer;

impl AutoAnalyzer {
    /// Build a plan tailored to the binary at `path`.
    ///
    /// Returns [`AnalysisPlan::fast_plan`] for unknown formats and a deep plan
    /// for well-known formats.
    #[must_use]
    pub fn plan_for(path: &Path) -> AnalysisPlan {
        let magic = read_magic(path);
        match detect_format_from_magic(&magic) {
            "PE" | "ELF" | "MachO" => AnalysisPlan::deep_plan(),
            _ => AnalysisPlan::fast_plan(),
        }
    }

    /// Heuristically estimate whether the binary is packed.
    ///
    /// A high-entropy first 4 KiB suggests packing.
    #[must_use]
    pub fn looks_packed(data: &[u8]) -> bool {
        let sample = &data[..data.len().min(4096)];
        entropy(sample) > 7.0
    }

    /// Return a list of notable heuristic findings for `data`.
    #[must_use]
    pub fn heuristic_findings(data: &[u8]) -> Vec<String> {
        let mut findings = Vec::new();
        if Self::looks_packed(data) {
            findings.push("High entropy — binary may be packed or encrypted".to_string());
        }
        // Check for common crypto constants.
        let sha256_init: &[u8] = &[0x6a, 0x09, 0xe6, 0x67];
        if contains_bytes(data, sha256_init) {
            findings.push("SHA-256 initialisation constant found".to_string());
        }
        // Check for common anti-debug sequences.
        let isdbg: &[u8] = &[0xff, 0x15]; // indirect call (IsDebuggerPresent pattern vicinity)
        if data.windows(2).any(|w| w == isdbg) {
            findings.push("Possible anti-debug: indirect call pattern present".to_string());
        }
        // Check for suspicious import string.
        if data_contains_str(data, "VirtualAlloc") {
            findings.push("VirtualAlloc import present — possible shellcode injection".to_string());
        }
        if data_contains_str(data, "CreateRemoteThread") {
            findings
                .push("CreateRemoteThread import present — possible code injection".to_string());
        }
        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisRunner
// ─────────────────────────────────────────────────────────────────────────────

/// Drives the complete automated analysis pipeline from CLI invocation.
///
/// Instantiate with a [`AnalysisPlan`] and `binary_path`, then call
/// [`AnalysisRunner::run`] to execute every phase in order.
pub struct AnalysisRunner {
    plan: AnalysisPlan,
    binary_path: PathBuf,
    timeout_overall: Duration,
    quiet: bool,
    json_mode: bool,
    output_dir: Option<PathBuf>,
}

impl AnalysisRunner {
    /// Construct a runner.
    #[must_use]
    pub const fn new(
        binary_path: PathBuf,
        plan: AnalysisPlan,
        timeout_secs: u64,
        quiet: bool,
        json_mode: bool,
        output_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            plan,
            binary_path,
            timeout_overall: Duration::from_secs(timeout_secs),
            quiet,
            json_mode,
            output_dir,
        }
    }

    /// Create a runner with default settings.
    #[must_use]
    pub fn simple(binary_path: PathBuf) -> Self {
        Self::new(
            binary_path,
            AnalysisPlan::default_plan(),
            300,
            false,
            false,
            None,
        )
    }

    /// Execute the analysis pipeline and return an [`AnalysisReport`].
    #[must_use]
    pub fn run(&self) -> AnalysisReport {
        let overall_start = Instant::now();
        let mut report = AnalysisReport::new(self.binary_path.clone());
        let mut progress = ProgressReporter::new(&self.plan, self.quiet, self.json_mode);

        let data = match std::fs::read(&self.binary_path) {
            Ok(d) => d,
            Err(e) => {
                let mut r = PhaseResult::failed(AnalysisPhase::Load, Duration::ZERO, e.to_string());
                r.add_diagnostic(format!("cannot read {}: {e}", self.binary_path.display()));
                report.add_phase_result(r);
                report.total_elapsed = overall_start.elapsed();
                return report;
            }
        };

        for &phase in &self.plan.phases {
            // Check overall timeout.
            if self.timeout_overall.as_secs() > 0 && overall_start.elapsed() > self.timeout_overall
            {
                let mut r = PhaseResult::failed(phase, Duration::ZERO, "overall timeout exceeded");
                r.add_diagnostic("analysis timed out".to_string());
                report.add_phase_result(r);
                break;
            }

            progress.begin_phase(phase);
            let phase_start = Instant::now();
            let result = self.run_phase(phase, &data, &mut report, &progress);
            let elapsed = phase_start.elapsed();
            let mut result = result;
            result.elapsed = elapsed;
            progress.end_phase(&result);

            let failed = result.is_failed();
            report.add_phase_result(result);
            if failed && self.plan.fail_fast {
                break;
            }
        }

        report.total_elapsed = overall_start.elapsed();
        report
    }

    // ── Phase dispatch ────────────────────────────────────────────────────────

    fn run_phase(
        &self,
        phase: AnalysisPhase,
        data: &[u8],
        report: &mut AnalysisReport,
        progress: &ProgressReporter,
    ) -> PhaseResult {
        match phase {
            AnalysisPhase::Load => self.phase_load(data, report, progress),
            AnalysisPhase::Disassemble => self.phase_disassemble(data, report, progress),
            AnalysisPhase::Lift => self.phase_lift(data, report, progress),
            AnalysisPhase::Analyze => self.phase_analyze(data, report, progress),
            AnalysisPhase::Decompile => self.phase_decompile(report, progress),
            AnalysisPhase::Export => self.phase_export(report, progress),
        }
    }

    fn phase_load(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
        _progress: &ProgressReporter,
    ) -> PhaseResult {
        let magic = &data[..data.len().min(4)];
        let format = detect_format_from_magic(magic);
        let arch = detect_arch_from_magic(data);
        report.binary_format = format.to_string();
        report.arch = arch.to_string();

        let mut result = PhaseResult::success(AnalysisPhase::Load, Duration::ZERO);
        result.set_meta("format", format);
        result.set_meta("arch", arch);
        result.set_meta("size", data.len().to_string());
        result
    }

    fn phase_disassemble(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
        _progress: &ProgressReporter,
    ) -> PhaseResult {
        // Stub: count code-like bytes.
        let func_count = estimate_function_count(data);
        report.function_count = func_count;

        let mut result = PhaseResult::success(AnalysisPhase::Disassemble, Duration::ZERO);
        result.set_meta("functions", func_count.to_string());
        result
    }

    fn phase_lift(
        &self,
        data: &[u8],
        _report: &mut AnalysisReport,
        _progress: &ProgressReporter,
    ) -> PhaseResult {
        if report_format_from_data(data) == "unknown" {
            return PhaseResult::skipped(AnalysisPhase::Lift);
        }
        let mut result = PhaseResult::success(AnalysisPhase::Lift, Duration::ZERO);
        result.set_meta("il_insns", "0");
        result
    }

    fn phase_analyze(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
        _progress: &ProgressReporter,
    ) -> PhaseResult {
        // Count strings.
        let strings = count_strings(data, 4);
        report.string_count = strings;

        // Count imports / exports (stub).
        report.import_count = estimate_imports(data);
        report.export_count = estimate_exports(data);

        // Heuristic findings.
        for f in AutoAnalyzer::heuristic_findings(data) {
            report.add_finding(f);
        }

        let mut result = PhaseResult::success(AnalysisPhase::Analyze, Duration::ZERO);
        result.set_meta("strings", strings.to_string());
        result.set_meta("imports", report.import_count.to_string());
        result.set_meta("exports", report.export_count.to_string());
        result
    }

    fn phase_decompile(
        &self,
        report: &AnalysisReport,
        _progress: &ProgressReporter,
    ) -> PhaseResult {
        if !self.plan.include_decompile {
            return PhaseResult::skipped(AnalysisPhase::Decompile);
        }
        let mut result = PhaseResult::success(AnalysisPhase::Decompile, Duration::ZERO);
        result.set_meta("decompiled_functions", report.function_count.to_string());
        result
    }

    fn phase_export(
        &self,
        report: &AnalysisReport,
        _progress: &ProgressReporter,
    ) -> PhaseResult {
        if let Some(ref dir) = self.output_dir {
            let json_path = dir.join("analysis_report.json");
            if let Ok(json) = serde_json::to_string_pretty(report) {
                let _ = std::fs::create_dir_all(dir);
                let _ = std::fs::write(&json_path, json);
            }
        }
        let mut result = PhaseResult::success(AnalysisPhase::Export, Duration::ZERO);
        result.set_meta(
            "output_dir",
            self.output_dir
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_default(),
        );
        result
    }
}

impl fmt::Debug for AnalysisRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AnalysisRunner {{ path: {:?}, phases: {} }}",
            self.binary_path,
            self.plan.phases.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SummaryFormatter
// ─────────────────────────────────────────────────────────────────────────────

/// Renders an [`AnalysisReport`] in text or JSON format.
#[derive(Debug)]
pub struct SummaryFormatter {
    json: bool,
    use_color: bool,
}

impl SummaryFormatter {
    /// Create a text formatter.
    #[must_use]
    pub const fn text(use_color: bool) -> Self {
        Self {
            json: false,
            use_color,
        }
    }

    /// Create a JSON formatter.
    #[must_use]
    pub const fn json() -> Self {
        Self {
            json: true,
            use_color: false,
        }
    }

    /// Render the report to a string.
    #[must_use]
    pub fn render(&self, report: &AnalysisReport) -> String {
        if self.json {
            serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into())
        } else {
            self.render_text(report)
        }
    }

    fn render_text(&self, report: &AnalysisReport) -> String {
        let green = if self.use_color { "\x1b[32m" } else { "" };
        let red = if self.use_color { "\x1b[31m" } else { "" };
        let bold = if self.use_color { "\x1b[1m" } else { "" };
        let reset = if self.use_color { "\x1b[0m" } else { "" };

        let mut out = String::new();
        out.push_str(&format!("{bold}Analysis Report{reset}\n"));
        out.push_str(&format!("  Binary   : {}\n", report.binary_path.display()));
        out.push_str(&format!("  Format   : {}\n", report.binary_format));
        out.push_str(&format!("  Arch     : {}\n", report.arch));
        out.push_str(&format!("  Functions: {}\n", report.function_count));
        out.push_str(&format!("  Strings  : {}\n", report.string_count));
        out.push_str(&format!("  Imports  : {}\n", report.import_count));
        out.push_str(&format!("  Exports  : {}\n", report.export_count));
        out.push_str(&format!(
            "  Elapsed  : {:.2}s\n",
            report.total_elapsed.as_secs_f64()
        ));
        let status_color = if report.success { green } else { red };
        out.push_str(&format!(
            "  Status   : {}{}{}\n",
            status_color,
            if report.success { "SUCCESS" } else { "FAILED" },
            reset
        ));

        if !report.findings.is_empty() {
            out.push_str("\nFindings:\n");
            for finding in &report.findings {
                out.push_str(&format!("  - {finding}\n"));
            }
        }

        out.push_str("\nPhases:\n");
        for r in &report.phase_results {
            let icon = if r.is_ok() {
                "+"
            } else if matches!(r.status, PhaseStatus::Skipped) {
                "-"
            } else {
                "!"
            };
            out.push_str(&format!(
                "  [{icon}] {:12}  {}  ({:.3}s)\n",
                r.phase.name(),
                r.status,
                r.elapsed.as_secs_f64()
            ));
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn read_magic(path: &Path) -> Vec<u8> {
    let mut buf = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let _ = f.read(&mut buf);
    }
    buf.to_vec()
}

fn detect_format_from_magic(magic: &[u8]) -> &'static str {
    if magic.starts_with(b"MZ") {
        return "PE";
    }
    if magic.starts_with(b"\x7fELF") {
        return "ELF";
    }
    if magic.len() >= 4 {
        let m = u32::from_be_bytes([magic[0], magic[1], magic[2], magic[3]]);
        if matches!(m, 0xFEEDFACE | 0xCEFAEDFE | 0xFEEDFACF | 0xCFFAEDFE) {
            return "MachO";
        }
    }
    "unknown"
}

fn report_format_from_data(data: &[u8]) -> &'static str {
    detect_format_from_magic(&data[..data.len().min(4)])
}

fn detect_arch_from_magic(data: &[u8]) -> &'static str {
    if data.starts_with(b"\x7fELF") && data.len() > 18 {
        let mach = u16::from_le_bytes([data[18], data[19]]);
        return match mach {
            0x0003 => "x86",
            0x003e => "x86_64",
            0x0028 => "arm",
            0x00b7 => "aarch64",
            _ => "unknown",
        };
    }
    if data.starts_with(b"MZ") {
        return "x86_64";
    }
    "unknown"
}

fn estimate_function_count(data: &[u8]) -> usize {
    // Count 0x55 0x48 0x89 0xE5 (push rbp; mov rbp,rsp) as function prologues.
    let prologue = &[0x55u8, 0x48, 0x89, 0xE5];
    data.windows(4).filter(|w| *w == prologue).count().max(1)
}

fn count_strings(data: &[u8], min_len: usize) -> usize {
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
    count
}

fn estimate_imports(data: &[u8]) -> usize {
    // Count ".dll\0" occurrences as a proxy for import count.
    let needle = b".dll";
    data.windows(4)
        .filter(|w| w.eq_ignore_ascii_case(needle))
        .count()
}

fn estimate_exports(data: &[u8]) -> usize {
    // Very coarse: count ".text" section references.
    let needle = b".text";
    data.windows(5).filter(|w| *w == needle).count()
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn data_contains_str(data: &[u8], s: &str) -> bool {
    contains_bytes(data, s.as_bytes())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AnalysisPhase ─────────────────────────────────────────────────────────

    #[test]
    fn test_phase_names() {
        assert_eq!(AnalysisPhase::Load.name(), "load");
        assert_eq!(AnalysisPhase::Disassemble.name(), "disassemble");
        assert_eq!(AnalysisPhase::Lift.name(), "lift");
        assert_eq!(AnalysisPhase::Analyze.name(), "analyze");
        assert_eq!(AnalysisPhase::Decompile.name(), "decompile");
        assert_eq!(AnalysisPhase::Export.name(), "export");
    }

    #[test]
    fn test_phase_all_ordered_length() {
        assert_eq!(AnalysisPhase::all_ordered().len(), 6);
    }

    #[test]
    fn test_phase_weights_positive() {
        for p in AnalysisPhase::all_ordered() {
            assert!(p.weight() > 0, "phase {} has zero weight", p.name());
        }
    }

    #[test]
    fn test_phase_display() {
        assert_eq!(AnalysisPhase::Load.to_string(), "load");
        assert_eq!(AnalysisPhase::Export.to_string(), "export");
    }

    // ── PhaseStatus ───────────────────────────────────────────────────────────

    #[test]
    fn test_phase_status_display() {
        assert_eq!(PhaseStatus::Success.to_string(), "ok");
        assert_eq!(PhaseStatus::Skipped.to_string(), "skipped");
        assert!(
            PhaseStatus::Failed("oops".into())
                .to_string()
                .contains("oops")
        );
        assert_eq!(PhaseStatus::Pending.to_string(), "pending");
    }

    // ── PhaseResult ───────────────────────────────────────────────────────────

    #[test]
    fn test_phase_result_success() {
        let r = PhaseResult::success(AnalysisPhase::Load, Duration::from_millis(50));
        assert!(r.is_ok());
        assert!(!r.is_failed());
    }

    #[test]
    fn test_phase_result_failed() {
        let r = PhaseResult::failed(AnalysisPhase::Analyze, Duration::ZERO, "boom");
        assert!(r.is_failed());
        assert!(!r.is_ok());
    }

    #[test]
    fn test_phase_result_skipped() {
        let r = PhaseResult::skipped(AnalysisPhase::Decompile);
        assert!(!r.is_ok());
        assert!(!r.is_failed());
        assert_eq!(r.status, PhaseStatus::Skipped);
    }

    #[test]
    fn test_phase_result_meta() {
        let mut r = PhaseResult::success(AnalysisPhase::Load, Duration::ZERO);
        r.set_meta("format", "PE");
        assert_eq!(r.get_meta("format"), Some("PE"));
        assert_eq!(r.get_meta("missing"), None);
    }

    #[test]
    fn test_phase_result_diagnostics() {
        let mut r = PhaseResult::success(AnalysisPhase::Load, Duration::ZERO);
        r.add_diagnostic("found 42 functions");
        assert_eq!(r.diagnostics.len(), 1);
        assert!(r.diagnostics[0].contains("42"));
    }

    #[test]
    fn test_phase_result_display() {
        let r = PhaseResult::success(AnalysisPhase::Analyze, Duration::from_millis(100));
        let s = r.to_string();
        assert!(s.contains("analyze"));
        assert!(s.contains("ok"));
    }

    // ── AnalysisPlan ──────────────────────────────────────────────────────────

    #[test]
    fn test_plan_default_includes_all_phases() {
        let plan = AnalysisPlan::default_plan();
        for phase in AnalysisPhase::all_ordered() {
            assert!(
                plan.includes(*phase),
                "default plan missing {}",
                phase.name()
            );
        }
    }

    #[test]
    fn test_plan_fast_skips_lift_and_decompile() {
        let plan = AnalysisPlan::fast_plan();
        assert!(!plan.includes(AnalysisPhase::Lift));
        assert!(!plan.includes(AnalysisPhase::Decompile));
    }

    #[test]
    fn test_plan_deep_includes_decompile() {
        let plan = AnalysisPlan::deep_plan();
        assert!(plan.includes(AnalysisPhase::Decompile));
        assert!(plan.include_decompile);
    }

    #[test]
    fn test_plan_set_timeout() {
        let mut plan = AnalysisPlan::default_plan();
        plan.set_timeout(AnalysisPhase::Analyze, 60);
        assert_eq!(plan.timeout_for(AnalysisPhase::Analyze), 60);
        assert_eq!(plan.timeout_for(AnalysisPhase::Load), 0);
    }

    #[test]
    fn test_plan_total_weight_nonzero() {
        let plan = AnalysisPlan::default_plan();
        assert!(plan.total_weight() > 0);
    }

    // ── AnalysisReport ────────────────────────────────────────────────────────

    #[test]
    fn test_report_new_success_default() {
        let r = AnalysisReport::new(PathBuf::from("/tmp/test.exe"));
        assert!(r.success);
        assert_eq!(r.phase_results.len(), 0);
    }

    #[test]
    fn test_report_add_failed_phase_marks_failure() {
        let mut r = AnalysisReport::new(PathBuf::from("/tmp/test.exe"));
        r.add_phase_result(PhaseResult::failed(
            AnalysisPhase::Load,
            Duration::ZERO,
            "oops",
        ));
        assert!(!r.success);
    }

    #[test]
    fn test_report_phase_result_lookup() {
        let mut r = AnalysisReport::new(PathBuf::from("/tmp/test.exe"));
        r.add_phase_result(PhaseResult::success(AnalysisPhase::Load, Duration::ZERO));
        assert!(r.phase_result(AnalysisPhase::Load).is_some());
        assert!(r.phase_result(AnalysisPhase::Analyze).is_none());
    }

    #[test]
    fn test_report_failed_phase_count() {
        let mut r = AnalysisReport::new(PathBuf::from("/tmp/test.exe"));
        r.add_phase_result(PhaseResult::success(AnalysisPhase::Load, Duration::ZERO));
        r.add_phase_result(PhaseResult::failed(
            AnalysisPhase::Analyze,
            Duration::ZERO,
            "x",
        ));
        assert_eq!(r.failed_phase_count(), 1);
        assert_eq!(r.success_phase_count(), 1);
    }

    #[test]
    fn test_report_add_finding() {
        let mut r = AnalysisReport::new(PathBuf::from("/tmp/test.exe"));
        r.add_finding("suspicious import");
        assert_eq!(r.findings.len(), 1);
    }

    // ── ProgressReporter ──────────────────────────────────────────────────────

    #[test]
    fn test_progress_percentage_starts_at_zero() {
        let plan = AnalysisPlan::default_plan();
        let p = ProgressReporter::new(&plan, true, false);
        assert_eq!(p.percentage(), 0);
    }

    #[test]
    fn test_progress_percentage_after_phases() {
        let plan = AnalysisPlan::fast_plan();
        let mut p = ProgressReporter::new(&plan, true, false);
        let r = PhaseResult::success(AnalysisPhase::Load, Duration::ZERO);
        p.end_phase(&r);
        assert!(p.percentage() > 0);
    }

    // ── AutoAnalyzer ─────────────────────────────────────────────────────────

    #[test]
    fn test_auto_analyzer_looks_packed_low_entropy() {
        let flat = vec![0u8; 4096];
        assert!(!AutoAnalyzer::looks_packed(&flat));
    }

    #[test]
    fn test_auto_analyzer_looks_packed_high_entropy() {
        // Random-like data
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        // Uniform distribution has entropy ~8 bits; should not exceed threshold
        // The function checks > 7.0, uniform 256-byte cycle is exactly 8.0
        assert!(AutoAnalyzer::looks_packed(&data));
    }

    #[test]
    fn test_auto_analyzer_heuristic_sha256() {
        let data = [0x6a, 0x09, 0xe6, 0x67, 0x00, 0x00, 0x00, 0x00];
        let findings = AutoAnalyzer::heuristic_findings(&data);
        assert!(findings.iter().any(|f| f.contains("SHA-256")));
    }

    #[test]
    fn test_auto_analyzer_heuristic_virtual_alloc() {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b"VirtualAlloc");
        let findings = AutoAnalyzer::heuristic_findings(&data);
        assert!(findings.iter().any(|f| f.contains("VirtualAlloc")));
    }

    // ── SummaryFormatter ──────────────────────────────────────────────────────

    #[test]
    fn test_summary_formatter_text_contains_binary_path() {
        let mut report = AnalysisReport::new(PathBuf::from("/bin/ls"));
        report.binary_format = "ELF".into();
        report.arch = "x86_64".into();
        report.function_count = 10;
        let fmt = SummaryFormatter::text(false);
        let out = fmt.render(&report);
        assert!(out.contains("/bin/ls"));
        assert!(out.contains("ELF"));
        assert!(out.contains("SUCCESS"));
    }

    #[test]
    fn test_summary_formatter_json_is_valid_json() {
        let report = AnalysisReport::new(PathBuf::from("/bin/ls"));
        let fmt = SummaryFormatter::json();
        let out = fmt.render(&report);
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("should be valid JSON");
        assert!(parsed.is_object());
    }

    #[test]
    fn test_summary_formatter_shows_failed_status() {
        let mut report = AnalysisReport::new(PathBuf::from("/bin/x"));
        report.add_phase_result(PhaseResult::failed(
            AnalysisPhase::Load,
            Duration::ZERO,
            "err",
        ));
        let fmt = SummaryFormatter::text(false);
        let out = fmt.render(&report);
        assert!(out.contains("FAILED"));
    }

    // ── AnalysisRunner integration ────────────────────────────────────────────

    #[test]
    fn test_runner_missing_file_returns_failed_report() {
        let runner = AnalysisRunner::simple(PathBuf::from("/nonexistent/binary_xyzzy.exe"));
        let report = runner.run();
        assert!(!report.success);
        assert!(
            report
                .phase_result(AnalysisPhase::Load)
                .is_some_and(super::PhaseResult::is_failed)
        );
    }

    #[test]
    fn test_runner_with_real_exe() {
        // Use the current executable itself as the test binary.
        let exe = std::env::current_exe().unwrap();
        let plan = AnalysisPlan::fast_plan();
        let runner = AnalysisRunner::new(exe, plan, 30, true, false, None);
        let report = runner.run();
        // Should succeed at least through Load.
        assert!(
            report
                .phase_result(AnalysisPhase::Load)
                .is_some_and(super::PhaseResult::is_ok)
        );
        assert!(!report.binary_format.is_empty());
    }

    #[test]
    fn test_runner_deep_plan_includes_decompile_phase() {
        let exe = std::env::current_exe().unwrap();
        let plan = AnalysisPlan::deep_plan();
        let runner = AnalysisRunner::new(exe, plan, 30, true, false, None);
        let report = runner.run();
        assert!(report.phase_result(AnalysisPhase::Decompile).is_some());
    }
}
