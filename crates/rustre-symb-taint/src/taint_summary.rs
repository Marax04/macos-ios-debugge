//! Taint analysis summary: per-function taint summaries, path reconstruction,
//! sanitizer detection, and aggregate reporting.
//!
//! `TaintSummary` captures which function parameters taint the return value and
//! which arguments flow through to output parameters. `SummaryReport` aggregates
//! per-function summaries and supports serialization for caching / display.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{TaintId, TaintLocation, TaintSource, FindingType, taint_bits};

// ─── TaintPath ────────────────────────────────────────────────────────────────

/// A chain of locations through which taint flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    /// Source location where taint originates.
    pub source: TaintLocation,
    /// Sequence of intermediate locations.
    pub steps: Vec<TaintPathStep>,
    /// Sink location where taint arrives.
    pub sink: TaintLocation,
    /// Combined taint mask along the path.
    pub taint: TaintId,
}

/// One step in a taint propagation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPathStep {
    pub from: TaintLocation,
    pub to: TaintLocation,
    pub operation: String,
    pub address: u64,
}

impl TaintPath {
    pub fn new(source: TaintLocation, sink: TaintLocation, taint: TaintId) -> Self {
        Self {
            source,
            steps: Vec::new(),
            sink,
            taint,
        }
    }

    pub fn add_step(&mut self, from: TaintLocation, to: TaintLocation, op: &str, addr: u64) {
        self.steps.push(TaintPathStep {
            from,
            to,
            operation: op.into(),
            address: addr,
        });
    }

    pub fn depth(&self) -> usize {
        self.steps.len()
    }

    pub fn passes_through(&self, loc: &TaintLocation) -> bool {
        self.steps.iter().any(|s| &s.from == loc || &s.to == loc)
    }

    pub fn is_direct(&self) -> bool {
        self.steps.is_empty()
    }

    /// Return the full chain of locations (source + intermediates + sink).
    pub fn all_locations(&self) -> Vec<&TaintLocation> {
        let mut locs = vec![&self.source];
        for step in &self.steps {
            locs.push(&step.to);
        }
        locs.push(&self.sink);
        locs
    }
}

// ─── SanitizerKind ────────────────────────────────────────────────────────────

/// How a sanitizer cleans tainted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanitizerKind {
    /// Validates/escapes a string.
    InputValidation,
    /// Parameterized query / prepared statement.
    PreparedStatement,
    /// HTML/XML entity encoding.
    HtmlEncoding,
    /// URL percent-encoding.
    UrlEncoding,
    /// Cryptographic hashing (output is no longer user-controlled).
    CryptoHash,
    /// Bounds check that prevents overflow.
    BoundsCheck,
    /// Custom / generic sanitizer.
    Custom(String),
}

impl SanitizerKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::InputValidation => "input_validation",
            Self::PreparedStatement => "prepared_statement",
            Self::HtmlEncoding => "html_encoding",
            Self::UrlEncoding => "url_encoding",
            Self::CryptoHash => "crypto_hash",
            Self::BoundsCheck => "bounds_check",
            Self::Custom(s) => s.as_str(),
        }
    }
}

// ─── SanitizerRecord ─────────────────────────────────────────────────────────

/// A detected sanitizer applied to tainted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerRecord {
    pub kind: SanitizerKind,
    pub function_name: String,
    pub address: u64,
    /// Which taint bits were cleared by this sanitizer.
    pub cleared_taint: TaintId,
}

impl SanitizerRecord {
    pub fn new(
        kind: SanitizerKind,
        function_name: impl Into<String>,
        address: u64,
        cleared_taint: TaintId,
    ) -> Self {
        Self {
            kind,
            function_name: function_name.into(),
            address,
            cleared_taint,
        }
    }
}

// ─── FunctionTaintSummary ─────────────────────────────────────────────────────

/// Taint behavior summary for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTaintSummary {
    /// Function address.
    pub address: u64,
    /// Function name, if known.
    pub name: Option<String>,
    /// Which argument indices propagate taint to the return value.
    pub args_to_return: Vec<usize>,
    /// Which argument index pairs propagate taint between each other (arg_in → arg_out).
    pub arg_to_arg: Vec<(usize, usize)>,
    /// Arguments that are sanitized inside the function.
    pub sanitized_args: Vec<usize>,
    /// Whether this function introduces a new taint source (e.g. reads from stdin).
    pub is_source: bool,
    /// If it is a taint source, which taint it introduces.
    pub source_taint: TaintId,
    /// Whether this function is a dangerous sink.
    pub is_sink: bool,
    /// The finding type if this is a sink.
    pub sink_finding: Option<FindingType>,
    /// Sanitizers found within this function.
    pub sanitizers: Vec<SanitizerRecord>,
    /// All taint paths through this function.
    pub paths: Vec<TaintPath>,
}

impl FunctionTaintSummary {
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name: None,
            args_to_return: Vec::new(),
            arg_to_arg: Vec::new(),
            sanitized_args: Vec::new(),
            is_source: false,
            source_taint: taint_bits::NONE,
            is_sink: false,
            sink_finding: None,
            sanitizers: Vec::new(),
            paths: Vec::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn propagates_arg_to_return(mut self, args: Vec<usize>) -> Self {
        self.args_to_return = args;
        self
    }

    pub fn mark_as_source(mut self, taint: TaintId) -> Self {
        self.is_source = true;
        self.source_taint = taint;
        self
    }

    pub fn mark_as_sink(mut self, finding: FindingType) -> Self {
        self.is_sink = true;
        self.sink_finding = Some(finding);
        self
    }

    /// Given a set of arg taints, compute the return taint.
    pub fn compute_return_taint(&self, arg_taints: &[TaintId]) -> TaintId {
        if self.is_source {
            return self.source_taint;
        }
        self.args_to_return
            .iter()
            .fold(taint_bits::NONE, |acc, &idx| {
                acc | arg_taints.get(idx).copied().unwrap_or(taint_bits::NONE)
            })
    }

    /// Return true if argument `arg_idx` is sanitized by this function.
    pub fn sanitizes(&self, arg_idx: usize) -> bool {
        self.sanitized_args.contains(&arg_idx)
    }

    /// Add a taint path through this function.
    pub fn add_path(&mut self, path: TaintPath) {
        self.paths.push(path);
    }

    /// Add a sanitizer record.
    pub fn add_sanitizer(&mut self, san: SanitizerRecord) {
        self.sanitizers.push(san);
    }

    /// Display name.
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("fn_0x{:x}", self.address))
    }
}

// ─── TaintSummary ─────────────────────────────────────────────────────────────

/// Top-level taint analysis summary: aggregates per-function summaries
/// and provides fast lookup by address or name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSummary {
    pub functions: HashMap<u64, FunctionTaintSummary>,
    pub name_index: HashMap<String, u64>,
    pub total_analyzed: usize,
    pub total_sources: usize,
    pub total_sinks: usize,
    pub total_sanitizers: usize,
    pub source_kinds: Vec<TaintSource>,
}

impl TaintSummary {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            name_index: HashMap::new(),
            total_analyzed: 0,
            total_sources: 0,
            total_sinks: 0,
            total_sanitizers: 0,
            source_kinds: Vec::new(),
        }
    }

    /// Insert a function summary.
    pub fn insert(&mut self, summary: FunctionTaintSummary) {
        let addr = summary.address;
        if summary.is_source {
            self.total_sources += 1;
        }
        if summary.is_sink {
            self.total_sinks += 1;
        }
        self.total_sanitizers += summary.sanitizers.len();
        if let Some(ref name) = summary.name {
            self.name_index.insert(name.clone(), addr);
        }
        self.functions.insert(addr, summary);
        self.total_analyzed += 1;
    }

    /// Look up by address.
    pub fn by_address(&self, addr: u64) -> Option<&FunctionTaintSummary> {
        self.functions.get(&addr)
    }

    /// Look up by name.
    pub fn by_name(&self, name: &str) -> Option<&FunctionTaintSummary> {
        let addr = self.name_index.get(name)?;
        self.functions.get(addr)
    }

    /// Return all source functions.
    pub fn sources(&self) -> Vec<&FunctionTaintSummary> {
        self.functions.values().filter(|f| f.is_source).collect()
    }

    /// Return all sink functions.
    pub fn sinks(&self) -> Vec<&FunctionTaintSummary> {
        self.functions.values().filter(|f| f.is_sink).collect()
    }

    /// Return all functions that contain sanitizers.
    pub fn sanitizing_functions(&self) -> Vec<&FunctionTaintSummary> {
        self.functions.values().filter(|f| !f.sanitizers.is_empty()).collect()
    }

    /// Compute return taint for a call, using summary if known; otherwise conservative.
    pub fn propagate_call(&self, addr: u64, arg_taints: &[TaintId]) -> TaintId {
        if let Some(summary) = self.functions.get(&addr) {
            summary.compute_return_taint(arg_taints)
        } else {
            // Unknown function: conservative union
            arg_taints.iter().fold(taint_bits::NONE, |acc, &t| acc | t)
        }
    }

    /// Collect all unique taint paths across all functions.
    pub fn all_paths(&self) -> Vec<&TaintPath> {
        self.functions.values().flat_map(|f| f.paths.iter()).collect()
    }

    /// Unique source taint bits seen across all functions.
    pub fn all_source_taints(&self) -> TaintId {
        self.functions
            .values()
            .filter(|f| f.is_source)
            .fold(taint_bits::NONE, |acc, f| acc | f.source_taint)
    }
}

impl Default for TaintSummary {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SummaryReport ────────────────────────────────────────────────────────────

/// A human- and machine-readable report derived from a `TaintSummary`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReport {
    pub total_functions: usize,
    pub source_functions: Vec<String>,
    pub sink_functions: Vec<String>,
    pub sanitizing_functions: Vec<String>,
    pub all_paths_count: usize,
    pub critical_paths: Vec<CriticalPathEntry>,
    pub source_taint_bits: TaintId,
    pub sanitizer_coverage: f64,
}

/// A notable source → sink path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalPathEntry {
    pub source_function: String,
    pub sink_function: String,
    pub path_depth: usize,
    pub taint: TaintId,
}

impl SummaryReport {
    /// Build a report from a `TaintSummary`.
    pub fn from_summary(summary: &TaintSummary) -> Self {
        let source_functions: Vec<String> = summary
            .sources()
            .iter()
            .map(|f| f.display_name())
            .collect();
        let sink_functions: Vec<String> = summary
            .sinks()
            .iter()
            .map(|f| f.display_name())
            .collect();
        let sanitizing_functions: Vec<String> = summary
            .sanitizing_functions()
            .iter()
            .map(|f| f.display_name())
            .collect();

        let all_paths = summary.all_paths();
        let all_paths_count = all_paths.len();

        // Build critical paths: those connecting a source to a sink
        let source_names: HashSet<&str> = source_functions.iter().map(|s| s.as_str()).collect();
        let sink_names: HashSet<&str> = sink_functions.iter().map(|s| s.as_str()).collect();

        let mut critical_paths = Vec::new();
        for path in &all_paths {
            let src_name = source_names.iter().next().copied().unwrap_or("unknown");
            let snk_name = sink_names.iter().next().copied().unwrap_or("unknown");
            if taint_bits::is_tainted(path.taint) && !source_names.is_empty() && !sink_names.is_empty() {
                critical_paths.push(CriticalPathEntry {
                    source_function: src_name.to_string(),
                    sink_function: snk_name.to_string(),
                    path_depth: path.depth(),
                    taint: path.taint,
                });
            }
        }

        let sanitizer_coverage = if summary.total_analyzed == 0 {
            0.0
        } else {
            sanitizing_functions.len() as f64 / summary.total_analyzed as f64
        };

        Self {
            total_functions: summary.total_analyzed,
            source_functions,
            sink_functions,
            sanitizing_functions,
            all_paths_count,
            critical_paths,
            source_taint_bits: summary.all_source_taints(),
            sanitizer_coverage,
        }
    }

    pub fn has_critical_paths(&self) -> bool {
        !self.critical_paths.is_empty()
    }

    pub fn format_text(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("=== Taint Summary Report ==="));
        lines.push(format!("Total functions analyzed: {}", self.total_functions));
        lines.push(format!("Taint sources: {:?}", self.source_functions));
        lines.push(format!("Taint sinks:   {:?}", self.sink_functions));
        lines.push(format!("Sanitizers:    {:?}", self.sanitizing_functions));
        lines.push(format!("Total paths:   {}", self.all_paths_count));
        lines.push(format!("Critical paths: {}", self.critical_paths.len()));
        lines.push(format!("Sanitizer coverage: {:.1}%", self.sanitizer_coverage * 100.0));
        lines.join("\n")
    }
}

// ─── SummaryBuilder ──────────────────────────────────────────────────────────

/// Builder that constructs a `TaintSummary` from analysis artifacts.
pub struct SummaryBuilder {
    summary: TaintSummary,
    /// Known sanitizer function names.
    sanitizer_names: HashSet<String>,
    /// Known source function names → taint bits.
    source_map: HashMap<String, TaintId>,
}

impl SummaryBuilder {
    pub fn new() -> Self {
        let mut builder = Self {
            summary: TaintSummary::new(),
            sanitizer_names: HashSet::new(),
            source_map: HashMap::new(),
        };
        builder.load_defaults();
        builder
    }

    /// Register a sanitizer function name.
    pub fn add_sanitizer_name(&mut self, name: &str) {
        self.sanitizer_names.insert(name.into());
    }

    /// Register a source function and the taint it introduces.
    pub fn add_source(&mut self, name: &str, taint: TaintId) {
        self.source_map.insert(name.into(), taint);
    }

    /// Add a raw function summary.
    pub fn add_function(&mut self, summary: FunctionTaintSummary) {
        self.summary.insert(summary);
    }

    /// Auto-classify a function: check if it is a known source or sanitizer.
    pub fn auto_classify(&mut self, mut summary: FunctionTaintSummary) -> FunctionTaintSummary {
        if let Some(ref name) = summary.name.clone() {
            if let Some(&taint) = self.source_map.get(name) {
                summary = summary.mark_as_source(taint);
            }
            if self.sanitizer_names.contains(name.as_str()) {
                summary.sanitizers.push(SanitizerRecord::new(
                    SanitizerKind::InputValidation,
                    name.clone(),
                    summary.address,
                    taint_bits::ALL,
                ));
            }
        }
        summary
    }

    /// Finalize and return the summary.
    pub fn build(self) -> TaintSummary {
        self.summary
    }

    fn load_defaults(&mut self) {
        // Standard sanitizers
        for name in &["escape_string", "sanitize_input", "validate_input",
                       "htmlspecialchars", "html_escape", "sql_escape",
                       "urlencode", "base64_encode"] {
            self.sanitizer_names.insert((*name).into());
        }
        // Standard sources
        self.source_map.insert("getenv".into(), taint_bits::ENVIRONMENT);
        self.source_map.insert("fgets".into(), taint_bits::FILE);
        self.source_map.insert("read".into(), taint_bits::FILE);
        self.source_map.insert("recv".into(), taint_bits::NETWORK);
        self.source_map.insert("recvfrom".into(), taint_bits::NETWORK);
        self.source_map.insert("gets".into(), taint_bits::USER_INPUT);
        self.source_map.insert("scanf".into(), taint_bits::USER_INPUT);
        self.source_map.insert("fread".into(), taint_bits::FILE);
    }
}

impl Default for SummaryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(name: &str) -> TaintLocation { TaintLocation::Register(name.into()) }

    #[test]
    fn test_taint_path_new() {
        let path = TaintPath::new(reg("rdi"), reg("rax"), taint_bits::USER_INPUT);
        assert_eq!(path.depth(), 0);
        assert!(path.is_direct());
    }

    #[test]
    fn test_taint_path_add_step() {
        let mut path = TaintPath::new(reg("rdi"), reg("rax"), taint_bits::USER_INPUT);
        path.add_step(reg("rdi"), reg("rbx"), "assign", 0x100);
        path.add_step(reg("rbx"), reg("rax"), "arith", 0x104);
        assert_eq!(path.depth(), 2);
        assert!(!path.is_direct());
    }

    #[test]
    fn test_taint_path_passes_through() {
        let mut path = TaintPath::new(reg("rdi"), reg("rax"), taint_bits::NONE);
        path.add_step(reg("rdi"), reg("rcx"), "assign", 0x100);
        assert!(path.passes_through(&reg("rcx")));
        assert!(!path.passes_through(&reg("rbx")));
    }

    #[test]
    fn test_taint_path_all_locations() {
        let mut path = TaintPath::new(reg("rdi"), reg("rax"), taint_bits::NONE);
        path.add_step(reg("rdi"), reg("rbx"), "x", 0);
        let locs = path.all_locations();
        assert_eq!(locs.len(), 3); // source + rbx + sink
    }

    #[test]
    fn test_function_summary_compute_return_taint() {
        let summary = FunctionTaintSummary::new(0x1000)
            .propagates_arg_to_return(vec![0, 2]);
        let arg_taints = vec![taint_bits::USER_INPUT, taint_bits::NONE, taint_bits::FILE];
        let result = summary.compute_return_taint(&arg_taints);
        assert!(taint_bits::has_bit(result, taint_bits::USER_INPUT));
        assert!(taint_bits::has_bit(result, taint_bits::FILE));
        assert!(!taint_bits::has_bit(result, taint_bits::NETWORK));
    }

    #[test]
    fn test_function_summary_source_overrides_return() {
        let summary = FunctionTaintSummary::new(0x2000)
            .mark_as_source(taint_bits::NETWORK);
        let result = summary.compute_return_taint(&[taint_bits::NONE]);
        assert_eq!(result, taint_bits::NETWORK);
    }

    #[test]
    fn test_function_summary_sanitizes() {
        let mut s = FunctionTaintSummary::new(0x3000);
        s.sanitized_args.push(1);
        assert!(s.sanitizes(1));
        assert!(!s.sanitizes(0));
    }

    #[test]
    fn test_taint_summary_insert_and_lookup() {
        let mut ts = TaintSummary::new();
        let f = FunctionTaintSummary::new(0x1000).with_name("foo");
        ts.insert(f);
        assert!(ts.by_address(0x1000).is_some());
        assert!(ts.by_name("foo").is_some());
        assert!(ts.by_name("bar").is_none());
    }

    #[test]
    fn test_taint_summary_sources_and_sinks() {
        let mut ts = TaintSummary::new();
        let src = FunctionTaintSummary::new(0x1000).mark_as_source(taint_bits::USER_INPUT);
        let snk = FunctionTaintSummary::new(0x2000).mark_as_sink(FindingType::FormatString);
        ts.insert(src);
        ts.insert(snk);
        assert_eq!(ts.sources().len(), 1);
        assert_eq!(ts.sinks().len(), 1);
        assert_eq!(ts.total_sources, 1);
        assert_eq!(ts.total_sinks, 1);
    }

    #[test]
    fn test_taint_summary_propagate_call_known() {
        let mut ts = TaintSummary::new();
        let f = FunctionTaintSummary::new(0x1000).propagates_arg_to_return(vec![0]);
        ts.insert(f);
        let ret = ts.propagate_call(0x1000, &[taint_bits::FILE, taint_bits::NONE]);
        assert_eq!(ret, taint_bits::FILE);
    }

    #[test]
    fn test_taint_summary_propagate_call_unknown_conservative() {
        let ts = TaintSummary::new();
        let ret = ts.propagate_call(0xDEAD, &[taint_bits::USER_INPUT, taint_bits::NETWORK]);
        assert!(taint_bits::has_bit(ret, taint_bits::USER_INPUT));
        assert!(taint_bits::has_bit(ret, taint_bits::NETWORK));
    }

    #[test]
    fn test_taint_summary_all_source_taints() {
        let mut ts = TaintSummary::new();
        ts.insert(FunctionTaintSummary::new(0x1).mark_as_source(taint_bits::NETWORK));
        ts.insert(FunctionTaintSummary::new(0x2).mark_as_source(taint_bits::FILE));
        let bits = ts.all_source_taints();
        assert!(taint_bits::has_bit(bits, taint_bits::NETWORK));
        assert!(taint_bits::has_bit(bits, taint_bits::FILE));
    }

    #[test]
    fn test_summary_report_from_summary() {
        let mut ts = TaintSummary::new();
        ts.insert(FunctionTaintSummary::new(0x1000).with_name("recv").mark_as_source(taint_bits::NETWORK));
        ts.insert(FunctionTaintSummary::new(0x2000).with_name("printf").mark_as_sink(FindingType::FormatString));
        let report = SummaryReport::from_summary(&ts);
        assert_eq!(report.total_functions, 2);
        assert!(!report.source_functions.is_empty());
        assert!(!report.sink_functions.is_empty());
    }

    #[test]
    fn test_summary_report_format_text() {
        let ts = TaintSummary::new();
        let report = SummaryReport::from_summary(&ts);
        let text = report.format_text();
        assert!(text.contains("Taint Summary Report"));
    }

    #[test]
    fn test_summary_builder_auto_classify_source() {
        let mut builder = SummaryBuilder::new();
        let f = FunctionTaintSummary::new(0x1000).with_name("recv");
        let classified = builder.auto_classify(f);
        assert!(classified.is_source);
        assert_eq!(classified.source_taint, taint_bits::NETWORK);
    }

    #[test]
    fn test_summary_builder_auto_classify_sanitizer() {
        let mut builder = SummaryBuilder::new();
        let f = FunctionTaintSummary::new(0x2000).with_name("escape_string");
        let classified = builder.auto_classify(f);
        assert!(!classified.sanitizers.is_empty());
    }

    #[test]
    fn test_summary_builder_build() {
        let mut builder = SummaryBuilder::new();
        builder.add_function(FunctionTaintSummary::new(0x1000).with_name("test_fn"));
        let ts = builder.build();
        assert_eq!(ts.total_analyzed, 1);
        assert!(ts.by_name("test_fn").is_some());
    }

    #[test]
    fn test_sanitizer_kind_as_str() {
        assert_eq!(SanitizerKind::PreparedStatement.as_str(), "prepared_statement");
        assert_eq!(SanitizerKind::Custom("x".into()).as_str(), "x");
    }

    #[test]
    fn test_sanitizer_record_construction() {
        let rec = SanitizerRecord::new(
            SanitizerKind::BoundsCheck,
            "check_bounds",
            0x5000,
            taint_bits::USER_INPUT,
        );
        assert_eq!(rec.address, 0x5000);
        assert_eq!(rec.cleared_taint, taint_bits::USER_INPUT);
    }
}
