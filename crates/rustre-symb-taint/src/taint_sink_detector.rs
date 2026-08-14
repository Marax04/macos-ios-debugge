//! Taint sink detector: identify dangerous sinks reached by tainted data.
//!
//! `TaintSinkDetector` maintains a configurable database of known dangerous call
//! sites and memory patterns. When a tainted value reaches one of these sinks,
//! a `TaintedSink` finding is emitted and aggregated in a `SinkReport`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{TaintId, TaintLocation, FindingType, taint_bits};

// ─── SinkKind ────────────────────────────────────────────────────────────────

/// Classification of a dangerous sink.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkKind {
    /// shell/exec call with tainted command string.
    CommandExecution,
    /// printf/sprintf with tainted format string.
    FormatString,
    /// memcpy/strcpy with tainted length or source.
    BufferOverflow,
    /// SQL execution with tainted query text.
    SqlInjection,
    /// File open/rename with tainted path.
    PathTraversal,
    /// Free of a tainted pointer.
    UseAfterFree,
    /// Conditional branch with tainted condition.
    TaintedCondition,
    /// Integer arithmetic that may overflow.
    IntegerOverflow,
    /// Network send with tainted payload.
    NetworkEgress,
    /// Custom user-defined sink kind.
    Custom(String),
}

impl SinkKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::CommandExecution => "command_execution",
            Self::FormatString => "format_string",
            Self::BufferOverflow => "buffer_overflow",
            Self::SqlInjection => "sql_injection",
            Self::PathTraversal => "path_traversal",
            Self::UseAfterFree => "use_after_free",
            Self::TaintedCondition => "tainted_condition",
            Self::IntegerOverflow => "integer_overflow",
            Self::NetworkEgress => "network_egress",
            Self::Custom(s) => s.as_str(),
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            Self::CommandExecution => 100,
            Self::BufferOverflow => 95,
            Self::FormatString => 90,
            Self::UseAfterFree => 88,
            Self::SqlInjection => 85,
            Self::PathTraversal => 75,
            Self::NetworkEgress => 60,
            Self::IntegerOverflow => 55,
            Self::TaintedCondition => 45,
            Self::Custom(_) => 50,
        }
    }

    /// Map to the legacy `FindingType`.
    pub fn to_finding_type(&self) -> FindingType {
        match self {
            Self::CommandExecution => FindingType::CommandInjection,
            Self::FormatString => FindingType::FormatString,
            Self::BufferOverflow => FindingType::BufferOverflow,
            Self::SqlInjection => FindingType::SqlInjection,
            Self::PathTraversal => FindingType::PathTraversal,
            Self::UseAfterFree => FindingType::UseAfterFree,
            Self::TaintedCondition => FindingType::TaintedCondition,
            Self::IntegerOverflow => FindingType::IntegerOverflow,
            Self::NetworkEgress => FindingType::Custom("network_egress".into()),
            Self::Custom(s) => FindingType::Custom(s.clone()),
        }
    }
}

// ─── SinkSpec ────────────────────────────────────────────────────────────────

/// Specification of a single dangerous sink (function name + relevant arg indices).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkSpec {
    /// Function name that represents the sink.
    pub function_name: String,
    /// Kind of sink.
    pub kind: SinkKind,
    /// Which argument positions are considered taint-sensitive.
    pub sensitive_args: Vec<usize>,
    /// Human-readable description.
    pub description: String,
}

impl SinkSpec {
    pub fn new(
        function_name: impl Into<String>,
        kind: SinkKind,
        sensitive_args: Vec<usize>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            kind,
            sensitive_args,
            description: description.into(),
        }
    }
}

// ─── TaintedSink ────────────────────────────────────────────────────────────

/// A single occurrence of tainted data reaching a dangerous sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedSink {
    /// Address of the sink call site.
    pub address: u64,
    /// The sink kind.
    pub kind: SinkKind,
    /// Which taint sources are involved.
    pub taint_sources: TaintId,
    /// The tainted argument position (if a call sink).
    pub argument_index: Option<usize>,
    /// The location of the tainted value.
    pub location: TaintLocation,
    /// Human-readable summary.
    pub summary: String,
    /// Severity score 0–100.
    pub severity: u8,
}

impl TaintedSink {
    pub fn new(
        address: u64,
        kind: SinkKind,
        taint_sources: TaintId,
        location: TaintLocation,
        summary: impl Into<String>,
    ) -> Self {
        let severity = kind.severity();
        Self {
            address,
            kind,
            taint_sources,
            argument_index: None,
            location,
            summary: summary.into(),
            severity,
        }
    }

    pub fn with_arg(mut self, idx: usize) -> Self {
        self.argument_index = Some(idx);
        self
    }

    pub fn is_critical(&self) -> bool {
        self.severity >= 90
    }

    pub fn source_name(&self) -> &'static str {
        if taint_bits::has_bit(self.taint_sources, taint_bits::USER_INPUT) {
            "user_input"
        } else if taint_bits::has_bit(self.taint_sources, taint_bits::NETWORK) {
            "network"
        } else if taint_bits::has_bit(self.taint_sources, taint_bits::FILE) {
            "file"
        } else if taint_bits::has_bit(self.taint_sources, taint_bits::ENVIRONMENT) {
            "environment"
        } else if taint_bits::has_bit(self.taint_sources, taint_bits::COMMAND_LINE) {
            "command_line"
        } else {
            "unknown"
        }
    }
}

// ─── SinkReport ──────────────────────────────────────────────────────────────

/// Aggregated results from a sink detection pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SinkReport {
    pub sinks: Vec<TaintedSink>,
    pub total_instructions_analyzed: u64,
    pub unique_sink_kinds: Vec<SinkKind>,
}

impl SinkReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, sink: TaintedSink) {
        if !self.unique_sink_kinds.contains(&sink.kind) {
            self.unique_sink_kinds.push(sink.kind.clone());
        }
        self.sinks.push(sink);
    }

    pub fn count(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    pub fn critical_sinks(&self) -> Vec<&TaintedSink> {
        self.sinks.iter().filter(|s| s.is_critical()).collect()
    }

    pub fn by_kind(&self, kind: &SinkKind) -> Vec<&TaintedSink> {
        self.sinks.iter().filter(|s| &s.kind == kind).collect()
    }

    pub fn max_severity(&self) -> u8 {
        self.sinks.iter().map(|s| s.severity).max().unwrap_or(0)
    }

    pub fn severity_counts(&self) -> HashMap<u8, usize> {
        let mut map = HashMap::new();
        for s in &self.sinks {
            *map.entry(s.severity).or_insert(0) += 1;
        }
        map
    }

    pub fn sinks_at_address(&self, addr: u64) -> Vec<&TaintedSink> {
        self.sinks.iter().filter(|s| s.address == addr).collect()
    }

    /// Return a summary suitable for display.
    pub fn summary_text(&self) -> String {
        if self.sinks.is_empty() {
            return "No tainted sinks detected.".into();
        }
        let mut lines = vec![format!("Detected {} tainted sink(s):", self.sinks.len())];
        for s in &self.sinks {
            lines.push(format!(
                "  [{:3}] 0x{:x}  {:?}  — {}",
                s.severity, s.address, s.kind, s.summary
            ));
        }
        lines.join("\n")
    }
}

// ─── TaintSinkDetector ───────────────────────────────────────────────────────

/// Detects dangerous taint sinks in a stream of tainted calls and conditions.
pub struct TaintSinkDetector {
    /// Registered sink specs, keyed by function name.
    specs: HashMap<String, SinkSpec>,
    /// Collected findings.
    report: SinkReport,
    /// Minimum severity to record (default 0 = record all).
    pub min_severity: u8,
}

impl TaintSinkDetector {
    /// Create an empty detector.
    pub fn new() -> Self {
        Self {
            specs: HashMap::new(),
            report: SinkReport::new(),
            min_severity: 0,
        }
    }

    /// Create a detector pre-loaded with the standard sink database.
    pub fn with_standard_sinks() -> Self {
        let mut d = Self::new();
        d.load_standard_sinks();
        d
    }

    /// Register a custom sink spec.
    pub fn register_sink(&mut self, spec: SinkSpec) {
        self.specs.insert(spec.function_name.clone(), spec);
    }

    /// Remove a sink spec by function name.
    pub fn remove_sink(&mut self, name: &str) -> bool {
        self.specs.remove(name).is_some()
    }

    /// Check if a function call with the given tainted arguments hits a sink.
    /// Returns `Some(TaintedSink)` if a finding is generated.
    pub fn check_call(
        &mut self,
        function_name: &str,
        arg_taints: &[TaintId],
        call_address: u64,
    ) -> Option<TaintedSink> {
        let spec = self.specs.get(function_name)?.clone();
        for &arg_idx in &spec.sensitive_args {
            let taint = arg_taints.get(arg_idx).copied().unwrap_or(taint_bits::NONE);
            if taint_bits::is_tainted(taint) {
                let summary = format!(
                    "Tainted arg[{arg_idx}] flows into {} ({:?}): {}",
                    function_name, spec.kind, spec.description
                );
                let location = TaintLocation::Argument(arg_idx);
                let sink = TaintedSink::new(call_address, spec.kind.clone(), taint, location, summary)
                    .with_arg(arg_idx);
                if sink.severity >= self.min_severity {
                    self.report.add(sink.clone());
                    return Some(sink);
                }
            }
        }
        None
    }

    /// Check if a tainted condition influences a branch (control-flow taint).
    pub fn check_branch_condition(
        &mut self,
        condition_taint: TaintId,
        branch_address: u64,
    ) -> Option<TaintedSink> {
        if !taint_bits::is_tainted(condition_taint) {
            return None;
        }
        let sink = TaintedSink::new(
            branch_address,
            SinkKind::TaintedCondition,
            condition_taint,
            TaintLocation::Register("flags".into()),
            "Tainted value controls branch condition",
        );
        if sink.severity >= self.min_severity {
            self.report.add(sink.clone());
            Some(sink)
        } else {
            None
        }
    }

    /// Check a memory write where either address or size is tainted.
    pub fn check_memory_write(
        &mut self,
        address_taint: TaintId,
        size_taint: TaintId,
        value_taint: TaintId,
        instr_addr: u64,
    ) -> Option<TaintedSink> {
        if taint_bits::is_tainted(size_taint) {
            let combined = size_taint | value_taint;
            let sink = TaintedSink::new(
                instr_addr,
                SinkKind::BufferOverflow,
                combined,
                TaintLocation::Register("size_reg".into()),
                "Tainted size in memory write — potential buffer overflow",
            );
            if sink.severity >= self.min_severity {
                self.report.add(sink.clone());
                return Some(sink);
            }
        }
        if taint_bits::is_tainted(address_taint) && !taint_bits::is_tainted(size_taint) {
            let sink = TaintedSink::new(
                instr_addr,
                SinkKind::PathTraversal,
                address_taint,
                TaintLocation::Memory(instr_addr),
                "Tainted address in memory write",
            );
            if sink.severity >= self.min_severity {
                self.report.add(sink.clone());
                return Some(sink);
            }
        }
        None
    }

    /// Return the accumulated sink report.
    pub fn report(&self) -> &SinkReport {
        &self.report
    }

    /// Take the report, leaving an empty one in its place.
    pub fn take_report(&mut self) -> SinkReport {
        std::mem::take(&mut self.report)
    }

    /// Number of registered sink specs.
    pub fn spec_count(&self) -> usize {
        self.specs.len()
    }

    /// Check if a function name is a registered sink.
    pub fn is_sink(&self, name: &str) -> bool {
        self.specs.contains_key(name)
    }

    /// Load the standard sink database for C/Win32 APIs.
    fn load_standard_sinks(&mut self) {
        let sinks = vec![
            // Command execution
            SinkSpec::new("system", SinkKind::CommandExecution, vec![0],
                "POSIX system(): executes a shell command"),
            SinkSpec::new("execve", SinkKind::CommandExecution, vec![0],
                "POSIX execve(): replaces process image"),
            SinkSpec::new("execl", SinkKind::CommandExecution, vec![0],
                "POSIX execl(): replaces process image"),
            SinkSpec::new("execvp", SinkKind::CommandExecution, vec![0],
                "POSIX execvp()"),
            SinkSpec::new("popen", SinkKind::CommandExecution, vec![0],
                "POSIX popen(): open a pipe to a shell command"),
            SinkSpec::new("WinExec", SinkKind::CommandExecution, vec![0],
                "Win32 WinExec()"),
            SinkSpec::new("ShellExecute", SinkKind::CommandExecution, vec![2, 3],
                "Win32 ShellExecute()"),
            SinkSpec::new("CreateProcess", SinkKind::CommandExecution, vec![1],
                "Win32 CreateProcess()"),
            // Format string
            SinkSpec::new("printf", SinkKind::FormatString, vec![0],
                "printf(): first argument is the format string"),
            SinkSpec::new("fprintf", SinkKind::FormatString, vec![1],
                "fprintf(): second argument is the format string"),
            SinkSpec::new("sprintf", SinkKind::FormatString, vec![1],
                "sprintf(): second argument is the format string"),
            SinkSpec::new("snprintf", SinkKind::FormatString, vec![2],
                "snprintf(): third argument is the format string"),
            SinkSpec::new("vprintf", SinkKind::FormatString, vec![0],
                "vprintf(): format string"),
            SinkSpec::new("vsprintf", SinkKind::FormatString, vec![1],
                "vsprintf(): format string"),
            // Buffer overflow
            SinkSpec::new("memcpy", SinkKind::BufferOverflow, vec![2],
                "memcpy(): third argument is size"),
            SinkSpec::new("memmove", SinkKind::BufferOverflow, vec![2],
                "memmove(): third argument is size"),
            SinkSpec::new("strcpy", SinkKind::BufferOverflow, vec![1],
                "strcpy(): unsafe copy with no length limit"),
            SinkSpec::new("strcat", SinkKind::BufferOverflow, vec![1],
                "strcat(): unsafe append"),
            SinkSpec::new("gets", SinkKind::BufferOverflow, vec![0],
                "gets(): inherently unsafe input function"),
            SinkSpec::new("scanf", SinkKind::BufferOverflow, vec![0],
                "scanf(): format-controlled input"),
            // SQL injection
            SinkSpec::new("sqlite3_exec", SinkKind::SqlInjection, vec![1],
                "SQLite sqlite3_exec()"),
            SinkSpec::new("mysql_query", SinkKind::SqlInjection, vec![1],
                "MySQL mysql_query()"),
            SinkSpec::new("PQexec", SinkKind::SqlInjection, vec![1],
                "PostgreSQL PQexec()"),
            SinkSpec::new("sql_exec", SinkKind::SqlInjection, vec![1],
                "Generic sql_exec()"),
            // Path traversal
            SinkSpec::new("fopen", SinkKind::PathTraversal, vec![0],
                "fopen(): path argument"),
            SinkSpec::new("open", SinkKind::PathTraversal, vec![0],
                "POSIX open(): path argument"),
            SinkSpec::new("CreateFile", SinkKind::PathTraversal, vec![0],
                "Win32 CreateFile(): path argument"),
            SinkSpec::new("unlink", SinkKind::PathTraversal, vec![0],
                "POSIX unlink(): path argument"),
            SinkSpec::new("rename", SinkKind::PathTraversal, vec![0, 1],
                "rename(): both path arguments"),
            SinkSpec::new("mkdir", SinkKind::PathTraversal, vec![0],
                "mkdir(): path argument"),
            // Network egress
            SinkSpec::new("send", SinkKind::NetworkEgress, vec![1, 2],
                "POSIX send(): payload and length"),
            SinkSpec::new("sendto", SinkKind::NetworkEgress, vec![1, 2],
                "POSIX sendto(): payload and length"),
            SinkSpec::new("write", SinkKind::NetworkEgress, vec![1, 2],
                "POSIX write() on a socket fd"),
        ];
        for spec in sinks {
            self.register_sink(spec);
        }
    }
}

impl Default for TaintSinkDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sink_kind_severity() {
        assert_eq!(SinkKind::CommandExecution.severity(), 100);
        assert_eq!(SinkKind::TaintedCondition.severity(), 45);
        assert!(SinkKind::CommandExecution.severity() > SinkKind::PathTraversal.severity());
    }

    #[test]
    fn test_sink_kind_to_finding_type() {
        assert_eq!(SinkKind::CommandExecution.to_finding_type(), FindingType::CommandInjection);
        assert_eq!(SinkKind::FormatString.to_finding_type(), FindingType::FormatString);
    }

    #[test]
    fn test_tainted_sink_is_critical() {
        let s = TaintedSink::new(0x1000, SinkKind::CommandExecution, taint_bits::USER_INPUT,
            TaintLocation::Argument(0), "cmd inj");
        assert!(s.is_critical());
        let low = TaintedSink::new(0x1001, SinkKind::TaintedCondition, taint_bits::USER_INPUT,
            TaintLocation::Argument(0), "cond");
        assert!(!low.is_critical());
    }

    #[test]
    fn test_tainted_sink_source_name() {
        let s = TaintedSink::new(0, SinkKind::FormatString, taint_bits::NETWORK,
            TaintLocation::Argument(0), "");
        assert_eq!(s.source_name(), "network");
    }

    #[test]
    fn test_sink_report_add_and_count() {
        let mut report = SinkReport::new();
        report.add(TaintedSink::new(0x1000, SinkKind::FormatString, taint_bits::USER_INPUT,
            TaintLocation::Argument(0), "fmt"));
        assert_eq!(report.count(), 1);
        assert!(!report.is_empty());
    }

    #[test]
    fn test_sink_report_critical_sinks() {
        let mut report = SinkReport::new();
        report.add(TaintedSink::new(0x1000, SinkKind::CommandExecution, taint_bits::USER_INPUT,
            TaintLocation::Argument(0), "cmd"));
        report.add(TaintedSink::new(0x2000, SinkKind::TaintedCondition, taint_bits::USER_INPUT,
            TaintLocation::Register("rax".into()), "cond"));
        assert_eq!(report.critical_sinks().len(), 1);
    }

    #[test]
    fn test_sink_report_by_kind() {
        let mut report = SinkReport::new();
        report.add(TaintedSink::new(0, SinkKind::SqlInjection, taint_bits::USER_INPUT,
            TaintLocation::Argument(1), "sql"));
        report.add(TaintedSink::new(0, SinkKind::FormatString, taint_bits::NETWORK,
            TaintLocation::Argument(0), "fmt"));
        assert_eq!(report.by_kind(&SinkKind::SqlInjection).len(), 1);
        assert_eq!(report.by_kind(&SinkKind::FormatString).len(), 1);
        assert_eq!(report.by_kind(&SinkKind::BufferOverflow).len(), 0);
    }

    #[test]
    fn test_sink_report_max_severity() {
        let mut report = SinkReport::new();
        report.add(TaintedSink::new(0, SinkKind::PathTraversal, taint_bits::FILE,
            TaintLocation::Argument(0), "path"));
        report.add(TaintedSink::new(0, SinkKind::CommandExecution, taint_bits::USER_INPUT,
            TaintLocation::Argument(0), "cmd"));
        assert_eq!(report.max_severity(), 100);
    }

    #[test]
    fn test_detector_standard_sinks_loaded() {
        let d = TaintSinkDetector::with_standard_sinks();
        assert!(d.is_sink("system"));
        assert!(d.is_sink("printf"));
        assert!(d.is_sink("sqlite3_exec"));
        assert!(!d.is_sink("strlen"));
    }

    #[test]
    fn test_detector_check_call_format_string() {
        let mut d = TaintSinkDetector::with_standard_sinks();
        let finding = d.check_call("printf", &[taint_bits::USER_INPUT], 0x1000);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert_eq!(f.kind, SinkKind::FormatString);
        assert_eq!(f.argument_index, Some(0));
    }

    #[test]
    fn test_detector_check_call_clean_args() {
        let mut d = TaintSinkDetector::with_standard_sinks();
        let finding = d.check_call("system", &[taint_bits::NONE], 0x1000);
        assert!(finding.is_none());
    }

    #[test]
    fn test_detector_check_call_unknown_func() {
        let mut d = TaintSinkDetector::with_standard_sinks();
        let finding = d.check_call("strlen", &[taint_bits::USER_INPUT], 0x1000);
        assert!(finding.is_none());
    }

    #[test]
    fn test_detector_check_branch_condition() {
        let mut d = TaintSinkDetector::new();
        let finding = d.check_branch_condition(taint_bits::NETWORK, 0x2000);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().kind, SinkKind::TaintedCondition);
    }

    #[test]
    fn test_detector_check_branch_clean() {
        let mut d = TaintSinkDetector::new();
        assert!(d.check_branch_condition(taint_bits::NONE, 0x2000).is_none());
    }

    #[test]
    fn test_detector_check_memory_write_tainted_size() {
        let mut d = TaintSinkDetector::new();
        let finding = d.check_memory_write(taint_bits::NONE, taint_bits::USER_INPUT, taint_bits::NONE, 0x3000);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().kind, SinkKind::BufferOverflow);
    }

    #[test]
    fn test_detector_take_report() {
        let mut d = TaintSinkDetector::with_standard_sinks();
        d.check_call("printf", &[taint_bits::USER_INPUT], 0x1000);
        let report = d.take_report();
        assert_eq!(report.count(), 1);
        assert_eq!(d.report().count(), 0); // report was taken
    }

    #[test]
    fn test_detector_custom_sink() {
        let mut d = TaintSinkDetector::new();
        d.register_sink(SinkSpec::new("my_dangerous_func", SinkKind::Custom("custom_sink".into()), vec![1], "custom sink"));
        let finding = d.check_call("my_dangerous_func", &[taint_bits::NONE, taint_bits::FILE], 0x5000);
        assert!(finding.is_some());
        assert!(matches!(finding.unwrap().kind, SinkKind::Custom(_)));
    }

    #[test]
    fn test_detector_remove_sink() {
        let mut d = TaintSinkDetector::with_standard_sinks();
        assert!(d.is_sink("system"));
        assert!(d.remove_sink("system"));
        assert!(!d.is_sink("system"));
    }

    #[test]
    fn test_sink_report_summary_text() {
        let mut report = SinkReport::new();
        let text = report.summary_text();
        assert!(text.contains("No tainted"));
        report.add(TaintedSink::new(0x100, SinkKind::FormatString, taint_bits::NETWORK,
            TaintLocation::Argument(0), "test finding"));
        let text2 = report.summary_text();
        assert!(text2.contains("1"));
    }

    #[test]
    fn test_memcpy_tainted_size_arg() {
        let mut d = TaintSinkDetector::with_standard_sinks();
        // memcpy arg 2 = size
        let finding = d.check_call("memcpy",
            &[taint_bits::NONE, taint_bits::NONE, taint_bits::USER_INPUT], 0x6000);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().kind, SinkKind::BufferOverflow);
    }
}
