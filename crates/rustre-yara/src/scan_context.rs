//! Per-scan state and condition evaluation for the YARA engine.
//!
//! [`ScanCtx`] holds all state accumulated during a single scan: matched
//! strings with offsets, loaded modules, external variables, and per-rule
//! timeout enforcement.  [`ScanResult`] aggregates all matched rules after
//! the scan completes.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// The scan exceeded the timeout.
    Timeout,
    /// An external variable is referenced but not defined.
    UndefinedVariable(String),
    /// Type mismatch when evaluating a condition.
    TypeError { expected: &'static str, found: &'static str },
    /// Module failed to load.
    ModuleError(String),
    /// Internal engine error.
    InternalError(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "scan timed out"),
            Self::UndefinedVariable(v) => write!(f, "undefined variable: {v}"),
            Self::TypeError { expected, found } => {
                write!(f, "type error: expected {expected}, found {found}")
            }
            Self::ModuleError(m) => write!(f, "module error: {m}"),
            Self::InternalError(e) => write!(f, "internal error: {e}"),
        }
    }
}

pub type ScanResult_<T> = Result<T, ScanError>;

// ── External variable ─────────────────────────────────────────────────────────

/// Value of an external (user-supplied) variable.
#[derive(Debug, Clone, PartialEq)]
pub enum ExternalVar {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
}

impl ExternalVar {
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Bool(_) => "bool",
            Self::Str(_) => "string",
        }
    }

    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            Self::Int(n) => Some(*n != 0),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }
}

impl fmt::Display for ExternalVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Str(s) => write!(f, "\"{s}\""),
        }
    }
}

// ── Match record ──────────────────────────────────────────────────────────────

/// One occurrence of a string match within the scanned data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchRecord {
    /// String identifier (e.g. `$a`).
    pub string_id: String,
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// Length of the matched bytes.
    pub length: usize,
    /// Optional: the actual matched bytes (for small matches).
    pub data: Option<Vec<u8>>,
    /// XOR key used, if any.
    pub xor_key: Option<u8>,
}

impl MatchRecord {
    #[must_use]
    pub fn new(string_id: impl Into<String>, offset: usize, length: usize) -> Self {
        Self {
            string_id: string_id.into(),
            offset,
            length,
            data: None,
            xor_key: None,
        }
    }

    #[must_use]
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    #[must_use]
    pub const fn with_xor_key(mut self, key: u8) -> Self {
        self.xor_key = Some(key);
        self
    }

    #[must_use]
    pub const fn end_offset(&self) -> usize {
        self.offset + self.length
    }
}

impl fmt::Display for MatchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} @ 0x{:x} len={}", self.string_id, self.offset, self.length)?;
        if let Some(key) = self.xor_key {
            write!(f, " xor=0x{key:02x}")?;
        }
        Ok(())
    }
}

// ── Rule match ────────────────────────────────────────────────────────────────

/// A rule that matched during the scan.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Rule name.
    pub rule_name: String,
    /// Rule namespace (empty string = default namespace).
    pub namespace: String,
    /// Tags associated with the rule.
    pub tags: Vec<String>,
    /// All string matches that contributed to this rule firing.
    pub string_matches: Vec<MatchRecord>,
    /// Wall-clock time at which the rule fired.
    pub matched_at: Option<Duration>,
    /// Metadata key-value pairs from the rule.
    pub meta: HashMap<String, String>,
}

impl RuleMatch {
    #[must_use]
    pub fn new(rule_name: impl Into<String>) -> Self {
        Self {
            rule_name: rule_name.into(),
            namespace: String::new(),
            tags: Vec::new(),
            string_matches: Vec::new(),
            matched_at: None,
            meta: HashMap::new(),
        }
    }

    /// Returns `true` if the string `$id` matched at least once.
    #[must_use]
    pub fn has_string_match(&self, id: &str) -> bool {
        self.string_matches.iter().any(|m| m.string_id == id)
    }

    /// Returns all match offsets for string `$id`.
    #[must_use]
    pub fn offsets_for(&self, id: &str) -> Vec<usize> {
        self.string_matches
            .iter()
            .filter(|m| m.string_id == id)
            .map(|m| m.offset)
            .collect()
    }

    /// Number of distinct strings that matched.
    #[must_use]
    pub fn matched_string_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for m in &self.string_matches {
            seen.insert(&m.string_id);
        }
        seen.len()
    }
}

impl fmt::Display for RuleMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule {} matched ({} string hits)", self.rule_name, self.string_matches.len())
    }
}

// ── Module data ───────────────────────────────────────────────────────────────

/// Data provided by a loaded YARA module (e.g. `pe`, `elf`, `math`).
#[derive(Debug, Clone)]
pub struct ModuleData {
    pub name: String,
    pub fields: HashMap<String, serde_json::Value>,
}

impl ModuleData {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), fields: HashMap::new() }
    }

    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.fields.insert(key.into(), value);
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.fields.get(key)
    }

    #[must_use]
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.fields.get(key)?.as_i64()
    }

    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.fields.get(key)?.as_str()
    }
}

// ── Scan config ───────────────────────────────────────────────────────────────

/// Configuration for a single scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Maximum number of matches per string (0 = unlimited).
    pub max_matches_per_string: usize,
    /// Per-scan timeout.
    pub timeout: Option<Duration>,
    /// Per-rule timeout.
    pub rule_timeout: Option<Duration>,
    /// Whether to collect match data (the actual bytes).
    pub collect_match_data: bool,
    /// Maximum size of match data to collect (bytes).
    pub max_match_data: usize,
    /// Whether to continue scanning after the first rule match.
    pub scan_all_rules: bool,
    /// Offset within the buffer to start scanning.
    pub scan_offset: usize,
    /// Maximum bytes to scan (0 = all).
    pub scan_limit: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_matches_per_string: 0,
            timeout: None,
            rule_timeout: None,
            collect_match_data: false,
            max_match_data: 512,
            scan_all_rules: true,
            scan_offset: 0,
            scan_limit: 0,
        }
    }
}

impl ScanConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    #[must_use]
    pub const fn with_max_matches(mut self, n: usize) -> Self {
        self.max_matches_per_string = n;
        self
    }

    #[must_use]
    pub const fn collecting_data(mut self) -> Self {
        self.collect_match_data = true;
        self
    }
}

// ── ScanCtx ───────────────────────────────────────────────────────────────────

/// Per-scan execution context.
///
/// Created once per scan and updated as the engine processes each rule.
pub struct ScanCtx {
    pub config: ScanConfig,
    /// External variables provided by the caller.
    external_vars: HashMap<String, ExternalVar>,
    /// Loaded module data.
    modules: HashMap<String, ModuleData>,
    /// String matches accumulated so far.
    /// Key = `string_id`, value = list of match records.
    string_matches: HashMap<String, Vec<MatchRecord>>,
    /// Rules that have fired.
    matched_rules: Vec<RuleMatch>,
    /// Rules that were evaluated but did not match.
    non_matched_rules: Vec<String>,
    /// Start time of the scan.
    start_time: Instant,
    /// Number of bytes scanned.
    pub bytes_scanned: usize,
    /// Number of rules evaluated.
    pub rules_evaluated: usize,
}

impl ScanCtx {
    #[must_use]
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            external_vars: HashMap::new(),
            modules: HashMap::new(),
            string_matches: HashMap::new(),
            matched_rules: Vec::new(),
            non_matched_rules: Vec::new(),
            start_time: Instant::now(),
            bytes_scanned: 0,
            rules_evaluated: 0,
        }
    }

    // ── External variables ────────────────────────────────────────────────

    pub fn define_var(&mut self, name: impl Into<String>, value: ExternalVar) {
        self.external_vars.insert(name.into(), value);
    }

    #[must_use]
    pub fn get_var(&self, name: &str) -> Option<&ExternalVar> {
        self.external_vars.get(name)
    }

    /// # Errors
    ///
    /// Returns [`ScanError::UndefinedVariable`] if no variable named `name` is defined.
    pub fn require_var(&self, name: &str) -> ScanResult_<&ExternalVar> {
        self.external_vars
            .get(name)
            .ok_or_else(|| ScanError::UndefinedVariable(name.to_owned()))
    }

    // ── Modules ───────────────────────────────────────────────────────────

    pub fn load_module(&mut self, data: ModuleData) {
        self.modules.insert(data.name.clone(), data);
    }

    #[must_use]
    pub fn module(&self, name: &str) -> Option<&ModuleData> {
        self.modules.get(name)
    }

    // ── String matches ────────────────────────────────────────────────────

    pub fn record_match(&mut self, m: MatchRecord) {
        let list = self.string_matches.entry(m.string_id.clone()).or_default();
        if self.config.max_matches_per_string == 0
            || list.len() < self.config.max_matches_per_string
        {
            list.push(m);
        }
    }

    #[must_use]
    pub fn matches_for(&self, string_id: &str) -> &[MatchRecord] {
        self.string_matches
            .get(string_id)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn match_count(&self, string_id: &str) -> usize {
        self.matches_for(string_id).len()
    }

    #[must_use]
    pub fn string_matched(&self, string_id: &str) -> bool {
        !self.matches_for(string_id).is_empty()
    }

    // ── Rule recording ────────────────────────────────────────────────────

    pub fn record_rule_match(&mut self, m: RuleMatch) {
        self.matched_rules.push(m);
    }

    pub fn record_non_match(&mut self, rule_name: impl Into<String>) {
        self.non_matched_rules.push(rule_name.into());
    }

    #[must_use]
    pub fn matched_rules(&self) -> &[RuleMatch] {
        &self.matched_rules
    }

    #[must_use]
    pub fn rule_matched(&self, name: &str) -> bool {
        self.matched_rules.iter().any(|r| r.rule_name == name)
    }

    // ── Timeout ───────────────────────────────────────────────────────────

    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.config.timeout.is_some_and(|limit| self.elapsed() > limit)
    }

    /// # Errors
    ///
    /// Returns [`ScanError::Timeout`] if the scan has exceeded its time limit.
    pub fn check_timeout(&self) -> ScanResult_<()> {
        if self.timed_out() {
            Err(ScanError::Timeout)
        } else {
            Ok(())
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────

    #[must_use]
    pub fn into_result(self) -> ScanResult {
        let timed_out = self.timed_out();
        let elapsed = self.start_time.elapsed();
        ScanResult {
            matched_rules: self.matched_rules,
            elapsed,
            bytes_scanned: self.bytes_scanned,
            rules_evaluated: self.rules_evaluated,
            timed_out,
        }
    }
}

impl fmt::Debug for ScanCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanCtx")
            .field("bytes_scanned", &self.bytes_scanned)
            .field("rules_evaluated", &self.rules_evaluated)
            .field("matched_rules", &self.matched_rules.len())
            .field("elapsed_ms", &self.elapsed().as_millis())
            .finish_non_exhaustive()
    }
}

// ── ScanResult ────────────────────────────────────────────────────────────────

/// The output of a completed scan.
#[derive(Debug, Default)]
pub struct ScanResult {
    pub matched_rules: Vec<RuleMatch>,
    pub elapsed: Duration,
    pub bytes_scanned: usize,
    pub rules_evaluated: usize,
    pub timed_out: bool,
}

impl ScanResult {
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matched_rules.len()
    }

    #[must_use]
    pub fn has_match(&self, rule_name: &str) -> bool {
        self.matched_rules.iter().any(|r| r.rule_name == rule_name)
    }

    #[must_use]
    pub fn rule_names(&self) -> Vec<&str> {
        self.matched_rules.iter().map(|r| r.rule_name.as_str()).collect()
    }

    /// All matches tagged with at least one of the given tags.
    #[must_use]
    pub fn matches_with_tag(&self, tag: &str) -> Vec<&RuleMatch> {
        self.matched_rules
            .iter()
            .filter(|r| r.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Throughput in MiB/s.
    #[must_use]
    pub fn throughput_mib_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs < 1e-9 { return 0.0; }
        (f64::from(u32::try_from(self.bytes_scanned).unwrap_or(u32::MAX))) / (1024.0 * 1024.0) / secs
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matched_rules.is_empty()
    }
}

impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ScanResult: {} rules matched, {} bytes in {:?} ({:.1} MiB/s){}",
            self.match_count(),
            self.bytes_scanned,
            self.elapsed,
            self.throughput_mib_per_sec(),
            if self.timed_out { " [TIMED OUT]" } else { "" },
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_var() {
        let mut ctx = ScanCtx::new(ScanConfig::default());
        ctx.define_var("is_pe", ExternalVar::Bool(true));
        assert_eq!(ctx.get_var("is_pe"), Some(&ExternalVar::Bool(true)));
        assert!(ctx.require_var("missing").is_err());
    }

    #[test]
    fn test_record_match() {
        let mut ctx = ScanCtx::new(ScanConfig::default());
        ctx.record_match(MatchRecord::new("$a", 0x100, 5));
        ctx.record_match(MatchRecord::new("$a", 0x200, 5));
        assert_eq!(ctx.match_count("$a"), 2);
        assert!(ctx.string_matched("$a"));
        assert!(!ctx.string_matched("$b"));
    }

    #[test]
    fn test_max_matches() {
        let cfg = ScanConfig::new().with_max_matches(2);
        let mut ctx = ScanCtx::new(cfg);
        for i in 0..10 {
            ctx.record_match(MatchRecord::new("$x", i * 10, 4));
        }
        assert_eq!(ctx.match_count("$x"), 2);
    }

    #[test]
    fn test_rule_match() {
        let mut ctx = ScanCtx::new(ScanConfig::default());
        let mut rm = RuleMatch::new("my_rule");
        rm.string_matches.push(MatchRecord::new("$a", 0, 4));
        ctx.record_rule_match(rm);
        assert!(ctx.rule_matched("my_rule"));
        assert!(!ctx.rule_matched("other_rule"));
    }

    #[test]
    fn test_into_result() {
        let mut ctx = ScanCtx::new(ScanConfig::default());
        ctx.bytes_scanned = 1024 * 1024;
        ctx.rules_evaluated = 10;
        ctx.record_rule_match(RuleMatch::new("r1"));
        let result = ctx.into_result();
        assert_eq!(result.match_count(), 1);
        assert_eq!(result.bytes_scanned, 1024 * 1024);
    }

    #[test]
    fn test_match_record_display() {
        let m = MatchRecord::new("$key", 0x1000, 16).with_xor_key(0xAB);
        let s = m.to_string();
        assert!(s.contains("$key"));
        assert!(s.contains("0xab"));
    }

    #[test]
    fn test_timeout() {
        let cfg = ScanConfig::new().with_timeout(Duration::from_nanos(1));
        let ctx = ScanCtx::new(cfg);
        std::thread::sleep(Duration::from_millis(1));
        assert!(ctx.timed_out());
        assert!(ctx.check_timeout().is_err());
    }

    #[test]
    fn test_scan_result_display() {
        let r = ScanResult {
            matched_rules: Vec::new(),
            elapsed: Duration::from_millis(100),
            bytes_scanned: 1024,
            rules_evaluated: 5,
            timed_out: false,
        };
        let s = r.to_string();
        assert!(s.contains("0 rules matched"));
    }

    #[test]
    fn test_module_data() {
        let mut m = ModuleData::new("pe");
        m.set("machine", serde_json::json!("x86"));
        assert_eq!(m.get_str("machine"), Some("x86"));
        assert_eq!(m.get_int("machine"), None);
    }
}
