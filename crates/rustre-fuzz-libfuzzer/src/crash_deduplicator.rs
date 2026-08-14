//! Crash deduplication: normalize stack traces, group crashes by backtrace hash,
//! detect exploitable crashes, compute uniqueness scores, and generate triage reports.
//!
//! Types: [`CrashRecord`], [`StackTrace`], [`BacktraceHash`], [`ExploitabilityRating`],
//! [`CrashGroup`].

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::SystemTime;

// ─── BacktraceHash ────────────────────────────────────────────────────────────

/// A 64-bit FNV-1a hash of a normalized stack trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BacktraceHash(pub u64);

impl BacktraceHash {
    /// Compute the hash from a slice of normalized frame strings.
    #[must_use]
    pub fn of(frames: &[String]) -> Self {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = OFFSET;
        for frame in frames {
            for &b in frame.as_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(PRIME);
            }
            // Frame separator.
            h ^= 0xff;
            h = h.wrapping_mul(PRIME);
        }
        Self(h)
    }

    /// Compute the hash from a single raw trace string.
    #[must_use]
    pub fn of_raw(raw: &str) -> Self {
        Self::of(&[raw.to_string()])
    }
}

impl fmt::Display for BacktraceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

// ─── StackFrame ──────────────────────────────────────────────────────────────

/// A single frame in a stack trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    /// Module name (e.g. `libc.so.6`).
    pub module: Option<String>,
    /// Function name.
    pub function: Option<String>,
    /// Source file path.
    pub source_file: Option<String>,
    /// Source line number.
    pub source_line: Option<u32>,
    /// Absolute instruction address.
    pub address: Option<u64>,
    /// Offset within the function.
    pub offset: Option<u64>,
}

impl StackFrame {
    /// Create a minimal frame from a function name.
    #[must_use]
    pub fn from_function(function: impl Into<String>) -> Self {
        Self {
            module: None,
            function: Some(function.into()),
            source_file: None,
            source_line: None,
            address: None,
            offset: None,
        }
    }

    /// Normalize the frame to a canonical string for hashing.
    ///
    /// Priority: function name > module+offset > address.
    #[must_use]
    pub fn normalized(&self) -> String {
        if let Some(f) = &self.function {
            // Strip address suffixes like `+0x123` or `<inlined>` annotations.
            let base = f.split('+').next().unwrap_or(f).trim();
            let base = base.split('<').next().unwrap_or(base).trim();
            return base.to_string();
        }
        if let (Some(module), Some(offset)) = (&self.module, &self.offset) {
            return format!("{module}+{offset:#x}");
        }
        if let Some(addr) = self.address {
            return format!("{addr:#x}");
        }
        "<unknown>".to_string()
    }

    /// True if this frame represents an OS or runtime artifact (noise).
    #[must_use]
    pub fn is_noise(&self) -> bool {
        let noise_prefixes = [
            "libc", "__libc", "_dl_", "pthread_", "start_thread",
            "__cxa_", "abort", "raise", "kill", "__sanitizer",
            "asan::", "lsan::", "ubsan::",
        ];
        if let Some(f) = &self.function {
            for prefix in &noise_prefixes {
                if f.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }
}

impl fmt::Display for StackFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(func) = &self.function {
            write!(f, "{func}")?;
        } else {
            write!(f, "<unknown>")?;
        }
        if let Some(addr) = self.address {
            write!(f, " @ {addr:#x}")?;
        }
        Ok(())
    }
}

// ─── StackTrace ───────────────────────────────────────────────────────────────

/// A full parsed stack trace.
#[derive(Debug, Clone)]
pub struct StackTrace {
    /// Ordered frames (index 0 = innermost).
    pub frames: Vec<StackFrame>,
    /// Raw text of the trace, if available.
    pub raw: Option<String>,
    /// Number of frames to use for deduplication (top-N).
    pub dedup_depth: usize,
}

impl StackTrace {
    /// Create from a vec of frames.
    #[must_use]
    pub const fn new(frames: Vec<StackFrame>) -> Self {
        Self {
            frames,
            raw: None,
            dedup_depth: 5,
        }
    }

    /// Create a minimal trace from a raw string.
    #[must_use]
    pub fn from_raw(raw: impl Into<String>) -> Self {
        let r = raw.into();
        let frames = r
            .lines()
            .map(|line| StackFrame::from_function(line.trim()))
            .collect();
        Self {
            frames,
            raw: Some(r),
            dedup_depth: 5,
        }
    }

    /// Remove noise frames (runtime / sanitizer internals).
    #[must_use]
    pub fn denoise(&self) -> Self {
        let frames = self.frames.iter().filter(|f| !f.is_noise()).cloned().collect();
        Self {
            frames,
            raw: self.raw.clone(),
            dedup_depth: self.dedup_depth,
        }
    }

    /// Normalize: denoise then take top-N frames, return their normalized strings.
    #[must_use]
    pub fn normalized_frames(&self) -> Vec<String> {
        self.denoise()
            .frames
            .iter()
            .take(self.dedup_depth)
            .map(StackFrame::normalized)
            .collect()
    }

    /// Compute the backtrace hash from the normalized frames.
    #[must_use]
    pub fn backtrace_hash(&self) -> BacktraceHash {
        BacktraceHash::of(&self.normalized_frames())
    }

    /// Length of the trace.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.frames.len()
    }

    /// True if the trace has no frames.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Return the top-N function names as a compact string.
    #[must_use]
    pub fn summary(&self, n: usize) -> String {
        self.frames
            .iter()
            .take(n)
            .map(|f| f.function.as_deref().unwrap_or("<?>"))
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

impl fmt::Display for StackTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, frame) in self.frames.iter().enumerate() {
            writeln!(f, "  #{i:2} {frame}")?;
        }
        Ok(())
    }
}

// ─── ExploitabilityRating ─────────────────────────────────────────────────────

/// Exploitability classification for a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExploitabilityRating {
    /// Not exploitable (e.g. assertion failure, OOM).
    NotExploitable,
    /// Unknown / insufficient info.
    Unknown,
    /// Probably not exploitable (read-only access violation at a safe address).
    ProbablyNotExploitable,
    /// Possibly exploitable (stack overflow, read at user-controlled address).
    PossiblyExploitable,
    /// Exploitable (write at user-controlled address, PC control, type confusion).
    Exploitable,
    /// Critically exploitable (code execution confirmed).
    Critical,
}

impl ExploitabilityRating {
    /// Numeric priority: higher = more severe.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::NotExploitable => 0,
            Self::Unknown => 1,
            Self::ProbablyNotExploitable => 2,
            Self::PossiblyExploitable => 3,
            Self::Exploitable => 4,
            Self::Critical => 5,
        }
    }

    /// True if this rating indicates potential exploitability.
    #[must_use]
    pub const fn is_exploitable(self) -> bool {
        matches!(
            self,
            Self::PossiblyExploitable | Self::Exploitable | Self::Critical
        )
    }
}

impl fmt::Display for ExploitabilityRating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── CrashPattern ─────────────────────────────────────────────────────────────

/// Patterns detected in a crash input that affect exploitability scoring.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CrashPattern {
    /// The crash involves a write to a null/near-null address.
    WriteToNull,
    /// The crash involves a read at an attacker-controlled address.
    ReadAtControlledAddress,
    /// The crash involves a write at an attacker-controlled address.
    WriteAtControlledAddress,
    /// Program counter has been overwritten (function pointer / return address).
    PcCorruption,
    /// Heap buffer overflow detected.
    HeapOverflow,
    /// Stack buffer overflow detected.
    StackOverflow,
    /// Use-after-free detected.
    UseAfterFree,
    /// Type confusion detected.
    TypeConfusion,
    /// Integer overflow in size calculation.
    IntegerOverflow,
    /// Division by zero.
    DivisionByZero,
    /// Assertion failure (typically not exploitable).
    AssertionFailure,
    /// Out-of-memory condition.
    OutOfMemory,
}

impl fmt::Display for CrashPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── ExploitabilityAnalyzer ───────────────────────────────────────────────────

/// Heuristic exploitability analyzer.
pub struct ExploitabilityAnalyzer;

impl ExploitabilityAnalyzer {
    /// Detect patterns in the crash input and trace.
    #[must_use]
    pub fn detect_patterns(
        input: &[u8],
        trace: &StackTrace,
        crash_message: &str,
    ) -> Vec<CrashPattern> {
        let mut patterns = Vec::new();
        let msg_lower = crash_message.to_lowercase();

        // Assertion failure / OOM.
        if msg_lower.contains("assert") || msg_lower.contains("abort") {
            patterns.push(CrashPattern::AssertionFailure);
        }
        if msg_lower.contains("out of memory") || msg_lower.contains("oom") {
            patterns.push(CrashPattern::OutOfMemory);
        }

        // PC corruption.
        if msg_lower.contains("pc") && msg_lower.contains("corrupt") {
            patterns.push(CrashPattern::PcCorruption);
        }
        if msg_lower.contains("segmentation fault") || msg_lower.contains("access violation") {
            // Check if input contains typical PC-hijack patterns.
            if input.windows(8).any(|w| w == b"\x41\x41\x41\x41\x41\x41\x41\x41") {
                patterns.push(CrashPattern::PcCorruption);
            }
        }

        // Write-to-null: trace contains null-deref write frames.
        if msg_lower.contains("write") && (msg_lower.contains("null") || msg_lower.contains("0x0000")) {
            patterns.push(CrashPattern::WriteToNull);
        }

        // Heap overflow.
        if (msg_lower.contains("heap") || trace.frames.iter().any(|f| {
            f.function.as_deref().is_some_and(|fn_name| {
                fn_name.contains("malloc") || fn_name.contains("free") || fn_name.contains("realloc")
            })
        })) && (msg_lower.contains("overflow") || msg_lower.contains("corruption")) {
            patterns.push(CrashPattern::HeapOverflow);
        }

        // Stack overflow.
        if msg_lower.contains("stack") && msg_lower.contains("overflow") {
            patterns.push(CrashPattern::StackOverflow);
        }

        // Use-after-free.
        if msg_lower.contains("use-after-free") || msg_lower.contains("uaf") {
            patterns.push(CrashPattern::UseAfterFree);
        }

        // Type confusion.
        if msg_lower.contains("type confusion") || msg_lower.contains("type_confusion") {
            patterns.push(CrashPattern::TypeConfusion);
        }

        // Integer overflow.
        if msg_lower.contains("integer overflow") || msg_lower.contains("integer-overflow") {
            patterns.push(CrashPattern::IntegerOverflow);
        }

        // Division by zero.
        if msg_lower.contains("division by zero") || msg_lower.contains("divide by zero") {
            patterns.push(CrashPattern::DivisionByZero);
        }

        // Controlled-address heuristic: input contains repeated patterns
        // that often indicate attacker-controlled offsets.
        let has_pattern_0xaa = input.iter().filter(|&&b| b == 0xaa).count() > input.len() / 4;
        let has_pattern_0x41 = input.iter().filter(|&&b| b == 0x41).count() > input.len() / 4;
        if has_pattern_0x41 || has_pattern_0xaa {
            if msg_lower.contains("write") {
                patterns.push(CrashPattern::WriteAtControlledAddress);
            } else if msg_lower.contains("read") {
                patterns.push(CrashPattern::ReadAtControlledAddress);
            }
        }

        patterns.dedup();
        patterns
    }

    /// Compute an exploitability rating from a set of detected patterns.
    #[must_use]
    pub fn rate(patterns: &[CrashPattern]) -> ExploitabilityRating {
        if patterns.is_empty() {
            return ExploitabilityRating::Unknown;
        }

        let mut rating = ExploitabilityRating::NotExploitable;

        for pattern in patterns {
            let candidate = match pattern {
                CrashPattern::AssertionFailure | CrashPattern::OutOfMemory => {
                    ExploitabilityRating::NotExploitable
                }
                CrashPattern::DivisionByZero => ExploitabilityRating::ProbablyNotExploitable,
                CrashPattern::WriteToNull | CrashPattern::IntegerOverflow => {
                    ExploitabilityRating::PossiblyExploitable
                }
                CrashPattern::HeapOverflow
                | CrashPattern::StackOverflow
                | CrashPattern::ReadAtControlledAddress => ExploitabilityRating::PossiblyExploitable,
                CrashPattern::WriteAtControlledAddress
                | CrashPattern::UseAfterFree
                | CrashPattern::TypeConfusion => ExploitabilityRating::Exploitable,
                CrashPattern::PcCorruption => ExploitabilityRating::Critical,
            };
            if candidate > rating {
                rating = candidate;
            }
        }

        rating
    }
}

// ─── CrashRecord ─────────────────────────────────────────────────────────────

/// A single crash instance with all associated data.
#[derive(Debug, Clone)]
pub struct CrashRecord {
    /// Unique identifier for this record.
    pub id: u64,
    /// The input that triggered the crash.
    pub input: Vec<u8>,
    /// FNV-1a hash of the input.
    pub input_hash: u64,
    /// Parsed stack trace.
    pub trace: StackTrace,
    /// Backtrace hash (for deduplication).
    pub backtrace_hash: BacktraceHash,
    /// Crash message / signal description.
    pub message: String,
    /// Signal number (Unix) or exception code (Windows).
    pub signal: i32,
    /// Exploitability assessment.
    pub exploitability: ExploitabilityRating,
    /// Detected crash patterns.
    pub patterns: Vec<CrashPattern>,
    /// Uniqueness score [0.0, 1.0].
    pub uniqueness_score: f64,
    /// When the crash was discovered.
    pub discovered_at: SystemTime,
    /// How many times this crash was reproduced.
    pub reproduction_count: u32,
}

impl CrashRecord {
    /// Create a new crash record, computing all derived fields.
    #[must_use]
    pub fn new(input: Vec<u8>, trace: StackTrace, message: String, signal: i32) -> Self {
        let input_hash = fnv1a_64(&input);
        let backtrace_hash = trace.backtrace_hash();
        let patterns = ExploitabilityAnalyzer::detect_patterns(&input, &trace, &message);
        let exploitability = ExploitabilityAnalyzer::rate(&patterns);
        Self {
            id: input_hash,
            input,
            input_hash,
            trace,
            backtrace_hash,
            message,
            signal,
            exploitability,
            patterns,
            uniqueness_score: 1.0,
            discovered_at: SystemTime::now(),
            reproduction_count: 1,
        }
    }

    /// Return the size of the triggering input in bytes.
    #[must_use]
    pub const fn input_len(&self) -> usize {
        self.input.len()
    }

    /// Return true if this crash is potentially exploitable.
    #[must_use]
    pub const fn is_exploitable(&self) -> bool {
        self.exploitability.is_exploitable()
    }
}

impl fmt::Display for CrashRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Crash[id={:016x} sig={} exploit={} score={:.2}]: {}",
            self.id, self.signal, self.exploitability, self.uniqueness_score, self.message
        )
    }
}

// ─── CrashGroup ──────────────────────────────────────────────────────────────

/// A cluster of crash records sharing the same backtrace hash.
#[derive(Debug, Clone)]
pub struct CrashGroup {
    /// The shared backtrace hash.
    pub backtrace_hash: BacktraceHash,
    /// The representative (first) record in the group.
    pub representative: CrashRecord,
    /// All crash record IDs in this group.
    pub member_ids: Vec<u64>,
    /// Highest exploitability rating seen in this group.
    pub max_exploitability: ExploitabilityRating,
    /// Earliest discovery time.
    pub first_seen: SystemTime,
}

impl CrashGroup {
    /// Create a new group from a single record.
    #[must_use]
    pub fn new(record: CrashRecord) -> Self {
        let hash = record.backtrace_hash;
        let id = record.id;
        let exploit = record.exploitability;
        let seen = record.discovered_at;
        Self {
            backtrace_hash: hash,
            representative: record,
            member_ids: vec![id],
            max_exploitability: exploit,
            first_seen: seen,
        }
    }

    /// Add a crash record to this group.
    pub fn add(&mut self, record: &CrashRecord) {
        self.member_ids.push(record.id);
        if record.exploitability > self.max_exploitability {
            self.max_exploitability = record.exploitability;
        }
        if record.discovered_at < self.first_seen {
            self.first_seen = record.discovered_at;
        }
    }

    /// Number of crashes in this group.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.member_ids.len()
    }
}

// ─── CrashDeduplicator ────────────────────────────────────────────────────────

/// Groups crash records by backtrace hash and computes uniqueness scores.
#[derive(Debug, Default)]
pub struct CrashDeduplicator {
    /// All crash records, keyed by record id.
    records: HashMap<u64, CrashRecord>,
    /// Groups keyed by backtrace hash value.
    groups: HashMap<u64, CrashGroup>,
    /// Set of input hashes already seen.
    seen_input_hashes: HashSet<u64>,
    /// Counter for generating monotone IDs.
    next_id: u64,
}

impl CrashDeduplicator {
    /// Create an empty deduplicator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a crash record.
    ///
    /// Returns `true` if the backtrace hash had not been seen before (new group).
    pub fn add(&mut self, mut record: CrashRecord) -> bool {
        record.id = self.next_id;
        self.next_id += 1;

        self.seen_input_hashes.insert(record.input_hash);

        let bh_key = record.backtrace_hash.0;
        let is_new = !self.groups.contains_key(&bh_key);

        if is_new {
            let group = CrashGroup::new(record.clone());
            self.groups.insert(bh_key, group);
        } else {
            self.groups.get_mut(&bh_key).unwrap().add(&record);
        }

        self.records.insert(record.id, record);
        is_new
    }

    /// Number of unique groups (distinct backtrace hashes).
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.groups.len()
    }

    /// Total number of crash records.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.records.len()
    }

    /// True if no records have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Return all groups sorted by max exploitability (highest first).
    #[must_use]
    pub fn groups_by_severity(&self) -> Vec<&CrashGroup> {
        let mut groups: Vec<&CrashGroup> = self.groups.values().collect();
        groups.sort_by(|a, b| b.max_exploitability.cmp(&a.max_exploitability));
        groups
    }

    /// Return all exploitable groups.
    #[must_use]
    pub fn exploitable_groups(&self) -> Vec<&CrashGroup> {
        self.groups
            .values()
            .filter(|g| g.max_exploitability.is_exploitable())
            .collect()
    }

    /// Compute and update uniqueness scores for all records.
    ///
    /// A record is "unique" if it belongs to a singleton group.
    /// Records in larger groups receive lower scores.
    pub fn compute_uniqueness_scores(&mut self) {
        let group_sizes: HashMap<u64, usize> = self
            .groups
            .iter()
            .map(|(k, g)| (*k, g.size()))
            .collect();

        for record in self.records.values_mut() {
            let group_size = group_sizes
                .get(&record.backtrace_hash.0)
                .copied()
                .unwrap_or(1);
            record.uniqueness_score = 1.0 / (group_size as f64);
        }
    }

    /// Return a reference to a record by id.
    #[must_use]
    pub fn get_record(&self, id: u64) -> Option<&CrashRecord> {
        self.records.get(&id)
    }

    /// Return all records.
    #[must_use]
    pub fn all_records(&self) -> Vec<&CrashRecord> {
        self.records.values().collect()
    }

    /// Return the representative record for each unique backtrace.
    #[must_use]
    pub fn representatives(&self) -> Vec<&CrashRecord> {
        self.groups
            .values()
            .map(|g| &g.representative)
            .collect()
    }

    /// Check if an input hash was already seen.
    #[must_use]
    pub fn is_input_known(&self, hash: u64) -> bool {
        self.seen_input_hashes.contains(&hash)
    }
}

// ─── TriageReport ─────────────────────────────────────────────────────────────

/// Summary statistics for a triage report.
#[derive(Debug, Clone, Default)]
pub struct TriageSummary {
    pub total_crashes: usize,
    pub unique_backtraces: usize,
    pub critical_count: usize,
    pub exploitable_count: usize,
    pub possibly_exploitable_count: usize,
    pub not_exploitable_count: usize,
    pub unknown_count: usize,
}

/// A full triage report over a set of crash records.
pub struct TriageReport {
    pub summary: TriageSummary,
    /// Representative records per group, sorted by severity.
    pub findings: Vec<CrashFinding>,
    pub generated_at: SystemTime,
}

/// A single finding in the triage report.
#[derive(Debug, Clone)]
pub struct CrashFinding {
    pub backtrace_hash: BacktraceHash,
    pub exploitability: ExploitabilityRating,
    pub patterns: Vec<CrashPattern>,
    pub group_size: usize,
    pub trace_summary: String,
    pub message: String,
    pub uniqueness_score: f64,
}

impl TriageReport {
    /// Generate a triage report from a [`CrashDeduplicator`].
    #[must_use]
    pub fn generate(dedup: &CrashDeduplicator) -> Self {
        let mut summary = TriageSummary {
            total_crashes: dedup.total_count(),
            unique_backtraces: dedup.unique_count(),
            ..Default::default()
        };

        let mut findings: Vec<CrashFinding> = dedup
            .groups_by_severity()
            .iter()
            .map(|g| {
                let rep = &g.representative;
                match g.max_exploitability {
                    ExploitabilityRating::Critical => summary.critical_count += 1,
                    ExploitabilityRating::Exploitable => summary.exploitable_count += 1,
                    ExploitabilityRating::PossiblyExploitable => {
                        summary.possibly_exploitable_count += 1;
                    }
                    ExploitabilityRating::NotExploitable
                    | ExploitabilityRating::ProbablyNotExploitable => {
                        summary.not_exploitable_count += 1;
                    }
                    ExploitabilityRating::Unknown => summary.unknown_count += 1,
                }
                CrashFinding {
                    backtrace_hash: g.backtrace_hash,
                    exploitability: g.max_exploitability,
                    patterns: rep.patterns.clone(),
                    group_size: g.size(),
                    trace_summary: rep.trace.summary(5),
                    message: rep.message.clone(),
                    uniqueness_score: rep.uniqueness_score,
                }
            })
            .collect();

        // Sort: Critical > Exploitable > ... > NotExploitable.
        findings.sort_by(|a, b| b.exploitability.cmp(&a.exploitability));

        Self {
            summary,
            findings,
            generated_at: SystemTime::now(),
        }
    }

    /// Format the report as a human-readable string.
    #[must_use]
    pub fn format(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Crash Triage Report ===\n");
        out.push_str(&format!(
            "Total crashes:     {}\n",
            self.summary.total_crashes
        ));
        out.push_str(&format!(
            "Unique backtraces: {}\n",
            self.summary.unique_backtraces
        ));
        out.push_str(&format!(
            "Critical:          {}\n",
            self.summary.critical_count
        ));
        out.push_str(&format!(
            "Exploitable:       {}\n",
            self.summary.exploitable_count
        ));
        out.push_str(&format!(
            "Possibly expl.:    {}\n",
            self.summary.possibly_exploitable_count
        ));
        out.push_str(&format!(
            "Not exploitable:   {}\n",
            self.summary.not_exploitable_count
        ));
        out.push_str(&format!(
            "Unknown:           {}\n",
            self.summary.unknown_count
        ));
        out.push_str("\n--- Findings ---\n");
        for (i, finding) in self.findings.iter().enumerate() {
            // Sanitize the message before embedding it in log output: replace
            // newlines and carriage-returns so an attacker-controlled crash
            // message cannot inject fake log lines (log-injection).
            let safe_message = finding.message.replace('\n', "\\n").replace('\r', "\\r");
            out.push_str(&format!(
                "[{}] {} | hash={} | group={} | trace: {} | msg: {}\n",
                i + 1,
                finding.exploitability,
                finding.backtrace_hash,
                finding.group_size,
                finding.trace_summary,
                safe_message,
            ));
            if !finding.patterns.is_empty() {
                let pats: Vec<String> = finding.patterns.iter().map(std::string::ToString::to_string).collect();
                out.push_str(&format!("     Patterns: {}\n", pats.join(", ")));
            }
        }
        out
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash of a byte slice.
fn fnv1a_64(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Parse a raw crash message into a [`StackTrace`] using minimal heuristics.
///
/// Lines starting with `#` or containing ` at ` are treated as frame lines.
#[must_use]
pub fn parse_crash_trace(raw: &str) -> StackTrace {
    let frames: Vec<StackFrame> = raw
        .lines()
        .filter(|l| {
            let l = l.trim();
            l.starts_with('#') || l.contains(" at ") || l.contains("+0x")
        })
        .map(|line| {
            let line = line.trim();
            // Try to extract address.
            let address = line
                .split_whitespace()
                .find(|tok| tok.starts_with("0x") || tok.starts_with("0X"))
                .and_then(|tok| u64::from_str_radix(tok.trim_start_matches("0x"), 16).ok());

            // Try to extract function name (first identifier-like token after #N).
            let function = line.strip_prefix('#').map_or_else(|| line.split(" at ").next().map(|s| s.trim().to_string()), |rest| {
                let rest = rest.trim();
                let maybe_fn = rest
                    .split_whitespace()
                    .skip(1) // skip frame number
                    .find(|tok| tok.chars().all(|c| c.is_alphanumeric() || c == '_' || c == ':'));
                maybe_fn.map(str::to_string)
            });

            StackFrame {
                module: None,
                function,
                source_file: None,
                source_line: None,
                address,
                offset: None,
            }
        })
        .collect();

    let mut trace = StackTrace::new(frames);
    trace.raw = Some(raw.to_string());
    trace
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace(fns: &[&str]) -> StackTrace {
        let frames = fns
            .iter()
            .map(|f| StackFrame::from_function(*f))
            .collect();
        StackTrace::new(frames)
    }

    fn make_record(msg: &str, signal: i32, fns: &[&str]) -> CrashRecord {
        CrashRecord::new(b"input".to_vec(), make_trace(fns), msg.to_string(), signal)
    }

    #[test]
    fn backtrace_hash_same_frames() {
        let h1 = BacktraceHash::of(&["foo".into(), "bar".into()]);
        let h2 = BacktraceHash::of(&["foo".into(), "bar".into()]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn backtrace_hash_different_frames() {
        let h1 = BacktraceHash::of(&["foo".into()]);
        let h2 = BacktraceHash::of(&["bar".into()]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn stack_frame_normalized_strips_suffix() {
        let f = StackFrame::from_function("my_function+0x123");
        assert_eq!(f.normalized(), "my_function");
    }

    #[test]
    fn stack_frame_noise_detection() {
        let f = StackFrame::from_function("__libc_start_main");
        assert!(f.is_noise());
        let g = StackFrame::from_function("target_function");
        assert!(!g.is_noise());
    }

    #[test]
    fn stack_trace_backtrace_hash_stable() {
        let t = make_trace(&["foo", "bar", "baz"]);
        let h1 = t.backtrace_hash();
        let h2 = t.backtrace_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn stack_trace_denoise_removes_noise() {
        let mut frames = make_trace(&["__libc_start_main", "my_func"]);
        frames.frames.push(StackFrame::from_function("abort"));
        let denoised = frames.denoise();
        assert!(!denoised.frames.iter().any(super::StackFrame::is_noise));
    }

    #[test]
    fn stack_trace_summary() {
        let t = make_trace(&["a", "b", "c"]);
        let s = t.summary(3);
        assert!(s.contains('a'));
        assert!(s.contains('b'));
    }

    #[test]
    fn exploitability_severity_ordering() {
        assert!(
            ExploitabilityRating::Critical.severity()
                > ExploitabilityRating::Exploitable.severity()
        );
        assert!(
            ExploitabilityRating::Exploitable.severity()
                > ExploitabilityRating::NotExploitable.severity()
        );
    }

    #[test]
    fn exploitability_is_exploitable() {
        assert!(ExploitabilityRating::Exploitable.is_exploitable());
        assert!(ExploitabilityRating::Critical.is_exploitable());
        assert!(!ExploitabilityRating::NotExploitable.is_exploitable());
    }

    #[test]
    fn analyzer_detect_assertion_failure() {
        let trace = make_trace(&["__assert_fail"]);
        let patterns = ExploitabilityAnalyzer::detect_patterns(b"data", &trace, "assertion failed");
        assert!(patterns.contains(&CrashPattern::AssertionFailure));
    }

    #[test]
    fn analyzer_rate_assertion_not_exploitable() {
        let patterns = vec![CrashPattern::AssertionFailure];
        let rating = ExploitabilityAnalyzer::rate(&patterns);
        assert_eq!(rating, ExploitabilityRating::NotExploitable);
    }

    #[test]
    fn analyzer_rate_pc_corruption_critical() {
        let patterns = vec![CrashPattern::PcCorruption];
        let rating = ExploitabilityAnalyzer::rate(&patterns);
        assert_eq!(rating, ExploitabilityRating::Critical);
    }

    #[test]
    fn crash_record_creation() {
        let r = make_record("segfault", 11, &["vulnerable_func", "caller"]);
        assert_eq!(r.signal, 11);
        assert_eq!(r.message, "segfault");
        assert!(!r.trace.is_empty());
    }

    #[test]
    fn crash_deduplicator_groups_same_trace() {
        let mut dedup = CrashDeduplicator::new();
        let r1 = make_record("crash1", 11, &["foo", "bar"]);
        let r2 = make_record("crash2", 11, &["foo", "bar"]);
        let new1 = dedup.add(r1);
        let new2 = dedup.add(r2);
        assert!(new1);
        assert!(!new2); // same backtrace hash
        assert_eq!(dedup.unique_count(), 1);
        assert_eq!(dedup.total_count(), 2);
    }

    #[test]
    fn crash_deduplicator_separates_different_traces() {
        let mut dedup = CrashDeduplicator::new();
        let r1 = make_record("c1", 11, &["foo"]);
        let r2 = make_record("c2", 11, &["bar"]);
        dedup.add(r1);
        dedup.add(r2);
        assert_eq!(dedup.unique_count(), 2);
    }

    #[test]
    fn crash_deduplicator_exploitable_groups() {
        let mut dedup = CrashDeduplicator::new();
        let mut r = make_record("pc control", 11, &["exploit_me"]);
        r.exploitability = ExploitabilityRating::Critical;
        r.backtrace_hash = BacktraceHash::of(&["exploit_me".into()]);
        dedup.add(r);
        let exploitable = dedup.exploitable_groups();
        assert!(!exploitable.is_empty());
    }

    #[test]
    fn triage_report_generation() {
        let mut dedup = CrashDeduplicator::new();
        dedup.add(make_record("assert fail", 6, &["assert_func"]));
        dedup.add(make_record("heap overflow", 11, &["heap_func"]));
        let report = TriageReport::generate(&dedup);
        assert_eq!(report.summary.total_crashes, 2);
        assert_eq!(report.summary.unique_backtraces, 2);
        let text = report.format();
        assert!(text.contains("Triage"));
    }

    #[test]
    fn uniqueness_scores_singleton() {
        let mut dedup = CrashDeduplicator::new();
        dedup.add(make_record("c", 11, &["unique_func"]));
        dedup.compute_uniqueness_scores();
        let recs = dedup.all_records();
        assert!((recs[0].uniqueness_score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn uniqueness_scores_group() {
        let mut dedup = CrashDeduplicator::new();
        dedup.add(make_record("c1", 11, &["shared"]));
        dedup.add(make_record("c2", 11, &["shared"]));
        dedup.compute_uniqueness_scores();
        let recs = dedup.all_records();
        for r in &recs {
            assert!((r.uniqueness_score - 0.5).abs() < 1e-9);
        }
    }

    #[test]
    fn parse_crash_trace_extracts_frames() {
        let raw = "#0 0x401234 in target_function\n#1 0x402000 in main";
        let trace = parse_crash_trace(raw);
        assert!(!trace.frames.is_empty());
    }

    #[test]
    fn backtrace_hash_display() {
        let h = BacktraceHash(0x0102_0304_0506_0708);
        assert_eq!(h.to_string(), "0102030405060708");
    }

    #[test]
    fn crash_group_size() {
        let r1 = make_record("c1", 11, &["f"]);
        let mut group = CrashGroup::new(r1);
        let r2 = make_record("c2", 11, &["f"]);
        group.add(&r2);
        assert_eq!(group.size(), 2);
    }
}
