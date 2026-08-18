//! Crash deduplication: deduplicate crashes by stack-trace hash and fault address.
//!
//! Provides [`CrashDedup`], [`CrashSignature`], [`CrashRecord`],
//! [`DeduplicationReport`], and [`MinimizationHint`].


use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── CrashKind ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrashKind {
    Segfault,
    HeapCorruption,
    StackOverflow,
    NullDeref,
    UseAfterFree,
    BufferOverflow,
    IntegerOverflow,
    DivideByZero,
    AssertionFailure,
    Abort,
    Timeout,
    Unknown,
}

impl std::fmt::Display for CrashKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Segfault => "SEGV",
            Self::HeapCorruption => "HEAP_CORRUPT",
            Self::StackOverflow => "STACK_OVF",
            Self::NullDeref => "NULL_DEREF",
            Self::UseAfterFree => "USE_AFTER_FREE",
            Self::BufferOverflow => "BUF_OVF",
            Self::IntegerOverflow => "INT_OVF",
            Self::DivideByZero => "DIV_ZERO",
            Self::AssertionFailure => "ASSERT",
            Self::Abort => "ABORT",
            Self::Timeout => "TIMEOUT",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

// ─── StackFrame ───────────────────────────────────────────────────────────────

/// A single frame in a crash stack trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrashFrame {
    pub address: u64,
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub offset: u64,
}

impl CrashFrame {
    #[must_use]
    pub const fn new(address: u64) -> Self {
        Self {
            address,
            symbol: None,
            module: None,
            offset: 0,
        }
    }

    #[must_use]
    pub fn with_symbol(mut self, sym: &str) -> Self {
        self.symbol = Some(sym.to_string());
        self
    }

    #[must_use]
    pub fn with_module(mut self, module: &str, offset: u64) -> Self {
        self.module = Some(module.to_string());
        self.offset = offset;
        self
    }

    /// A normalized form for deduplication: prefer symbol name over raw address.
    #[must_use]
    pub fn normalized(&self) -> String {
        if let Some(sym) = &self.symbol {
            sym.clone()
        } else if let Some(module) = &self.module {
            format!("{module}+0x{:x}", self.offset)
        } else {
            format!("0x{:x}", self.address)
        }
    }
}

impl std::fmt::Display for CrashFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(sym) = &self.symbol {
            write!(f, "0x{:x} <{sym}>", self.address)
        } else {
            write!(f, "0x{:x}", self.address)
        }
    }
}

// ─── CrashSignature ───────────────────────────────────────────────────────────

/// Deduplication key: top-N frames + fault address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrashSignature {
    /// Top 3 normalized frame identifiers.
    pub top3_frames: [String; 3],
    /// Faulting address (page-aligned for stability).
    pub fault_addr_page: u64,
    /// Crash kind.
    pub kind: CrashKind,
}

impl CrashSignature {
    #[must_use]
    pub fn new(frames: &[CrashFrame], fault_addr: u64, kind: CrashKind) -> Self {
        let normalized: Vec<String> = frames.iter().take(3).map(CrashFrame::normalized).collect();
        let top3_frames = [
            normalized.first().cloned().unwrap_or_default(),
            normalized.get(1).cloned().unwrap_or_default(),
            normalized.get(2).cloned().unwrap_or_default(),
        ];
        // Page-align the fault address (4 KiB pages)
        let fault_addr_page = fault_addr & !0xFFF;
        Self {
            top3_frames,
            fault_addr_page,
            kind,
        }
    }

    #[must_use]
    pub fn hash_u64(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    #[must_use]
    pub fn short_id(&self) -> String {
        format!("{:016x}", self.hash_u64())
    }
}

impl std::fmt::Display for CrashSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind, self.short_id())
    }
}

// ─── CrashRecord ──────────────────────────────────────────────────────────────

/// A unique crash record after deduplication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    /// Unique record ID.
    pub id: u64,
    /// Deduplication signature.
    pub signature: CrashSignature,
    /// Full stack trace.
    pub frames: Vec<CrashFrame>,
    /// Faulting address.
    pub fault_addr: u64,
    /// Input bytes that triggered this crash.
    pub triggering_input: Vec<u8>,
    /// Timestamp of first occurrence.
    pub first_seen: u64,
    /// Timestamp of most recent occurrence.
    pub last_seen: u64,
    /// How many times this crash has been triggered.
    pub occurrence_count: u32,
    /// True if this crash has been minimized.
    pub minimized: bool,
    /// Minimized input, if available.
    pub minimized_input: Option<Vec<u8>>,
    /// Analyst notes.
    pub notes: String,
    /// Severity estimate.
    pub severity: CrashSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashSeverity {
    /// Likely unexploitable.
    Low,
    /// Possible info leak or `DoS`.
    Medium,
    /// Likely exploitable (control flow / write primitive).
    High,
    /// Confirmed exploitable.
    Critical,
    /// Not yet analyzed.
    Unknown,
}

impl std::fmt::Display for CrashSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

impl CrashRecord {
    #[must_use]
    pub fn new(
        id: u64,
        frames: Vec<CrashFrame>,
        fault_addr: u64,
        kind: CrashKind,
        input: Vec<u8>,
    ) -> Self {
        let sig = CrashSignature::new(&frames, fault_addr, kind);
        let now = now_secs();
        Self {
            id,
            signature: sig,
            frames,
            fault_addr,
            triggering_input: input,
            first_seen: now,
            last_seen: now,
            occurrence_count: 1,
            minimized: false,
            minimized_input: None,
            notes: String::new(),
            severity: CrashSeverity::Unknown,
        }
    }

    pub fn record_duplicate(&mut self) {
        self.occurrence_count += 1;
        self.last_seen = now_secs();
    }

    pub fn set_minimized(&mut self, min_input: Vec<u8>) {
        self.minimized = true;
        self.minimized_input = Some(min_input);
    }

    #[must_use]
    pub fn effective_input(&self) -> &[u8] {
        self.minimized_input
            .as_deref()
            .unwrap_or(&self.triggering_input)
    }

    #[must_use]
    pub fn with_notes(mut self, notes: &str) -> Self {
        self.notes = notes.to_string();
        self
    }

    #[must_use]
    pub const fn with_severity(mut self, s: CrashSeverity) -> Self {
        self.severity = s;
        self
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ─── MinimizationHint ─────────────────────────────────────────────────────────

/// Hints for minimizing a crash input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizationHint {
    pub original_size: usize,
    pub estimated_minimal_size: usize,
    /// Byte ranges that appear essential (must keep).
    pub essential_ranges: Vec<(usize, usize)>,
    /// Strategy recommendation.
    pub strategy: MinimizationStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MinimizationStrategy {
    /// Binary half-and-half.
    Bisect,
    /// Remove blocks iteratively.
    BlockDrop,
    /// Byte-level delta debugging.
    DeltaDebug,
    /// Line-by-line (for text inputs).
    LineDrop,
}

impl MinimizationHint {
    #[must_use]
    pub fn new(original_size: usize, crash_record: &CrashRecord) -> Self {
        // Heuristic: null-deref / DoS often minimal, exploit primitives need more bytes
        let estimated = match crash_record.signature.kind {
            CrashKind::NullDeref | CrashKind::Abort => (original_size / 4).max(1),
            CrashKind::BufferOverflow | CrashKind::UseAfterFree => (original_size / 2).max(1),
            _ => (original_size * 2 / 3).max(1),
        };
        Self {
            original_size,
            estimated_minimal_size: estimated,
            essential_ranges: Vec::new(),
            strategy: MinimizationStrategy::Bisect,
        }
    }

    #[must_use]
    pub const fn with_strategy(mut self, s: MinimizationStrategy) -> Self {
        self.strategy = s;
        self
    }

    #[must_use]
    pub fn reduction_ratio(&self) -> f64 {
        if self.original_size == 0 {
            0.0
        } else {
            1.0 - (self.estimated_minimal_size as f64 / self.original_size as f64)
        }
    }
}

// ─── DeduplicationReport ──────────────────────────────────────────────────────

/// Summary report after a deduplication run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeduplicationReport {
    pub total_crashes: u64,
    pub unique_crashes: u64,
    pub duplicate_crashes: u64,
    pub by_kind: HashMap<String, u64>,
    pub by_severity: HashMap<String, u64>,
    pub dedup_ratio: f64,
    pub most_frequent_signature: Option<String>,
    pub most_frequent_count: u32,
}

impl DeduplicationReport {
    #[must_use]
    pub fn from_records(records: &[CrashRecord]) -> Self {
        let mut report = Self::default();
        report.unique_crashes = records.len() as u64;
        report.total_crashes = records.iter().map(|r| u64::from(r.occurrence_count)).sum();
        report.duplicate_crashes = report.total_crashes - report.unique_crashes;

        for r in records {
            *report
                .by_kind
                .entry(r.signature.kind.to_string())
                .or_insert(0) += u64::from(r.occurrence_count);
            *report
                .by_severity
                .entry(r.severity.to_string())
                .or_insert(0) += 1;
        }

        if report.total_crashes > 0 {
            report.dedup_ratio = report.duplicate_crashes as f64 / report.total_crashes as f64;
        }

        // Most frequent
        if let Some(r) = records.iter().max_by_key(|r| r.occurrence_count) {
            report.most_frequent_signature = Some(r.signature.to_string());
            report.most_frequent_count = r.occurrence_count;
        }

        report
    }
}

// ─── CrashDedup ───────────────────────────────────────────────────────────────

/// Deduplicates crash records by signature.
#[derive(Debug, Default)]
pub struct CrashDedup {
    /// Known unique crashes keyed by signature hash.
    records: HashMap<u64, CrashRecord>,
    id_counter: u64,
}

impl CrashDedup {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a crash. Returns (`record_id`, `is_new`).
    pub fn submit(
        &mut self,
        frames: Vec<CrashFrame>,
        fault_addr: u64,
        kind: CrashKind,
        input: Vec<u8>,
    ) -> (u64, bool) {
        let sig = CrashSignature::new(&frames, fault_addr, kind);
        let sig_hash = sig.hash_u64();

        if let Some(existing) = self.records.get_mut(&sig_hash) {
            existing.record_duplicate();
            return (existing.id, false);
        }

        let id = self.id_counter;
        self.id_counter += 1;
        let record = CrashRecord::new(id, frames, fault_addr, kind, input);
        self.records.insert(sig_hash, record);
        (id, true)
    }

    /// Get a record by ID.
    #[must_use]
    pub fn get_by_id(&self, id: u64) -> Option<&CrashRecord> {
        self.records.values().find(|r| r.id == id)
    }

    /// Get a mutable record by ID.
    pub fn get_by_id_mut(&mut self, id: u64) -> Option<&mut CrashRecord> {
        self.records.values_mut().find(|r| r.id == id)
    }

    /// All unique crash records.
    #[must_use]
    pub fn unique_records(&self) -> Vec<&CrashRecord> {
        let mut v: Vec<&CrashRecord> = self.records.values().collect();
        v.sort_by_key(|r| r.id);
        v
    }

    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn total_crashes(&self) -> u64 {
        self.records
            .values()
            .map(|r| u64::from(r.occurrence_count))
            .sum()
    }

    /// Generate a deduplication report.
    #[must_use]
    pub fn report(&self) -> DeduplicationReport {
        let records: Vec<CrashRecord> = self.records.values().cloned().collect();
        DeduplicationReport::from_records(&records)
    }

    /// Records sorted by occurrence count (most frequent first).
    #[must_use]
    pub fn sorted_by_frequency(&self) -> Vec<&CrashRecord> {
        let mut v: Vec<&CrashRecord> = self.records.values().collect();
        v.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));
        v
    }

    /// Records of a specific crash kind.
    #[must_use]
    pub fn by_kind(&self, kind: CrashKind) -> Vec<&CrashRecord> {
        self.records
            .values()
            .filter(|r| r.signature.kind == kind)
            .collect()
    }

    /// Mark a record as minimized.
    pub fn set_minimized(&mut self, id: u64, min_input: Vec<u8>) -> bool {
        if let Some(r) = self.get_by_id_mut(id) {
            r.set_minimized(min_input);
            true
        } else {
            false
        }
    }

    /// Hint for minimizing a crash.
    #[must_use]
    pub fn minimization_hint(&self, id: u64) -> Option<MinimizationHint> {
        let r = self.get_by_id(id)?;
        let orig_size = r.triggering_input.len();
        Some(MinimizationHint::new(orig_size, r))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(addr: u64, sym: &str) -> CrashFrame {
        CrashFrame::new(addr).with_symbol(sym)
    }

    fn sample_frames() -> Vec<CrashFrame> {
        vec![
            frame(0x40_1000, "vuln_func"),
            frame(0x40_2000, "caller"),
            frame(0x40_3000, "main"),
        ]
    }

    #[test]
    fn test_submit_new_crash() {
        let mut dedup = CrashDedup::new();
        let (id, is_new) = dedup.submit(
            sample_frames(),
            0xDEAD_0000,
            CrashKind::Segfault,
            b"input".to_vec(),
        );
        assert!(is_new);
        assert_eq!(id, 0);
    }

    #[test]
    fn test_submit_duplicate_crash() {
        let mut dedup = CrashDedup::new();
        dedup.submit(
            sample_frames(),
            0xDEAD_0000,
            CrashKind::Segfault,
            b"input1".to_vec(),
        );
        let (id, is_new) = dedup.submit(
            sample_frames(),
            0xDEAD_0000,
            CrashKind::Segfault,
            b"input2".to_vec(),
        );
        assert!(!is_new);
        // Should be same record
        let r = dedup.get_by_id(id).unwrap();
        assert_eq!(r.occurrence_count, 2);
    }

    #[test]
    fn test_different_signatures() {
        let mut dedup = CrashDedup::new();
        let frames1 = vec![
            frame(0x1000, "f1"),
            frame(0x2000, "f2"),
            frame(0x3000, "f3"),
        ];
        let frames2 = vec![
            frame(0x4000, "g1"),
            frame(0x5000, "g2"),
            frame(0x6000, "g3"),
        ];
        let (id1, new1) = dedup.submit(frames1, 0, CrashKind::Segfault, vec![]);
        let (id2, new2) = dedup.submit(frames2, 0, CrashKind::Segfault, vec![]);
        assert!(new1 && new2);
        assert_ne!(id1, id2);
        assert_eq!(dedup.unique_count(), 2);
    }

    #[test]
    fn test_unique_records_sorted() {
        let mut dedup = CrashDedup::new();
        for i in 0..5u64 {
            let frames = vec![frame(i * 0x1000 + 1, "unique_sym")];
            dedup.submit(frames, i * 0x1000, CrashKind::NullDeref, vec![]);
        }
        let records = dedup.unique_records();
        assert_eq!(records.len(), 5);
        assert!(records.windows(2).all(|w| w[0].id < w[1].id));
    }

    #[test]
    fn test_total_crashes_with_duplicates() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        assert_eq!(dedup.total_crashes(), 3);
        assert_eq!(dedup.unique_count(), 1);
    }

    #[test]
    fn test_by_kind() {
        let mut dedup = CrashDedup::new();
        dedup.submit(
            vec![frame(1, "f1"), frame(2, "f2"), frame(3, "f3")],
            0,
            CrashKind::NullDeref,
            vec![],
        );
        dedup.submit(
            vec![frame(4, "g1"), frame(5, "g2"), frame(6, "g3")],
            0,
            CrashKind::Segfault,
            vec![],
        );
        assert_eq!(dedup.by_kind(CrashKind::NullDeref).len(), 1);
        assert_eq!(dedup.by_kind(CrashKind::Segfault).len(), 1);
        assert_eq!(dedup.by_kind(CrashKind::Abort).len(), 0);
    }

    #[test]
    fn test_set_minimized() {
        let mut dedup = CrashDedup::new();
        let (id, _) = dedup.submit(
            sample_frames(),
            0,
            CrashKind::BufferOverflow,
            b"AAAAAAAAA".to_vec(),
        );
        assert!(dedup.set_minimized(id, b"A".to_vec()));
        let r = dedup.get_by_id(id).unwrap();
        assert!(r.minimized);
        assert_eq!(r.minimized_input.as_deref(), Some(b"A".as_slice()));
    }

    #[test]
    fn test_minimization_hint() {
        let mut dedup = CrashDedup::new();
        let input = vec![0xABu8; 1000];
        let (id, _) = dedup.submit(sample_frames(), 0, CrashKind::BufferOverflow, input);
        let hint = dedup.minimization_hint(id).unwrap();
        assert_eq!(hint.original_size, 1000);
        assert!(hint.estimated_minimal_size < 1000);
    }

    #[test]
    fn test_report_basic() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        let report = dedup.report();
        assert_eq!(report.unique_crashes, 1);
        assert_eq!(report.total_crashes, 2);
        assert_eq!(report.duplicate_crashes, 1);
    }

    #[test]
    fn test_report_dedup_ratio() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        let report = dedup.report();
        assert!((report.dedup_ratio - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_crash_signature_short_id() {
        let sig = CrashSignature::new(&sample_frames(), 0xDEAD_0000, CrashKind::Segfault);
        let id = sig.short_id();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_crash_frame_normalized_symbol() {
        let f = frame(0x1000, "malloc");
        assert_eq!(f.normalized(), "malloc");
    }

    #[test]
    fn test_crash_frame_normalized_address() {
        let f = CrashFrame::new(0xDEAD_BEEF);
        assert!(f.normalized().contains("deadbeef"));
    }

    #[test]
    fn test_crash_kind_display() {
        assert_eq!(CrashKind::Segfault.to_string(), "SEGV");
        assert_eq!(CrashKind::BufferOverflow.to_string(), "BUF_OVF");
    }

    #[test]
    fn test_minimization_hint_reduction_ratio() {
        let frames = sample_frames();
        let record = CrashRecord::new(0, frames, 0, CrashKind::NullDeref, vec![0u8; 100]);
        let hint = MinimizationHint::new(100, &record);
        assert!(hint.reduction_ratio() > 0.0);
        assert!(hint.reduction_ratio() < 1.0);
    }

    #[test]
    fn test_sorted_by_frequency() {
        let mut dedup = CrashDedup::new();
        let (_id1, _) = dedup.submit(
            vec![frame(1, "a"), frame(2, "b"), frame(3, "c")],
            0,
            CrashKind::Segfault,
            vec![],
        );
        // Submit second crash twice
        let (_, _) = dedup.submit(
            vec![frame(4, "d"), frame(5, "e"), frame(6, "f")],
            0,
            CrashKind::Abort,
            vec![],
        );
        let (_, _) = dedup.submit(
            vec![frame(4, "d"), frame(5, "e"), frame(6, "f")],
            0,
            CrashKind::Abort,
            vec![],
        );
        let sorted = dedup.sorted_by_frequency();
        assert_eq!(sorted[0].occurrence_count, 2);
    }
}

// ─── TriageReport ─────────────────────────────────────────────────────────────

/// Structured triage output for all unique crashes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriageReport {
    pub unique_count: usize,
    pub entries: Vec<TriageEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TriageEntry {
    pub id: u64,
    pub signature: String,
    pub kind: String,
    pub severity: String,
    pub occurrences: u32,
    pub top_frame: String,
    pub input_size: usize,
    pub minimized: bool,
}

impl TriageReport {
    #[must_use]
    pub fn from_dedup(dedup: &CrashDedup) -> Self {
        let entries: Vec<TriageEntry> = dedup
            .unique_records()
            .iter()
            .map(|r| TriageEntry {
                id: r.id,
                signature: r.signature.short_id(),
                kind: r.signature.kind.to_string(),
                severity: r.severity.to_string(),
                occurrences: r.occurrence_count,
                top_frame: r
                    .frames
                    .first()
                    .map(CrashFrame::normalized)
                    .unwrap_or_default(),
                input_size: r.triggering_input.len(),
                minimized: r.minimized,
            })
            .collect();
        Self {
            unique_count: entries.len(),
            entries,
        }
    }

    #[must_use]
    pub fn critical_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.severity == "CRITICAL")
            .count()
    }

    #[must_use]
    pub fn high_count(&self) -> usize {
        self.entries.iter().filter(|e| e.severity == "HIGH").count()
    }

    #[must_use]
    pub fn minimized_count(&self) -> usize {
        self.entries.iter().filter(|e| e.minimized).count()
    }

    #[must_use]
    pub fn to_text_report(&self) -> String {
        let mut out = format!(
            "=== Crash Triage Report ({} unique) ===\n\n",
            self.unique_count
        );
        for e in &self.entries {
            out.push_str(&format!(
                "[{}] {} | {} | {} | {} occurrence(s) | top: {}\n",
                e.id, e.signature, e.kind, e.severity, e.occurrences, e.top_frame
            ));
        }
        out
    }
}

// ─── CrashExporter ────────────────────────────────────────────────────────────

/// Exports crash records to various formats.
pub struct CrashExporter;

impl CrashExporter {
    #[must_use]
    pub fn to_json(records: &[CrashRecord]) -> String {
        // Simplified JSON serialization
        let mut parts: Vec<String> = Vec::with_capacity(records.len());
        for r in records {
            parts.push(format!(
                r#"{{"id":{},"sig":"{}","kind":"{}","count":{}}}"#,
                r.id,
                r.signature.short_id(),
                r.signature.kind,
                r.occurrence_count
            ));
        }
        format!("[{}]", parts.join(","))
    }

    #[must_use]
    pub fn to_csv(records: &[CrashRecord]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(64 + records.len() * 48);
        out.push_str("id,signature,kind,severity,occurrences,minimized\n");
        for r in records {
            let _ = writeln!(
                out,
                "{},{},{},{},{},{}",
                r.id,
                r.signature.short_id(),
                r.signature.kind,
                r.severity,
                r.occurrence_count,
                r.minimized,
            );
        }
        out
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    fn frame(addr: u64, sym: &str) -> CrashFrame {
        CrashFrame::new(addr).with_symbol(sym)
    }

    fn sample_frames() -> Vec<CrashFrame> {
        vec![
            frame(0x40_1000, "vuln"),
            frame(0x40_2000, "caller"),
            frame(0x40_3000, "main"),
        ]
    }

    #[test]
    fn test_triage_report_from_dedup() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![0u8; 10]);
        dedup.submit(
            vec![frame(1, "a"), frame(2, "b"), frame(3, "c")],
            0,
            CrashKind::NullDeref,
            vec![],
        );
        let report = TriageReport::from_dedup(&dedup);
        assert_eq!(report.unique_count, 2);
    }

    #[test]
    fn test_triage_report_to_text() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, b"aaa".to_vec());
        let report = TriageReport::from_dedup(&dedup);
        let text = report.to_text_report();
        assert!(text.contains("Crash Triage Report"));
        assert!(text.contains("SEGV"));
    }

    #[test]
    fn test_triage_report_minimized_count() {
        let mut dedup = CrashDedup::new();
        let (id, _) = dedup.submit(sample_frames(), 0, CrashKind::Segfault, b"long".to_vec());
        dedup.set_minimized(id, b"x".to_vec());
        let report = TriageReport::from_dedup(&dedup);
        assert_eq!(report.minimized_count(), 1);
    }

    #[test]
    fn test_triage_entry_signature_length() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        let report = TriageReport::from_dedup(&dedup);
        assert_eq!(report.entries[0].signature.len(), 16);
    }

    #[test]
    fn test_crash_exporter_to_json() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        let records: Vec<CrashRecord> = dedup
            .unique_records()
            .iter()
            .map(|r| (*r).clone())
            .collect();
        let json = CrashExporter::to_json(&records);
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));
        assert!(json.contains("\"id\":0"));
    }

    #[test]
    fn test_crash_exporter_to_csv() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        let records: Vec<CrashRecord> = dedup
            .unique_records()
            .iter()
            .map(|r| (*r).clone())
            .collect();
        let csv = CrashExporter::to_csv(&records);
        assert!(csv.contains("id,signature"));
        assert!(csv.contains("SEGV"));
    }

    #[test]
    fn test_crash_severity_display_all() {
        assert_eq!(CrashSeverity::Low.to_string(), "LOW");
        assert_eq!(CrashSeverity::Medium.to_string(), "MEDIUM");
        assert_eq!(CrashSeverity::High.to_string(), "HIGH");
        assert_eq!(CrashSeverity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_minimization_hint_strategy() {
        let frames = sample_frames();
        let r = CrashRecord::new(0, frames, 0, CrashKind::BufferOverflow, vec![0u8; 500]);
        let hint = MinimizationHint::new(500, &r).with_strategy(MinimizationStrategy::DeltaDebug);
        assert_eq!(hint.strategy, MinimizationStrategy::DeltaDebug);
    }

    #[test]
    fn test_crash_record_effective_input_not_minimized() {
        let frames = sample_frames();
        let r = CrashRecord::new(0, frames, 0, CrashKind::Segfault, b"original".to_vec());
        assert_eq!(r.effective_input(), b"original");
    }

    #[test]
    fn test_crash_record_effective_input_minimized() {
        let frames = sample_frames();
        let mut r = CrashRecord::new(0, frames, 0, CrashKind::Segfault, b"long_input".to_vec());
        r.set_minimized(b"min".to_vec());
        assert_eq!(r.effective_input(), b"min");
    }

    #[test]
    fn test_dedup_get_by_id_not_found() {
        let dedup = CrashDedup::new();
        assert!(dedup.get_by_id(999).is_none());
    }

    #[test]
    fn test_report_by_kind_entries() {
        let mut dedup = CrashDedup::new();
        dedup.submit(sample_frames(), 0, CrashKind::Segfault, vec![]);
        dedup.submit(
            vec![frame(1, "a"), frame(2, "b"), frame(3, "c")],
            0,
            CrashKind::NullDeref,
            vec![],
        );
        let report = dedup.report();
        assert!(report.by_kind.contains_key("SEGV"));
        assert!(report.by_kind.contains_key("NULL_DEREF"));
    }

    #[test]
    fn test_crash_kind_all_variants_display() {
        let kinds = [
            CrashKind::Segfault,
            CrashKind::HeapCorruption,
            CrashKind::StackOverflow,
            CrashKind::NullDeref,
            CrashKind::UseAfterFree,
            CrashKind::BufferOverflow,
            CrashKind::IntegerOverflow,
            CrashKind::DivideByZero,
            CrashKind::AssertionFailure,
            CrashKind::Abort,
            CrashKind::Timeout,
            CrashKind::Unknown,
        ];
        for k in &kinds {
            assert!(!k.to_string().is_empty());
        }
    }

    #[test]
    fn test_crash_signature_same_input_same_hash() {
        let sig1 = CrashSignature::new(&sample_frames(), 0xDEAD_0000, CrashKind::Segfault);
        let sig2 = CrashSignature::new(&sample_frames(), 0xDEAD_0000, CrashKind::Segfault);
        assert_eq!(sig1.hash_u64(), sig2.hash_u64());
    }

    #[test]
    fn test_crash_frame_module_normalized() {
        let f = CrashFrame::new(0x1000).with_module("ntdll.dll", 0x500);
        assert!(f.normalized().contains("ntdll"));
    }

    #[test]
    fn test_dedup_total_crashes_empty() {
        let dedup = CrashDedup::new();
        assert_eq!(dedup.total_crashes(), 0);
    }

    #[test]
    fn test_triage_report_critical_count_zero() {
        let dedup = CrashDedup::new();
        let report = TriageReport::from_dedup(&dedup);
        assert_eq!(report.critical_count(), 0);
    }

    #[test]
    fn test_triage_report_high_count_zero() {
        let dedup = CrashDedup::new();
        let report = TriageReport::from_dedup(&dedup);
        assert_eq!(report.high_count(), 0);
    }
}
