//! Crash triage — deduplication, severity classification, root cause analysis,
//! and reproducer minimization for fuzzer-discovered crashes.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ─── Crash classification ─────────────────────────────────────────────────────

/// Crash severity tier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CrashSeverity {
    /// Likely exploitable: control-flow or write-primitive.
    Critical,
    /// Potentially exploitable: heap/stack corruption without direct control.
    High,
    /// Memory safety issue without clear exploitability path.
    Medium,
    /// Assertion, abort, or logic error — not memory-safety related.
    Low,
    /// Unknown or unclassified.
    Unknown,
}

impl std::fmt::Display for CrashSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Category of memory-safety crash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrashKind {
    NullDeref,
    HeapOverflow,
    StackOverflow,
    UseAfterFree,
    DoubleFree,
    OutOfBounds { read: bool },
    IntegerOverflow,
    DivisionByZero,
    UnreachableCode,
    StackBufferOverflow,
    GlobalBufferOverflow,
    Assertion,
    Abort,
    SignalN(u32),
    Timeout,
    Unknown,
}

impl std::fmt::Display for CrashKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NullDeref => write!(f, "null-deref"),
            Self::HeapOverflow => write!(f, "heap-overflow"),
            Self::StackOverflow => write!(f, "stack-overflow"),
            Self::UseAfterFree => write!(f, "use-after-free"),
            Self::DoubleFree => write!(f, "double-free"),
            Self::OutOfBounds { read: true } => write!(f, "out-of-bounds-read"),
            Self::OutOfBounds { read: false } => write!(f, "out-of-bounds-write"),
            Self::IntegerOverflow => write!(f, "integer-overflow"),
            Self::DivisionByZero => write!(f, "division-by-zero"),
            Self::UnreachableCode => write!(f, "unreachable"),
            Self::StackBufferOverflow => write!(f, "stack-buffer-overflow"),
            Self::GlobalBufferOverflow => write!(f, "global-buffer-overflow"),
            Self::Assertion => write!(f, "assertion-failure"),
            Self::Abort => write!(f, "abort"),
            Self::SignalN(n) => write!(f, "signal-{n}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── Stack frame ──────────────────────────────────────────────────────────────

/// One frame in a crash stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    pub frame_no: usize,
    pub pc: u64,
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub offset: u64,
    pub file_line: Option<String>,
}

impl std::fmt::Display for StackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{:2} {:#018x}", self.frame_no, self.pc)?;
        if let Some(sym) = &self.symbol {
            write!(f, " {sym}")?;
        }
        if let Some(m) = &self.module {
            write!(f, " ({m}+{:#x})", self.offset)?;
        }
        if let Some(fl) = &self.file_line {
            write!(f, " [{fl}]")?;
        }
        Ok(())
    }
}

// ─── Crash record ─────────────────────────────────────────────────────────────

/// A fully described crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashRecord {
    pub id: u64,
    /// Deduplification hash (based on top-N frames).
    pub dedup_hash: u64,
    pub kind: CrashKind,
    pub severity: CrashSeverity,
    pub signal: Option<u32>,
    pub fault_address: Option<u64>,
    pub stack_trace: Vec<StackFrame>,
    /// The fuzzer input that triggered this crash.
    pub reproducer: Vec<u8>,
    /// Minimized reproducer (may be shorter).
    pub minimized_reproducer: Option<Vec<u8>>,
    /// Sanitizer output (asan/ubsan log line).
    pub sanitizer_output: Option<String>,
    /// Root cause analysis notes.
    pub root_cause_notes: Vec<String>,
    pub first_seen_run: u64,
    pub occurrence_count: usize,
}

impl CrashRecord {
    /// Build a one-line summary.
    #[must_use] 
    pub fn summary(&self) -> String {
        let addr = self.fault_address.map(|a| format!(" @ {a:#x}")).unwrap_or_default();
        format!("[{}] {} id={} hash={:#x}{addr}", self.severity, self.kind, self.id, self.dedup_hash)
    }
}

// ─── Dedup key computation ────────────────────────────────────────────────────

/// Compute a deduplication key from the top-N significant frames.
///
/// Uses the first `frame_depth` frames that are inside user code (not libc,
/// not sanitizer runtime, not libFuzzer).
#[must_use] 
pub fn compute_dedup_hash(frames: &[StackFrame], frame_depth: usize) -> u64 {
    let significant: Vec<u64> = frames
        .iter()
        .filter(|f| {
            !f.module.as_deref().unwrap_or("").contains("libc")
                && !f.module.as_deref().unwrap_or("").contains("asan")
                && !f.module.as_deref().unwrap_or("").contains("libFuzzer")
                && !f.symbol.as_deref().unwrap_or("").starts_with("__sanitizer")
        })
        .take(frame_depth)
        .map(|f| f.pc)
        .collect();

    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for pc in significant {
        h ^= pc;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ─── Sanitizer output parser ──────────────────────────────────────────────────

/// Parse ASan/UBSan/MSan output to extract crash kind and fault address.
#[must_use] 
pub fn parse_sanitizer_output(output: &str) -> (CrashKind, Option<u64>) {
    let lower = output.to_lowercase();

    // ASAN patterns
    if lower.contains("heap-use-after-free") { return (CrashKind::UseAfterFree, extract_fault_addr(output)); }
    if lower.contains("heap-buffer-overflow") { return (CrashKind::HeapOverflow, extract_fault_addr(output)); }
    if lower.contains("stack-buffer-overflow") { return (CrashKind::StackBufferOverflow, extract_fault_addr(output)); }
    if lower.contains("global-buffer-overflow") { return (CrashKind::GlobalBufferOverflow, extract_fault_addr(output)); }
    if lower.contains("stack-overflow") { return (CrashKind::StackOverflow, None); }
    if lower.contains("double-free") { return (CrashKind::DoubleFree, extract_fault_addr(output)); }
    if lower.contains("use-after-return") { return (CrashKind::UseAfterFree, None); }

    // Null deref: READ/WRITE of size N at address 0x00...
    if lower.contains("null") && (lower.contains("read") || lower.contains("write")) {
        return (CrashKind::NullDeref, Some(0));
    }

    // Out-of-bounds read/write
    if lower.contains("out-of-bounds") && lower.contains("write") {
        return (CrashKind::OutOfBounds { read: false }, extract_fault_addr(output));
    }
    if lower.contains("out-of-bounds") {
        return (CrashKind::OutOfBounds { read: true }, extract_fault_addr(output));
    }

    // UBSAN
    if lower.contains("integer overflow") || lower.contains("signed integer overflow") {
        return (CrashKind::IntegerOverflow, None);
    }
    if lower.contains("division by zero") { return (CrashKind::DivisionByZero, None); }
    if lower.contains("reached unreachable code") { return (CrashKind::UnreachableCode, None); }

    // Assertions / aborts
    if lower.contains("assertion") || lower.contains("assert") { return (CrashKind::Assertion, None); }
    if lower.contains("abort") { return (CrashKind::Abort, None); }

    (CrashKind::Unknown, extract_fault_addr(output))
}

fn extract_fault_addr(output: &str) -> Option<u64> {
    // Look for "address 0x<hex>" pattern
    for part in output.split_whitespace() {
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            let clean: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
            if clean.len() >= 4
                && let Ok(v) = u64::from_str_radix(&clean, 16) {
                    return Some(v);
                }
        }
    }
    None
}

/// Classify severity from crash kind and fault address.
#[must_use] 
pub fn classify_severity(kind: &CrashKind, fault_addr: Option<u64>) -> CrashSeverity {
    match kind {
        CrashKind::UseAfterFree | CrashKind::HeapOverflow | CrashKind::StackBufferOverflow => {
            CrashSeverity::Critical
        }
        CrashKind::DoubleFree | CrashKind::GlobalBufferOverflow => CrashSeverity::High,
        CrashKind::OutOfBounds { read: false } => CrashSeverity::Critical,
        CrashKind::OutOfBounds { read: true } | CrashKind::StackOverflow | CrashKind::IntegerOverflow | CrashKind::DivisionByZero => CrashSeverity::Medium,
        CrashKind::NullDeref => {
            // NULL deref at very small address = probably not exploitable
            if fault_addr.is_none_or(|a| a < 0x1000) {
                CrashSeverity::Medium
            } else {
                CrashSeverity::High
            }
        }
        CrashKind::Assertion | CrashKind::Abort | CrashKind::UnreachableCode | CrashKind::Timeout => CrashSeverity::Low,
        _ => CrashSeverity::Unknown,
    }
}

// ─── Crash deduplicator ────────────────────────────────────────────────────────

/// Maintains a database of unique crashes and deduplicates new ones.
pub struct CrashDeduplicator {
    seen: HashMap<u64 /* dedup_hash */, CrashRecord>,
    next_id: u64,
    frame_depth: usize,
}

impl CrashDeduplicator {
    #[must_use] 
    pub fn new(frame_depth: usize) -> Self {
        Self { seen: HashMap::new(), next_id: 1, frame_depth }
    }

    /// Try to add a crash. Returns `Some(record)` if it is new, `None` if duplicate.
    pub fn add(
        &mut self,
        kind: CrashKind,
        frames: Vec<StackFrame>,
        reproducer: Vec<u8>,
        sanitizer_output: Option<String>,
        fault_addr: Option<u64>,
        run_id: u64,
    ) -> Option<&CrashRecord> {
        let dedup_hash = compute_dedup_hash(&frames, self.frame_depth);
        if let Some(existing) = self.seen.get_mut(&dedup_hash) {
            existing.occurrence_count += 1;
            return None;
        }

        let severity = classify_severity(&kind, fault_addr);
        let root_cause_notes = self.analyze_root_cause(&kind, &frames, fault_addr);
        let id = self.next_id;
        self.next_id += 1;

        let record = CrashRecord {
            id,
            dedup_hash,
            kind,
            severity,
            signal: None,
            fault_address: fault_addr,
            stack_trace: frames,
            reproducer,
            minimized_reproducer: None,
            sanitizer_output,
            root_cause_notes,
            first_seen_run: run_id,
            occurrence_count: 1,
        };

        self.seen.insert(dedup_hash, record);
        self.seen.get(&dedup_hash)
    }

    fn analyze_root_cause(&self, kind: &CrashKind, frames: &[StackFrame], fault_addr: Option<u64>) -> Vec<String> {
        let mut notes = Vec::new();
        match kind {
            CrashKind::NullDeref => {
                notes.push("NULL pointer dereference — check all pointer validity before use.".into());
                if let Some(frame) = frames.first()
                    && let Some(sym) = &frame.symbol {
                        notes.push(format!("Crash site function: {sym}"));
                    }
            }
            CrashKind::HeapOverflow => {
                notes.push("Heap buffer overflow — likely missing bounds check on buffer write.".into());
                if let Some(addr) = fault_addr {
                    notes.push(format!("Fault at {addr:#x} — check allocation size vs. access size."));
                }
            }
            CrashKind::UseAfterFree => {
                notes.push("Use-after-free — object accessed after deallocation.".into());
                notes.push("Look for double ownership or escaping references.".into());
            }
            CrashKind::IntegerOverflow => {
                notes.push("Integer overflow — consider using checked arithmetic or sanitized casts.".into());
            }
            _ => {}
        }

        // Stack-based heuristics
        let has_memcpy = frames.iter().any(|f| f.symbol.as_deref().is_some_and(|s| s.contains("memcpy") || s.contains("memmove")));
        if has_memcpy { notes.push("Stack contains memcpy/memmove — possible length mismatch.".into()); }

        let has_malloc = frames.iter().any(|f| f.symbol.as_deref().is_some_and(|s| s.contains("malloc") || s.contains("realloc")));
        if has_malloc { notes.push("Stack contains malloc/realloc — check returned pointer and size.".into()); }

        notes
    }

    /// Return all unique crashes sorted by severity (Critical first).
    #[must_use] 
    pub fn unique_crashes(&self) -> Vec<&CrashRecord> {
        let mut v: Vec<&CrashRecord> = self.seen.values().collect();
        v.sort_by(|a, b| a.severity.cmp(&b.severity));
        v
    }

    #[must_use] 
    pub fn crash_count(&self) -> usize { self.seen.len() }

    /// Print a triage report.
    #[must_use] 
    pub fn triage_report(&self) -> String {
        let mut out = String::new();
        writeln!(out, "╔══════════════════════════════════════╗").ok();
        writeln!(out, "║          Crash Triage Report         ║").ok();
        writeln!(out, "╚══════════════════════════════════════╝").ok();
        writeln!(out, "Unique crashes: {}", self.crash_count()).ok();
        writeln!(out).ok();

        let mut crashes = self.unique_crashes();
        crashes.sort_by(|a, b| a.severity.cmp(&b.severity));

        for cr in &crashes {
            writeln!(out, "{}", cr.summary()).ok();
            writeln!(out, "  Occurrences : {}", cr.occurrence_count).ok();
            writeln!(out, "  Reproducer  : {} bytes", cr.reproducer.len()).ok();
            if let Some(min) = &cr.minimized_reproducer {
                writeln!(out, "  Minimized   : {} bytes", min.len()).ok();
            }
            if !cr.root_cause_notes.is_empty() {
                writeln!(out, "  Root cause  :").ok();
                for note in &cr.root_cause_notes {
                    writeln!(out, "    - {note}").ok();
                }
            }
            if !cr.stack_trace.is_empty() {
                writeln!(out, "  Stack trace :").ok();
                for frame in cr.stack_trace.iter().take(5) {
                    writeln!(out, "    {frame}").ok();
                }
                if cr.stack_trace.len() > 5 {
                    writeln!(out, "    ... ({} more frames)", cr.stack_trace.len() - 5).ok();
                }
            }
            writeln!(out).ok();
        }
        out
    }
}

// ─── Reproducer minimizer ─────────────────────────────────────────────────────

/// Minimizes a crash reproducer by removing bytes that are not needed to
/// trigger the crash, using a binary-search / delta-debugging approach.
pub struct ReproducerMinimizer<F: Fn(&[u8]) -> bool> {
    /// Predicate: returns `true` if the input still triggers the crash.
    still_crashes: F,
    /// Maximum minimization iterations.
    max_iterations: usize,
}

impl<F: Fn(&[u8]) -> bool> ReproducerMinimizer<F> {
    pub const fn new(still_crashes: F, max_iterations: usize) -> Self {
        Self { still_crashes, max_iterations }
    }

    /// Run delta-debugging minimization (RFC 1 algorithm).
    pub fn minimize(&self, input: &[u8]) -> Vec<u8> {
        let mut current = input.to_vec();
        let mut iterations = 0;

        // Stage 1: try to halve the input repeatedly
        while current.len() > 1 && iterations < self.max_iterations {
            let half = current.len() / 2;
            // Try first half
            if (self.still_crashes)(&current[..half]) {
                current = current[..half].to_vec();
                iterations += 1;
                continue;
            }
            // Try second half
            if (self.still_crashes)(&current[half..]) {
                current = current[half..].to_vec();
                iterations += 1;
                continue;
            }
            break;
        }

        // Stage 2: try removing individual bytes (one at a time from the front)
        let mut i = 0;
        while i < current.len() && iterations < self.max_iterations {
            let mut candidate = current.clone();
            candidate.remove(i);
            if (self.still_crashes)(&candidate) {
                current = candidate;
                // don't advance i — the removed byte closed the gap
            } else {
                i += 1;
            }
            iterations += 1;
        }

        current
    }
}

// ─── Stack trace parser ───────────────────────────────────────────────────────

/// Parse a text-format stack trace (ASAN / GDB / lldb style) into `StackFrame`s.
#[must_use] 
pub fn parse_stack_trace(text: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // ASAN format: `    #0 0x4005f7 in parse_input src/parse.c:42`
        if let Some(rest) = line.strip_prefix('#') {
            let mut parts = rest.splitn(2, ' ');
            let frame_no: usize = parts.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let remainder = parts.next().unwrap_or("").trim();

            let (pc_str, sym_rest) = remainder.split_once(' ').unwrap_or((remainder, ""));
            let pc = parse_hex_addr(pc_str).unwrap_or(0);

            let (symbol, file_line) = sym_rest.strip_prefix("in ").map_or((None, None), |rest| {
                let (sym, fl) = rest.split_once(' ').unwrap_or((rest, ""));
                (Some(sym.to_string()), if fl.is_empty() { None } else { Some(fl.to_string()) })
            });

            frames.push(StackFrame { frame_no, pc, symbol, module: None, offset: 0, file_line });
        }
        // GDB / lldb format: `0x00007f... in parse_input () at src/parse.c:42`
        else if line.starts_with("0x") {
            let (pc_str, rest) = line.split_once(' ').unwrap_or((line, ""));
            let pc = parse_hex_addr(pc_str).unwrap_or(0);
            let symbol = rest.strip_prefix("in ").map(|s| s.split_once(' ').map_or(s, |(n, _)| n).to_string());
            let frame_no = frames.len();
            frames.push(StackFrame { frame_no, pc, symbol, module: None, offset: 0, file_line: None });
        }
    }
    frames
}

fn parse_hex_addr(s: &str) -> Option<u64> {
    s.trim().strip_prefix("0x").or_else(|| s.trim().strip_prefix("0X"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

// ─── Crash signature ──────────────────────────────────────────────────────────

/// A compact signature string that uniquely identifies a crash class.
///
/// Format: `KIND:frame0_sym:frame1_sym:...`
#[must_use] 
pub fn compute_crash_signature(record: &CrashRecord, depth: usize) -> String {
    let frames: Vec<&str> = record.stack_trace.iter()
        .take(depth)
        .filter_map(|f| f.symbol.as_deref())
        .collect();
    format!("{}:{}", record.kind, frames.join(":"))
}

// ─── Crash export ─────────────────────────────────────────────────────────────

/// Export a `CrashRecord` as a JSON value.
#[must_use] 
pub fn export_crash_json(record: &CrashRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "kind": format!("{}", record.kind),
        "severity": format!("{}", record.severity),
        "dedup_hash": format!("{:#x}", record.dedup_hash),
        "fault_address": record.fault_address,
        "occurrence_count": record.occurrence_count,
        "first_seen_run": record.first_seen_run,
        "reproducer_len": record.reproducer.len(),
        "minimized_len": record.minimized_reproducer.as_ref().map(std::vec::Vec::len),
        "stack_depth": record.stack_trace.len(),
        "root_cause_notes": record.root_cause_notes,
        "signature": compute_crash_signature(record, 3),
    })
}

/// Export all crashes from a deduplicator as a JSON array.
#[must_use] 
pub fn export_all_crashes_json(dedup: &CrashDeduplicator) -> serde_json::Value {
    let arr: Vec<_> = dedup.unique_crashes().iter().map(|r| export_crash_json(r)).collect();
    serde_json::Value::Array(arr)
}

// ─── Crash clustering ────────────────────────────────────────────────────────

/// Group crashes by kind for batch analysis.
#[must_use] 
pub fn group_by_kind(crashes: &[&CrashRecord]) -> HashMap<String, Vec<u64>> {
    let mut map: HashMap<String, Vec<u64>> = HashMap::new();
    for cr in crashes {
        map.entry(format!("{}", cr.kind)).or_default().push(cr.id);
    }
    map
}

/// Group crashes by severity.
#[must_use] 
pub fn group_by_severity(crashes: &[&CrashRecord]) -> HashMap<CrashSeverity, Vec<u64>> {
    let mut map: HashMap<CrashSeverity, Vec<u64>> = HashMap::new();
    for cr in crashes {
        map.entry(cr.severity.clone()).or_default().push(cr.id);
    }
    map
}

/// Parse GDB `backtrace` / `bt` output format.
#[must_use] 
pub fn parse_gdb_backtrace(text: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // GDB format: `#0  0x00007ffff7a12345 in parse_input (data=0x...) at src/parse.c:42`
        if let Some(rest) = line.strip_prefix('#') {
            let (num_str, rest) = rest.split_once(' ').unwrap_or((rest, ""));
            let frame_no: usize = num_str.trim().parse().unwrap_or(frames.len());
            let rest = rest.trim();

            // PC can be "0x..." or just part of "in FUNC (...)"
            let (pc, sym_part) = if rest.starts_with("0x") || rest.starts_with("0X") {
                let (pc_str, r) = rest.split_once(' ').unwrap_or((rest, ""));
                (parse_hex_addr(pc_str).unwrap_or(0), r)
            } else {
                (0, rest)
            };

            let symbol = sym_part.trim_start_matches("in ").split_once(' ').map(|(s, _)| s).map_or_else(|| if sym_part.is_empty() {
                None
            } else {
                Some(sym_part.split(' ').next().unwrap_or("").to_string())
            }, |s| Some(s.to_string()));

            let file_line = if sym_part.contains("at ") {
                sym_part.split("at ").nth(1).map(|s| s.trim().to_string())
            } else { None };

            frames.push(StackFrame { frame_no, pc, symbol, module: None, offset: 0, file_line });
        }
    }
    frames
}

/// Compute a severity histogram for reporting.
#[must_use] 
pub fn severity_histogram(crashes: &[&CrashRecord]) -> Vec<(CrashSeverity, usize)> {
    let grouped = group_by_severity(crashes);
    let mut hist: Vec<(CrashSeverity, usize)> = grouped.into_iter().map(|(s, ids)| (s, ids.len())).collect();
    hist.sort_by(|a, b| a.0.cmp(&b.0));
    hist
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(pc: u64, sym: &str) -> StackFrame {
        StackFrame { frame_no: 0, pc, symbol: Some(sym.into()), module: Some("target".into()), offset: 0, file_line: None }
    }

    #[test]
    fn test_parse_asan_heap_overflow() {
        let output = "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000001234 at pc 0x...";
        let (kind, addr) = parse_sanitizer_output(output);
        assert_eq!(kind, CrashKind::HeapOverflow);
        assert_eq!(addr, Some(0x6020_0000_1234));
    }

    #[test]
    fn test_parse_uaf() {
        let output = "heap-use-after-free READ size 8 at 0x60200000ef80";
        let (kind, _) = parse_sanitizer_output(output);
        assert_eq!(kind, CrashKind::UseAfterFree);
    }

    #[test]
    fn test_dedup_same_stack() {
        let mut dedup = CrashDeduplicator::new(3);
        let frames = vec![make_frame(0x4000, "parse"), make_frame(0x3000, "main")];
        let r1 = dedup.add(CrashKind::HeapOverflow, frames.clone(), b"aaa".to_vec(), None, None, 1);
        assert!(r1.is_some());
        let r2 = dedup.add(CrashKind::HeapOverflow, frames, b"bbb".to_vec(), None, None, 2);
        assert!(r2.is_none()); // duplicate
        assert_eq!(dedup.crash_count(), 1);
    }

    #[test]
    fn test_dedup_different_stack() {
        let mut dedup = CrashDeduplicator::new(3);
        let frames1 = vec![make_frame(0x4000, "parse")];
        let frames2 = vec![make_frame(0x5000, "decode")];
        dedup.add(CrashKind::HeapOverflow, frames1, b"aaa".to_vec(), None, None, 1);
        dedup.add(CrashKind::HeapOverflow, frames2, b"bbb".to_vec(), None, None, 2);
        assert_eq!(dedup.crash_count(), 2);
    }

    #[test]
    fn test_severity_classification() {
        assert_eq!(classify_severity(&CrashKind::UseAfterFree, None), CrashSeverity::Critical);
        assert_eq!(classify_severity(&CrashKind::NullDeref, Some(0x0)), CrashSeverity::Medium);
        assert_eq!(classify_severity(&CrashKind::Assertion, None), CrashSeverity::Low);
    }

    #[test]
    fn test_minimizer() {
        // Crash triggered by any input containing 0xff in the first 4 bytes
        let trigger = |data: &[u8]| data.iter().take(4).any(|&b| b == 0xff);
        let minimizer = ReproducerMinimizer::new(trigger, 100);
        let input = {
            let mut v = vec![0u8; 64];
            v[2] = 0xff;
            v
        };
        let minimized = minimizer.minimize(&input);
        assert!(minimized.len() <= input.len());
        assert!(trigger(&minimized), "minimized must still crash");
    }

    #[test]
    fn test_triage_report_format() {
        let mut dedup = CrashDeduplicator::new(3);
        let frames = vec![make_frame(0x4000, "parse_input")];
        dedup.add(CrashKind::HeapOverflow, frames, b"crash_input".to_vec(), None, Some(0x0060_1000), 1);
        let report = dedup.triage_report();
        assert!(report.contains("heap-overflow"));
        assert!(report.contains("CRITICAL"));
    }
}
