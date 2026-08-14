//! `tsan_report_parser` — Parse `ThreadSanitizer` (`TSan`) text reports.
//!
//! `TSan` reports are emitted when a data race, deadlock, or other
//! thread-safety violation is detected.  A typical data-race report looks like:
//!
//! ```text
//! ==================
//! WARNING: ThreadSanitizer: data race (pid=12345)
//!   Write of size 4 at 0x7b040000f7d0 by thread T1:
//!     #0 0x40123f in write_func race.c:10:3
//!   Previous read of size 4 at 0x7b040000f7d0 by main thread:
//!     #0 0x401300 in read_func race.c:20:5
//! ==================
//! SUMMARY: ThreadSanitizer: data race race.c:10 in write_func
//! ```

use std::collections::HashMap;

// ── RaceAccess ────────────────────────────────────────────────────────────────

/// Whether a racing access is a read or a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDirection {
    /// Memory read.
    Read,
    /// Memory write.
    Write,
}

impl std::fmt::Display for AccessDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
        }
    }
}

// ── RaceLocation ──────────────────────────────────────────────────────────────

/// A single location (stack frame) involved in a data race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceLocation {
    /// Frame index within the race's call stack.
    pub frame_index: usize,
    /// Program counter address.
    pub pc: Option<u64>,
    /// Function name.
    pub function: Option<String>,
    /// Source file.
    pub file: Option<String>,
    /// Line number.
    pub line: Option<u32>,
    /// Column number.
    pub column: Option<u32>,
}

impl RaceLocation {
    /// Create an empty location with the given frame index.
    #[must_use]
    pub const fn empty(frame_index: usize) -> Self {
        Self {
            frame_index,
            pc: None,
            function: None,
            file: None,
            line: None,
            column: None,
        }
    }

    /// Short human-readable description.
    #[must_use]
    pub fn describe(&self) -> String {
        let pc = self
            .pc
            .map_or_else(|| "?".to_owned(), |a| format!("0x{a:x}"));
        let func = self.function.as_deref().unwrap_or("<unknown>");
        let loc = match (&self.file, self.line) {
            (Some(f), Some(l)) => format!(" {f}:{l}"),
            (Some(f), None) => format!(" {f}"),
            _ => String::new(),
        };
        format!("#{} {} in {}{}", self.frame_index, pc, func, loc)
    }
}

impl std::fmt::Display for RaceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

// ── DataRace ──────────────────────────────────────────────────────────────────

/// A single data race detected by `TSan`.
#[derive(Debug, Clone)]
pub struct DataRace {
    /// Memory address where the race occurred.
    pub address: Option<u64>,
    /// Size of the racing access in bytes.
    pub access_size: Option<usize>,
    /// Direction of the first (current) access.
    pub access_dir: AccessDirection,
    /// Thread identifier of the first access (e.g. `"T1"` or `"main"`).
    pub access_thread: Option<String>,
    /// Stack frames of the current (first-seen) access.
    pub access_stack: Vec<RaceLocation>,
    /// Direction of the prior (previous) access.
    pub prior_dir: AccessDirection,
    /// Thread identifier of the prior access.
    pub prior_thread: Option<String>,
    /// Stack frames of the previous access.
    pub prior_stack: Vec<RaceLocation>,
}

impl DataRace {
    /// Return a one-line summary of the race.
    #[must_use]
    pub fn summary(&self) -> String {
        let addr = self
            .address
            .map_or_else(|| "?".to_owned(), |a| format!("0x{a:x}"));
        let size = self
            .access_size
            .map_or_else(|| "?".to_owned(), |s| s.to_string());
        let thread = self.access_thread.as_deref().unwrap_or("?");
        format!(
            "DataRace({} {} bytes at {} by {})",
            self.access_dir, size, addr, thread
        )
    }
}

impl std::fmt::Display for DataRace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary())
    }
}

// ── TsanStackFrame ────────────────────────────────────────────────────────────

/// A single stack frame in a `TSan` report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsanStackFrame {
    /// Zero-based frame index.
    pub index: usize,
    /// Program counter.
    pub pc: Option<u64>,
    /// Function name.
    pub function: Option<String>,
    /// Source file.
    pub file: Option<String>,
    /// Line number.
    pub line: Option<u32>,
    /// Column number.
    pub column: Option<u32>,
}

impl TsanStackFrame {
    /// Create an empty frame.
    #[must_use]
    pub const fn empty(index: usize) -> Self {
        Self {
            index,
            pc: None,
            function: None,
            file: None,
            line: None,
            column: None,
        }
    }

    /// Format the frame as a single line.
    #[must_use]
    pub fn display_line(&self) -> String {
        let pc = self
            .pc
            .map_or_else(|| "???".to_owned(), |a| format!("0x{a:x}"));
        let func = self.function.as_deref().unwrap_or("<unknown>");
        let loc = match (&self.file, self.line, self.column) {
            (Some(f), Some(l), Some(c)) => format!(" {f}:{l}:{c}"),
            (Some(f), Some(l), None) => format!(" {f}:{l}"),
            (Some(f), None, _) => format!(" {f}"),
            _ => String::new(),
        };
        format!("  #{} {} in {}{}", self.index, pc, func, loc)
    }
}

impl std::fmt::Display for TsanStackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_line())
    }
}

// ── TsanReport ────────────────────────────────────────────────────────────────

/// A fully-parsed `ThreadSanitizer` report.
#[derive(Debug, Clone)]
pub struct TsanReport {
    /// Process ID extracted from the header.
    pub pid: Option<u32>,
    /// Violation kind, e.g. `"data race"`, `"deadlock"`, `"lock-order-inversion"`.
    pub kind: String,
    /// All data races found in this report block.
    pub races: Vec<DataRace>,
    /// Frames of the thread creation or mutex lock stack, if present.
    pub thread_create_stack: Vec<TsanStackFrame>,
    /// The SUMMARY line, if present.
    pub summary: Option<String>,
    /// Complete raw text of the report block.
    pub raw: String,
}

impl TsanReport {
    /// Return the number of distinct data races.
    #[must_use]
    pub const fn race_count(&self) -> usize {
        self.races.len()
    }

    /// Return the top function from the first race's access stack, if any.
    #[must_use]
    pub fn top_function(&self) -> Option<&str> {
        self.races
            .first()
            .and_then(|r| r.access_stack.first())
            .and_then(|l| l.function.as_deref())
    }

    /// A one-line headline for this report.
    #[must_use]
    pub fn headline(&self) -> String {
        let pid = self
            .pid
            .map_or_else(|| "?".to_owned(), |p| p.to_string());
        format!(
            "[pid={}] TSan: {} ({} races)",
            pid,
            self.kind,
            self.races.len()
        )
    }
}

impl std::fmt::Display for TsanReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.headline())
    }
}

// ── TsanReportParser ──────────────────────────────────────────────────────────

/// Stateful parser for `ThreadSanitizer` text output.
#[derive(Debug, Default)]
pub struct TsanReportParser {
    /// Collect reports even when the summary line is missing.
    pub lenient: bool,
}

impl TsanReportParser {
    /// Create a strict parser (default).
    #[must_use]
    pub const fn new() -> Self {
        Self { lenient: false }
    }

    /// Create a lenient parser that accepts reports without a SUMMARY line.
    #[must_use]
    pub const fn lenient() -> Self {
        Self { lenient: true }
    }

    /// Maximum lines processed per `parse_all` call (dos-memory-exhaustion guard).
    const MAX_LINES: usize = 1_000_000;

    /// Parse all `TSan` reports from `text`.
    #[must_use]
    pub fn parse_all(&self, text: &str) -> Vec<TsanReport> {
        let lines: Vec<&str> = text.lines().take(Self::MAX_LINES).collect();
        let starts: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| Self::is_tsan_header(l))
            .map(|(i, _)| i)
            .collect();

        if starts.is_empty() {
            return Vec::new();
        }

        let mut reports = Vec::new();
        for (idx, &start) in starts.iter().enumerate() {
            let end = if idx + 1 < starts.len() {
                starts[idx + 1]
            } else {
                lines.len()
            };
            let block = lines[start..end].join("\n");
            reports.push(Self::parse_block(&block));
        }
        reports
    }

    /// Parse a single `TSan` report block.
    #[must_use]
    pub fn parse_block(block: &str) -> TsanReport {
        let pid = Self::extract_pid(block);
        let kind = Self::extract_kind(block);
        let races = Self::extract_races(block);
        let thread_create_stack = Self::parse_thread_create_stack(block);
        let summary = Self::extract_summary(block);

        TsanReport {
            pid,
            kind,
            races,
            thread_create_stack,
            summary,
            raw: block.to_owned(),
        }
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn is_tsan_header(line: &str) -> bool {
        line.contains("WARNING: ThreadSanitizer:")
            || line.contains("ERROR: ThreadSanitizer:")
    }

    fn extract_pid(block: &str) -> Option<u32> {
        for line in block.lines() {
            if line.contains("ThreadSanitizer") {
                if let Some(idx) = line.find("pid=") {
                    let rest = &line[idx + 4..];
                    let s: String = rest
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    if let Ok(p) = s.parse::<u32>() {
                        return Some(p);
                    }
                }
                // Also try ==PID== prefix.
                if let Some(stripped) = line.strip_prefix("==") {
                    let s: String = stripped
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    if let Ok(p) = s.parse::<u32>() {
                        return Some(p);
                    }
                }
            }
        }
        None
    }

    fn extract_kind(block: &str) -> String {
        for line in block.lines() {
            for marker in &["WARNING: ThreadSanitizer:", "ERROR: ThreadSanitizer:"] {
                if let Some(after) = line.find(marker).map(|i| &line[i + marker.len()..]) {
                    let t = after.trim();
                    // Strip trailing " (pid=N)"
                    let t = t.find(" (pid=").map_or(t, |p| t[..p].trim());
                    if !t.is_empty() {
                        return t.trim_end_matches(':').to_owned();
                    }
                }
            }
        }
        "unknown".to_owned()
    }

    fn extract_summary(block: &str) -> Option<String> {
        block
            .lines()
            .find(|l| l.contains("SUMMARY:"))
            .map(|l| l.trim().to_owned())
    }

    fn extract_races(block: &str) -> Vec<DataRace> {
        let lines: Vec<&str> = block.lines().collect();
        let mut races = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim().to_ascii_lowercase();
            if (t.starts_with("write of size") || t.starts_with("read of size"))
                && t.contains("at 0x")
            {
                let (dir, size, addr, thread) = Self::parse_access_header(lines[i]);
                let (stack, next_i) = Self::collect_frames(&lines, i + 1);
                i = next_i;

                // Look for the "Previous read/write" line immediately after.
                let mut prior_dir = AccessDirection::Read;
                let mut prior_size = None;
                let mut prior_addr = None;
                let mut prior_thread = None;
                let mut prior_stack = Vec::new();

                if i < lines.len() {
                    let pt = lines[i].trim().to_ascii_lowercase();
                    if pt.starts_with("previous write") || pt.starts_with("previous read") {
                        let (pd, ps, pa, pth) = Self::parse_access_header(lines[i]);
                        prior_dir = pd;
                        prior_size = ps;
                        prior_addr = pa;
                        prior_thread = pth;
                        let (ps2, next2) = Self::collect_frames(&lines, i + 1);
                        prior_stack = ps2;
                        i = next2;
                    }

                    let _ = (prior_size, prior_addr);
                }

                races.push(DataRace {
                    address: addr,
                    access_size: size,
                    access_dir: dir,
                    access_thread: thread,
                    access_stack: stack
                        .into_iter()
                        .enumerate()
                        .map(|(fi, f)| RaceLocation {
                            frame_index: fi,
                            pc: f.pc,
                            function: f.function,
                            file: f.file,
                            line: f.line,
                            column: f.column,
                        })
                        .collect(),
                    prior_dir,
                    prior_thread,
                    prior_stack: prior_stack
                        .into_iter()
                        .enumerate()
                        .map(|(fi, f)| RaceLocation {
                            frame_index: fi,
                            pc: f.pc,
                            function: f.function,
                            file: f.file,
                            line: f.line,
                            column: f.column,
                        })
                        .collect(),
                });
            } else {
                i += 1;
            }
        }
        races
    }

    fn parse_access_header(line: &str) -> (AccessDirection, Option<usize>, Option<u64>, Option<String>) {
        let lower = line.trim().to_ascii_lowercase();
        let dir = if lower.starts_with("write") || lower.starts_with("previous write") {
            AccessDirection::Write
        } else {
            AccessDirection::Read
        };
        let size = extract_usize_after(line, "size");
        let addr = extract_hex_after(line, "at ");
        let thread = extract_thread_id(line);
        (dir, size, addr, thread)
    }

    fn collect_frames(lines: &[&str], start: usize) -> (Vec<TsanStackFrame>, usize) {
        let mut frames = Vec::new();
        let mut i = start;
        while i < lines.len() {
            let t = lines[i].trim();
            if let Some(f) = Self::try_parse_frame(t) {
                frames.push(f);
            } else if !frames.is_empty() && !t.is_empty() && !t.starts_with('#') {
                break;
            }
            i += 1;
        }
        (frames, i)
    }

    fn parse_thread_create_stack(block: &str) -> Vec<TsanStackFrame> {
        let lines: Vec<&str> = block.lines().collect();
        let start = lines
            .iter()
            .position(|l| l.to_ascii_lowercase().contains("thread t")
                && l.to_ascii_lowercase().contains("created"))
            .map_or(lines.len(), |i| i + 1);
        let mut frames = Vec::new();
        for line in &lines[start..] {
            let t = line.trim();
            if let Some(f) = Self::try_parse_frame(t) {
                frames.push(f);
            } else if !frames.is_empty() && !t.is_empty() && !t.starts_with('#') {
                break;
            }
        }
        frames
    }

    fn try_parse_frame(s: &str) -> Option<TsanStackFrame> {
        let s = s.trim();
        if !s.starts_with('#') {
            return None;
        }
        let s = &s[1..];
        let mut it = s.splitn(2, ' ');
        let idx_str = it.next()?;
        let index: usize = idx_str.trim().parse().ok()?;
        let rest = it.next().unwrap_or("").trim();

        let (pc, rest) = if rest.starts_with("0x") || rest.starts_with("0X") {
            let end = rest.find(' ').unwrap_or(rest.len());
            (parse_hex(rest[..end].trim()), rest[end..].trim())
        } else {
            (None, rest)
        };

        let (function, file, line, column) = rest.strip_prefix("in ").map_or_else(|| (
                if rest.is_empty() { None } else { Some(rest.to_owned()) },
                None,
                None,
                None,
            ), |after| {
            let mut parts = after.splitn(2, ' ');
            let func = parts.next().map(str::to_owned);
            let loc = parts.next().unwrap_or("").trim();
            let (f, l, c) = parse_location(loc);
            (func, f, l, c)
        });

        Some(TsanStackFrame {
            index,
            pc,
            function,
            file,
            line,
            column,
        })
    }
}

/// Parse all `TSan` reports from `text` and return them.
#[must_use]
pub fn parse_tsan_output(text: &str) -> Vec<TsanReport> {
    TsanReportParser::new().parse_all(text)
}

// ── TsanReportStats ───────────────────────────────────────────────────────────

/// Aggregate statistics over a set of `TSan` reports.
#[derive(Debug, Clone, Default)]
pub struct TsanReportStats {
    /// Total reports parsed.
    pub total: usize,
    /// Reports by violation kind.
    pub by_kind: HashMap<String, usize>,
    /// Top-frame functions across all races.
    pub top_functions: HashMap<String, usize>,
    /// Total distinct data races.
    pub total_races: usize,
}

impl TsanReportStats {
    /// Compute stats from a slice of reports.
    #[must_use]
    pub fn compute(reports: &[TsanReport]) -> Self {
        let mut stats = Self { total: reports.len(), ..Self::default() };
        for r in reports {
            *stats.by_kind.entry(r.kind.clone()).or_insert(0) += 1;
            stats.total_races += r.race_count();
            if let Some(f) = r.top_function() {
                *stats.top_functions.entry(f.to_owned()).or_insert(0) += 1;
            }
        }
        stats
    }

    /// Most common violation kind.
    #[must_use]
    pub fn dominant_kind(&self) -> Option<&str> {
        // Total order on ties, so the answer does not vary between runs.
        self.by_kind
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, _)| k.as_str())
    }
}

// ── private helpers ───────────────────────────────────────────────────────────

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let clean: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
    u64::from_str_radix(&clean, 16).ok()
}

fn parse_location(s: &str) -> (Option<String>, Option<u32>, Option<u32>) {
    if s.is_empty() {
        return (None, None, None);
    }
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    match parts.as_slice() {
        [col_s, line_s, file] => {
            let col = col_s.parse::<u32>().ok();
            if let Ok(ln) = line_s.parse::<u32>() {
                return (Some((*file).to_owned()), Some(ln), col);
            }
            (Some(s.to_owned()), None, None)
        }
        [line_s, file] => (Some((*file).to_owned()), line_s.parse::<u32>().ok(), None),
        [file] => (Some((*file).to_owned()), None, None),
        _ => (Some(s.to_owned()), None, None),
    }
}

fn extract_usize_after(s: &str, keyword: &str) -> Option<usize> {
    let lower = s.to_ascii_lowercase();
    let idx = lower.find(keyword)?;
    let rest = s[idx + keyword.len()..].trim_start();
    let tok: String = rest.chars().take_while(char::is_ascii_digit).collect();
    tok.parse().ok()
}

fn extract_hex_after(s: &str, keyword: &str) -> Option<u64> {
    let idx = s.find(keyword)?;
    let rest = s[idx + keyword.len()..].trim_start();
    let tok: String = rest
        .chars()
        .take_while(|c| c.is_ascii_hexdigit() || *c == 'x' || *c == 'X')
        .collect();
    parse_hex(&tok)
}

fn extract_thread_id(s: &str) -> Option<String> {
    // Look for "by thread T3:" or "by main thread:"
    let lower = s.to_ascii_lowercase();
    if let Some(idx) = lower.find("by thread ") {
        let rest = &s[idx + "by thread ".len()..];
        let id: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric())
            .collect();
        if !id.is_empty() {
            return Some(id);
        }
    }
    if lower.contains("by main thread") {
        return Some("main".to_owned());
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r"==================
WARNING: ThreadSanitizer: data race (pid=99)
  Write of size 4 at 0xdeadbeef by thread T1:
    #0 0x401000 in writer_fn race.c:10:3
    #1 0x401100 in thread_entry race.c:30:1
  Previous read of size 4 at 0xdeadbeef by main thread:
    #0 0x401200 in reader_fn race.c:20:5
    #1 0x401300 in main race.c:40:1

SUMMARY: ThreadSanitizer: data race race.c:10 in writer_fn
==================
";

    #[test]
    fn test_parse_pid() {
        let reports = parse_tsan_output(SAMPLE);
        assert!(!reports.is_empty());
        assert_eq!(reports[0].pid, Some(99));
    }

    #[test]
    fn test_parse_kind() {
        let reports = parse_tsan_output(SAMPLE);
        assert_eq!(reports[0].kind, "data race");
    }

    #[test]
    fn test_race_count() {
        let reports = parse_tsan_output(SAMPLE);
        assert_eq!(reports[0].race_count(), 1);
    }

    #[test]
    fn test_race_access_dir() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert_eq!(race.access_dir, AccessDirection::Write);
    }

    #[test]
    fn test_race_prior_dir() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert_eq!(race.prior_dir, AccessDirection::Read);
    }

    #[test]
    fn test_race_address() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert_eq!(race.address, Some(0xdead_beef));
    }

    #[test]
    fn test_race_access_size() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert_eq!(race.access_size, Some(4));
    }

    #[test]
    fn test_race_access_thread() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert_eq!(race.access_thread.as_deref(), Some("T1"));
    }

    #[test]
    fn test_race_prior_thread() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert_eq!(race.prior_thread.as_deref(), Some("main"));
    }

    #[test]
    fn test_race_access_stack_not_empty() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert!(!race.access_stack.is_empty());
    }

    #[test]
    fn test_race_access_stack_function() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert_eq!(race.access_stack[0].function.as_deref(), Some("writer_fn"));
    }

    #[test]
    fn test_race_prior_stack_not_empty() {
        let reports = parse_tsan_output(SAMPLE);
        let race = &reports[0].races[0];
        assert!(!race.prior_stack.is_empty());
    }

    #[test]
    fn test_summary_present() {
        let reports = parse_tsan_output(SAMPLE);
        assert!(reports[0].summary.is_some());
        assert!(reports[0].summary.as_deref().unwrap().contains("SUMMARY"));
    }

    #[test]
    fn test_top_function() {
        let reports = parse_tsan_output(SAMPLE);
        assert_eq!(reports[0].top_function(), Some("writer_fn"));
    }

    #[test]
    fn test_headline() {
        let reports = parse_tsan_output(SAMPLE);
        let h = reports[0].headline();
        assert!(h.contains("TSan"));
        assert!(h.contains("99"));
    }

    #[test]
    fn test_display() {
        let reports = parse_tsan_output(SAMPLE);
        let s = reports[0].to_string();
        assert!(s.contains("TSan"));
    }

    #[test]
    fn test_no_reports() {
        let r = parse_tsan_output("nothing here");
        assert!(r.is_empty());
    }

    #[test]
    fn test_multiple_reports() {
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let reports = parse_tsan_output(&two);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_data_race_summary() {
        let reports = parse_tsan_output(SAMPLE);
        let s = reports[0].races[0].summary();
        assert!(s.contains("DataRace"));
    }

    #[test]
    fn test_data_race_display() {
        let reports = parse_tsan_output(SAMPLE);
        let s = reports[0].races[0].to_string();
        assert!(s.contains("write") || s.contains("read"));
    }

    #[test]
    fn test_race_location_describe() {
        let loc = RaceLocation {
            frame_index: 0,
            pc: Some(0x1000),
            function: Some("foo".to_owned()),
            file: Some("a.c".to_owned()),
            line: Some(5),
            column: None,
        };
        let d = loc.describe();
        assert!(d.contains("foo"));
        assert!(d.contains("a.c:5"));
    }

    #[test]
    fn test_race_location_empty() {
        let loc = RaceLocation::empty(2);
        assert!(loc.describe().contains("#2"));
    }

    #[test]
    fn test_tsan_stack_frame_empty() {
        let f = TsanStackFrame::empty(1);
        assert!(f.display_line().contains("#1"));
    }

    #[test]
    fn test_tsan_stack_frame_display() {
        let f = TsanStackFrame {
            index: 0,
            pc: Some(0x4000),
            function: Some("bar".to_owned()),
            file: Some("b.c".to_owned()),
            line: Some(9),
            column: Some(1),
        };
        let s = f.display_line();
        assert!(s.contains("bar"));
        assert!(s.contains("b.c:9:1"));
    }

    #[test]
    fn test_access_direction_display() {
        assert_eq!(AccessDirection::Read.to_string(), "read");
        assert_eq!(AccessDirection::Write.to_string(), "write");
    }

    #[test]
    fn test_stats_compute() {
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let reports = parse_tsan_output(&two);
        let stats = TsanReportStats::compute(&reports);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.total_races, 2);
    }

    #[test]
    fn test_stats_dominant_kind() {
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let reports = parse_tsan_output(&two);
        let stats = TsanReportStats::compute(&reports);
        assert_eq!(stats.dominant_kind(), Some("data race"));
    }

    #[test]
    fn test_raw_preserved() {
        let reports = parse_tsan_output(SAMPLE);
        assert!(reports[0].raw.contains("ThreadSanitizer"));
    }
}
