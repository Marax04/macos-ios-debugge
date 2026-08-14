//! `msan_report_parser` — Parse `MemorySanitizer` (`MSan`) text reports.
//!
//! `MSan` reports are emitted by LLVM's `MemorySanitizer` runtime when a program
//! reads from uninitialised memory.  They have a recognisable header line of
//! the form:
//!
//! ```text
//! ==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
//!   #0 0x4a1234 in foo /home/user/src/foo.c:42:7
//!   ...
//! SUMMARY: MemorySanitizer: use-of-uninitialized-value /path/to/file.c:42 in foo
//! ```

use std::collections::HashMap;

// ── UninitRead ────────────────────────────────────────────────────────────────

/// A single uninitialised-value read event found in an `MSan` report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninitRead {
    /// Program counter where the uninitialized read occurred.
    pub pc: Option<u64>,
    /// Source file where the read occurred.
    pub source_file: Option<String>,
    /// Source line number.
    pub source_line: Option<u32>,
    /// Source column number.
    pub source_col: Option<u32>,
    /// Function name if resolved.
    pub function: Option<String>,
    /// Number of bytes read (if parseable from the report).
    pub size_bytes: Option<usize>,
}

impl UninitRead {
    /// Construct a new `UninitRead` with only a program counter set.
    #[must_use]
    pub const fn from_pc(pc: u64) -> Self {
        Self {
            pc: Some(pc),
            source_file: None,
            source_line: None,
            source_col: None,
            function: None,
            size_bytes: None,
        }
    }

    /// Return a short human-readable description of the read.
    #[must_use]
    pub fn describe(&self) -> String {
        let addr = self
            .pc
            .map_or_else(|| "?".to_owned(), |a| format!("0x{a:x}"));
        let loc = match (&self.source_file, self.source_line) {
            (Some(f), Some(l)) => format!(" at {f}:{l}"),
            (Some(f), None) => format!(" at {f}"),
            _ => String::new(),
        };
        let func = self
            .function
            .as_deref()
            .map_or_else(String::new, |f| format!(" in {f}"));
        format!("UninitRead pc={addr}{func}{loc}")
    }
}

impl std::fmt::Display for UninitRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

// ── MsanStackFrame ────────────────────────────────────────────────────────────

/// A single parsed stack frame from an `MSan` report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsanStackFrame {
    /// Zero-based frame index.
    pub index: usize,
    /// Program counter of the frame.
    pub pc: Option<u64>,
    /// Mangled or demangled function name.
    pub function: Option<String>,
    /// Source file path.
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Column number within the line.
    pub column: Option<u32>,
}

impl MsanStackFrame {
    /// Create a frame with only an index.
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

    /// Format as a single display line.
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

impl std::fmt::Display for MsanStackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_line())
    }
}

// ── MsanReport ────────────────────────────────────────────────────────────────

/// A fully-parsed `MemorySanitizer` report.
#[derive(Debug, Clone)]
pub struct MsanReport {
    /// Operating-system process ID extracted from the header.
    pub pid: Option<u32>,
    /// Error category, e.g. `"use-of-uninitialized-value"`.
    pub error_type: String,
    /// All stack frames at the point of the violation.
    pub stack_frames: Vec<MsanStackFrame>,
    /// Where the uninitialised value was created (origin stack, if any).
    pub origin_frames: Vec<MsanStackFrame>,
    /// Detailed uninitialised-read events extracted from the body.
    pub uninit_reads: Vec<UninitRead>,
    /// The SUMMARY line, if present.
    pub summary: Option<String>,
    /// Complete raw text of this report block.
    pub raw: String,
}

impl MsanReport {
    /// Return the top function name from the crash stack, if any.
    #[must_use]
    pub fn top_function(&self) -> Option<&str> {
        self.stack_frames
            .first()
            .and_then(|f| f.function.as_deref())
    }

    /// Return the number of stack frames.
    #[must_use]
    pub const fn frame_count(&self) -> usize {
        self.stack_frames.len()
    }

    /// Produce a one-line summary of this report.
    #[must_use]
    pub fn headline(&self) -> String {
        let pid = self
            .pid
            .map_or_else(|| "?".to_owned(), |p| p.to_string());
        format!(
            "[pid={}] MSan: {} ({} frames)",
            pid,
            self.error_type,
            self.stack_frames.len()
        )
    }
}

impl std::fmt::Display for MsanReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.headline())
    }
}

// ── MsanReportParser ──────────────────────────────────────────────────────────

/// Parser for `MemorySanitizer` text output.
///
/// Handles multi-report logs as produced by `MSAN_OPTIONS=log_path=…`.
/// Each report begins with a line matching `==<pid>==WARNING: MemorySanitizer:`.
#[derive(Debug, Default)]
pub struct MsanReportParser {
    /// If `true`, the parser stops after the first report.
    pub stop_at_first: bool,
}

impl MsanReportParser {
    /// Create a new parser that processes all reports in the input.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stop_at_first: false,
        }
    }

    /// Create a parser that returns only the first report found.
    #[must_use]
    pub const fn first_only() -> Self {
        Self {
            stop_at_first: true,
        }
    }

    /// Parse all `MSan` reports embedded in `text`.
    ///
    /// Returns an empty `Vec` when no MSan-style report headers are found.
    #[must_use]
    pub fn parse_all(&self, text: &str) -> Vec<MsanReport> {
        let lines: Vec<&str> = text.lines().collect();
        let block_starts: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| Self::is_msan_header(l))
            .map(|(i, _)| i)
            .collect();

        if block_starts.is_empty() {
            return Vec::new();
        }

        let mut reports = Vec::new();
        for (idx, &start) in block_starts.iter().enumerate() {
            let end = if idx + 1 < block_starts.len() {
                block_starts[idx + 1]
            } else {
                lines.len()
            };
            let block = lines[start..end].join("\n");
            reports.push(Self::parse_block(&block));
            if self.stop_at_first {
                break;
            }
        }
        reports
    }

    /// Parse a single `MSan` text block into an [`MsanReport`].
    #[must_use]
    pub fn parse_block(block: &str) -> MsanReport {
        let pid = Self::extract_pid(block);
        let error_type = Self::extract_error_type(block);
        let stack_frames = Self::parse_frames(block, None);
        let origin_frames = Self::parse_frames(block, Some("Uninitialized value was created"));
        let uninit_reads = Self::extract_uninit_reads(block, &stack_frames);
        let summary = Self::extract_summary(block);

        MsanReport {
            pid,
            error_type,
            stack_frames,
            origin_frames,
            uninit_reads,
            summary,
            raw: block.to_owned(),
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn is_msan_header(line: &str) -> bool {
        line.contains("WARNING: MemorySanitizer:")
            || line.contains("ERROR: MemorySanitizer:")
    }

    fn extract_pid(block: &str) -> Option<u32> {
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("==") {
                let pid_str: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(p) = pid_str.parse::<u32>() {
                    return Some(p);
                }
            }
        }
        None
    }

    fn extract_error_type(block: &str) -> String {
        for line in block.lines() {
            for marker in &["WARNING: MemorySanitizer:", "ERROR: MemorySanitizer:"] {
                if let Some(after) = line.find(marker).map(|i| &line[i + marker.len()..]) {
                    let trimmed = after.trim();
                    if !trimmed.is_empty() {
                        return trimmed
                            .split_whitespace()
                            .next()
                            .unwrap_or(trimmed)
                            .trim_end_matches(':')
                            .to_owned();
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

    /// Parse stack frames from `block`, optionally starting after `anchor`.
    fn parse_frames(block: &str, anchor: Option<&str>) -> Vec<MsanStackFrame> {
        let lines: Vec<&str> = block.lines().collect();
        let start = anchor.map_or(0, |a| {
            lines
                .iter()
                .position(|l| l.contains(a))
                .map_or(lines.len(), |i| i + 1)
        });

        let mut frames = Vec::new();
        for line in &lines[start..] {
            let t = line.trim();
            if let Some(f) = Self::try_parse_frame(t) {
                frames.push(f);
            } else if !frames.is_empty()
                && !t.is_empty()
                && !t.starts_with('#')
                && !t.starts_with("0x")
            {
                break;
            }
        }
        frames
    }

    fn try_parse_frame(s: &str) -> Option<MsanStackFrame> {
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
            let addr = parse_hex(rest[..end].trim());
            (addr, rest[end..].trim())
        } else {
            (None, rest)
        };

        let (function, file, line, column) = rest.strip_prefix("in ").map_or_else(|| {
            let func = if rest.is_empty() {
                None
            } else {
                Some(rest.to_owned())
            };
            (func, None, None, None)
        }, |after| {
            let mut parts = after.splitn(2, ' ');
            let func = parts.next().map(str::to_owned);
            let loc = parts.next().unwrap_or("").trim();
            let (f, l, c) = parse_location(loc);
            (func, f, l, c)
        });

        Some(MsanStackFrame {
            index,
            pc,
            function,
            file,
            line,
            column,
        })
    }

    /// Synthesise `UninitRead` records from the first few crash frames.
    fn extract_uninit_reads(
        block: &str,
        frames: &[MsanStackFrame],
    ) -> Vec<UninitRead> {
        // If the report mentions explicit "read of N bytes", extract them.
        let mut reads = Vec::new();
        for line in block.lines() {
            let t = line.trim().to_ascii_lowercase();
            if t.contains("uninitialized") && t.contains("bytes") {
                let size = extract_number_after(line, "bytes").or_else(|| {
                    extract_number_after(line, "size")
                });
                let read = UninitRead {
                    pc: frames.first().and_then(|f| f.pc),
                    source_file: frames.first().and_then(|f| f.file.clone()),
                    source_line: frames.first().and_then(|f| f.line),
                    source_col: frames.first().and_then(|f| f.column),
                    function: frames.first().and_then(|f| f.function.clone()),
                    size_bytes: size,
                };
                reads.push(read);
            }
        }
        // If nothing was found but there are stack frames, synthesise one entry.
        if reads.is_empty() && !frames.is_empty() {
            reads.push(UninitRead {
                pc: frames[0].pc,
                source_file: frames[0].file.clone(),
                source_line: frames[0].line,
                source_col: frames[0].column,
                function: frames[0].function.clone(),
                size_bytes: None,
            });
        }
        reads
    }
}

/// Top-level convenience function: parse the first `MSan` report in `text`.
///
/// Returns `None` if no `MSan` report header is found.
#[must_use]
pub fn parse_msan_output(text: &str) -> Option<MsanReport> {
    MsanReportParser::first_only().parse_all(text).into_iter().next()
}

// ── MsanReportStats ───────────────────────────────────────────────────────────

/// Aggregate statistics over a collection of parsed `MSan` reports.
#[derive(Debug, Clone, Default)]
pub struct MsanReportStats {
    /// Total number of reports.
    pub total: usize,
    /// Count per error type.
    pub by_error_type: HashMap<String, usize>,
    /// Functions that appear most frequently in the top frame.
    pub top_functions: HashMap<String, usize>,
}

impl MsanReportStats {
    /// Compute statistics from a slice of reports.
    #[must_use]
    pub fn compute(reports: &[MsanReport]) -> Self {
        let mut stats = Self { total: reports.len(), ..Self::default() };
        for r in reports {
            *stats.by_error_type.entry(r.error_type.clone()).or_insert(0) += 1;
            if let Some(func) = r.top_function() {
                *stats.top_functions.entry(func.to_owned()).or_insert(0) += 1;
            }
        }
        stats
    }

    /// Return the most common error type, or `None` for an empty set.
    #[must_use]
    pub fn dominant_error(&self) -> Option<&str> {
        // Total order on ties, so the answer does not vary between runs.
        self.by_error_type
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, _)| k.as_str())
    }

    /// Return the function that appears most in top frames.
    #[must_use]
    pub fn hottest_function(&self) -> Option<&str> {
        // Total order on ties, so the answer does not vary between runs.
        self.top_functions
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, _)| k.as_str())
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

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
            if let Ok(ln) = col_s.parse::<u32>() {
                let fp = format!("{file}:{line_s}");
                return (Some(fp), Some(ln), None);
            }
            (Some(s.to_owned()), None, None)
        }
        [line_s, file] => {
            let ln = line_s.parse::<u32>().ok();
            (Some((*file).to_owned()), ln, None)
        }
        [file] => (Some((*file).to_owned()), None, None),
        _ => (Some(s.to_owned()), None, None),
    }
}

fn extract_number_after(s: &str, keyword: &str) -> Option<usize> {
    let idx = s.to_ascii_lowercase().find(keyword)?;
    let after = s[..idx].trim();
    let tok: String = after
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    tok.parse().ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r"==54321==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x401234 in foo /src/foo.c:10:3
    #1 0x401300 in bar /src/bar.c:20:7
    #2 0x401400 in main /src/main.c:5:1

SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/foo.c:10 in foo
";

    #[test]
    fn test_parse_msan_output_pid() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.pid, Some(54321));
    }

    #[test]
    fn test_parse_error_type() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.error_type, "use-of-uninitialized-value");
    }

    #[test]
    fn test_parse_stack_frames_count() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.frame_count(), 3);
    }

    #[test]
    fn test_parse_frame_zero_pc() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.stack_frames[0].pc, Some(0x0040_1234));
    }

    #[test]
    fn test_parse_frame_zero_function() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.stack_frames[0].function.as_deref(), Some("foo"));
    }

    #[test]
    fn test_parse_frame_zero_file() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.stack_frames[0].file.as_deref(), Some("/src/foo.c"));
    }

    #[test]
    fn test_parse_frame_zero_line() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.stack_frames[0].line, Some(10));
    }

    #[test]
    fn test_parse_frame_zero_column() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.stack_frames[0].column, Some(3));
    }

    #[test]
    fn test_parse_summary_present() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert!(r.summary.is_some());
        assert!(r.summary.as_deref().unwrap().contains("SUMMARY"));
    }

    #[test]
    fn test_top_function() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert_eq!(r.top_function(), Some("foo"));
    }

    #[test]
    fn test_headline() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert!(r.headline().contains("MSan"));
        assert!(r.headline().contains("54321"));
    }

    #[test]
    fn test_display() {
        let r = parse_msan_output(SAMPLE).unwrap();
        let s = r.to_string();
        assert!(s.contains("MSan"));
    }

    #[test]
    fn test_no_report_returns_none() {
        assert!(parse_msan_output("nothing here").is_none());
    }

    #[test]
    fn test_parse_all_multiple() {
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let parser = MsanReportParser::new();
        let reports = parser.parse_all(&two);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_stop_at_first() {
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let parser = MsanReportParser::first_only();
        let reports = parser.parse_all(&two);
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn test_uninit_read_describe() {
        let r = UninitRead::from_pc(0xdead_beef);
        let d = r.describe();
        assert!(d.contains("0xdeadbeef"));
    }

    #[test]
    fn test_uninit_read_display() {
        let r = UninitRead::from_pc(0x1000);
        assert!(r.to_string().contains("UninitRead"));
    }

    #[test]
    fn test_frame_empty_display() {
        let f = MsanStackFrame::empty(3);
        assert!(f.display_line().contains("#3"));
    }

    #[test]
    fn test_frame_display_with_location() {
        let f = MsanStackFrame {
            index: 0,
            pc: Some(0x4000),
            function: Some("func".to_owned()),
            file: Some("a.c".to_owned()),
            line: Some(7),
            column: Some(2),
        };
        let s = f.display_line();
        assert!(s.contains("func"));
        assert!(s.contains("a.c:7:2"));
    }

    #[test]
    fn test_stats_dominant_error() {
        let parser = MsanReportParser::new();
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let reports = parser.parse_all(&two);
        let stats = MsanReportStats::compute(&reports);
        assert_eq!(stats.dominant_error(), Some("use-of-uninitialized-value"));
    }

    #[test]
    fn test_stats_hottest_function() {
        let parser = MsanReportParser::new();
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let reports = parser.parse_all(&two);
        let stats = MsanReportStats::compute(&reports);
        assert_eq!(stats.hottest_function(), Some("foo"));
    }

    #[test]
    fn test_stats_total() {
        let parser = MsanReportParser::new();
        let two = format!("{SAMPLE}\n{SAMPLE}");
        let reports = parser.parse_all(&two);
        let stats = MsanReportStats::compute(&reports);
        assert_eq!(stats.total, 2);
    }

    #[test]
    fn test_stats_empty() {
        let stats = MsanReportStats::compute(&[]);
        assert_eq!(stats.total, 0);
        assert!(stats.dominant_error().is_none());
        assert!(stats.hottest_function().is_none());
    }

    #[test]
    fn test_parse_block_directly() {
        let report = MsanReportParser::parse_block(SAMPLE);
        assert_eq!(report.pid, Some(54321));
        assert_eq!(report.frame_count(), 3);
    }

    #[test]
    fn test_raw_preserved() {
        let r = parse_msan_output(SAMPLE).unwrap();
        assert!(r.raw.contains("54321"));
    }
}
