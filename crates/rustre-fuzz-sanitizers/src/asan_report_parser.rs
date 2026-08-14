//! `AddressSanitizer` report parser.
//!
//! Parses textual `ASan` crash reports (as written to stderr by a process
//! instrumented with `-fsanitize=address`) into structured Rust types.
//!
//! # Key types
//!
//! * [`AsanReportParser`] — stateless parser entry-point.
//! * [`AsanReport`] — a fully parsed `ASan` crash report.
//! * [`CrashKind`] — category of the memory error.
//! * [`StackFrame`] — a single frame in a stack trace.
//! * Free function [`parse_asan_output`] — convenience wrapper.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── CrashKind ─────────────────────────────────────────────────────────────────

/// The category of memory error reported by `AddressSanitizer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashKind {
    HeapBufferOverflow,
    StackBufferOverflow,
    GlobalBufferOverflow,
    UseAfterFree,
    UseAfterReturn,
    UseAfterScope,
    DoubleFree,
    BadFree,
    AllocDeallocMismatch,
    MemoryLeak,
    StackOverflow,
    NullDereference,
    ContainerOverflow,
    /// Error type not recognised by this parser.
    Unknown(String),
}

impl std::str::FromStr for CrashKind {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl CrashKind {
    /// Parse an error-type string as returned by `ASan`.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "heap-buffer-overflow" => Self::HeapBufferOverflow,
            "stack-buffer-overflow" => Self::StackBufferOverflow,
            "global-buffer-overflow" => Self::GlobalBufferOverflow,
            "use-after-free" | "heap-use-after-free" => Self::UseAfterFree,
            "use-after-return" => Self::UseAfterReturn,
            "use-after-scope" => Self::UseAfterScope,
            "double-free" => Self::DoubleFree,
            "bad-free" => Self::BadFree,
            "alloc-dealloc-mismatch" => Self::AllocDeallocMismatch,
            "memory-leak" | "indirect-leak" | "direct-leak" => Self::MemoryLeak,
            "stack-overflow" => Self::StackOverflow,
            "null-dereference" | "null-deref" => Self::NullDereference,
            "container-overflow" => Self::ContainerOverflow,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Estimated exploitability / severity score (higher = worse).
    #[must_use]
    pub const fn severity_score(&self) -> u8 {
        match self {
            Self::UseAfterFree => 10,
            Self::HeapBufferOverflow | Self::StackBufferOverflow => 9,
            Self::GlobalBufferOverflow | Self::DoubleFree => 8,
            Self::AllocDeallocMismatch | Self::BadFree => 7,
            Self::NullDereference | Self::StackOverflow => 6,
            Self::ContainerOverflow | Self::UseAfterReturn => 5,
            Self::UseAfterScope => 4,
            Self::Unknown(_) => 3,
            Self::MemoryLeak => 2,
        }
    }

    /// Returns `true` if this error is likely exploitable (score >= 8).
    #[must_use]
    pub const fn is_likely_exploitable(&self) -> bool {
        self.severity_score() >= 8
    }
}

impl fmt::Display for CrashKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeapBufferOverflow => write!(f, "heap-buffer-overflow"),
            Self::StackBufferOverflow => write!(f, "stack-buffer-overflow"),
            Self::GlobalBufferOverflow => write!(f, "global-buffer-overflow"),
            Self::UseAfterFree => write!(f, "use-after-free"),
            Self::UseAfterReturn => write!(f, "use-after-return"),
            Self::UseAfterScope => write!(f, "use-after-scope"),
            Self::DoubleFree => write!(f, "double-free"),
            Self::BadFree => write!(f, "bad-free"),
            Self::AllocDeallocMismatch => write!(f, "alloc-dealloc-mismatch"),
            Self::MemoryLeak => write!(f, "memory-leak"),
            Self::StackOverflow => write!(f, "stack-overflow"),
            Self::NullDereference => write!(f, "null-dereference"),
            Self::ContainerOverflow => write!(f, "container-overflow"),
            Self::Unknown(s) => write!(f, "unknown({s})"),
        }
    }
}

// ── StackFrame ────────────────────────────────────────────────────────────────

/// A single frame parsed from an `ASan` stack trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    /// Frame index (0-based).
    pub index: usize,
    /// Instruction pointer address, if available.
    pub address: Option<u64>,
    /// Function name (possibly mangled), if available.
    pub function: Option<String>,
    /// Shared library or binary that contains this frame.
    pub module: Option<String>,
    /// Source file path, if debug info is available.
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Source column number.
    pub column: Option<u32>,
}

impl StackFrame {
    /// Create a minimal frame with only an index.
    #[must_use]
    pub const fn empty(index: usize) -> Self {
        Self {
            index,
            address: None,
            function: None,
            module: None,
            file: None,
            line: None,
            column: None,
        }
    }

    /// One-line human-readable summary of this frame.
    #[must_use]
    pub fn display_line(&self) -> String {
        let addr = self
            .address
            .map_or_else(|| "???".to_owned(), |a| format!("{a:#018x}"));
        let func = self.function.as_deref().unwrap_or("<unknown>");
        let loc = match (&self.file, self.line) {
            (Some(f), Some(l)) => format!(" {f}:{l}"),
            (Some(f), None) => format!(" {f}"),
            _ => String::new(),
        };
        let module = self
            .module
            .as_deref()
            .map_or_else(String::new, |m| format!(" ({m})"));
        format!("#{} {} in {}{}{}", self.index, addr, func, loc, module)
    }
}

impl fmt::Display for StackFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_line())
    }
}

// ── AccessInfo ────────────────────────────────────────────────────────────────

/// Direction and size of the memory access that triggered the error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessInfo {
    /// True for a memory read, false for a write.
    pub is_read: bool,
    /// Number of bytes accessed.
    pub size: usize,
    /// The address that was accessed.
    pub address: u64,
}

impl fmt::Display for AccessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dir = if self.is_read { "READ" } else { "WRITE" };
        write!(f, "{dir} of {:#x} bytes at {:#018x}", self.size, self.address)
    }
}

// ── AllocationInfo ────────────────────────────────────────────────────────────

/// Information about the heap allocation involved in the crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationInfo {
    /// Base address of the allocation.
    pub address: u64,
    /// Size of the allocation in bytes.
    pub size: Option<usize>,
    /// Stack frames showing where the memory was allocated.
    pub alloc_stack: Vec<StackFrame>,
    /// Stack frames showing where the memory was freed (for UAF).
    pub free_stack: Vec<StackFrame>,
}

// ── AsanReport ────────────────────────────────────────────────────────────────

/// A fully-parsed `AddressSanitizer` crash report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsanReport {
    /// The category of error.
    pub kind: CrashKind,
    /// Details about the triggering memory access.
    pub access: Option<AccessInfo>,
    /// The crash stack trace (at the point of the error).
    pub crash_stack: Vec<StackFrame>,
    /// Allocation / deallocation context, if present.
    pub allocation: Option<AllocationInfo>,
    /// Thread index that triggered the error.
    pub thread_id: Option<u32>,
    /// Process ID extracted from the report header.
    pub pid: Option<u32>,
    /// Raw text of the entire report.
    pub raw_text: String,
    /// The error type string extracted verbatim from the header.
    pub error_type_raw: String,
}

impl AsanReport {
    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let addr = self
            .access
            .as_ref()
            .map_or_else(|| "?".to_owned(), |a| format!("{:#018x}", a.address));
        format!(
            "[ASan] {} at {} ({} crash frames)",
            self.kind,
            addr,
            self.crash_stack.len()
        )
    }

    /// The top-most function in the crash stack, if any.
    #[must_use]
    pub fn top_function(&self) -> Option<&str> {
        self.crash_stack
            .first()
            .and_then(|f| f.function.as_deref())
    }

    /// Returns `true` if this is likely exploitable.
    #[must_use]
    pub const fn is_exploitable(&self) -> bool {
        self.kind.is_likely_exploitable()
    }

    /// Deduplication key derived from the error kind and top-N stack frames.
    #[must_use]
    pub fn dedup_key(&self, stack_depth: usize) -> String {
        let depth = stack_depth.min(self.crash_stack.len());
        let mut key = String::with_capacity(32 + depth * 24);
        key.push_str(&self.kind.to_string());
        for frame in self.crash_stack.iter().take(stack_depth) {
            key.push('|');
            if let Some(func) = &frame.function {
                key.push_str(func.split('+').next().unwrap_or(func).trim());
            } else {
                key.push('?');
            }
        }
        key
    }
}

impl fmt::Display for AsanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── AsanReportParser ──────────────────────────────────────────────────────────

/// Stateless parser for `AddressSanitizer` textual crash reports.
pub struct AsanReportParser;

impl AsanReportParser {
    /// Parse the first `ASan` crash report found in `text`.
    ///
    /// Returns `None` when no recognisable `ASan` header is found.
    #[must_use]
    pub fn parse(text: &str) -> Option<AsanReport> {
        let reports = Self::parse_all(text);
        reports.into_iter().next()
    }

    /// Maximum number of lines accepted per `parse_all` call (dos-memory-exhaustion guard).
    const MAX_LINES: usize = 1_000_000;

    /// Parse *all* `ASan` crash reports found in `text`.
    ///
    /// A report begins with a line matching `==PID==ERROR: AddressSanitizer: …`.
    #[must_use]
    pub fn parse_all(text: &str) -> Vec<AsanReport> {
        let lines: Vec<&str> = text.lines().take(Self::MAX_LINES).collect();
        let block_starts: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| Self::is_asan_header(l))
            .map(|(i, _)| i)
            .collect();

        if block_starts.is_empty() {
            return Vec::new();
        }

        let mut reports = Vec::with_capacity(block_starts.len());
        for (idx, &start) in block_starts.iter().enumerate() {
            let end = block_starts.get(idx + 1).copied().unwrap_or(lines.len());
            let block = lines[start..end].join("\n");
            reports.push(Self::parse_block(&block));
        }
        reports
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn is_asan_header(line: &str) -> bool {
        line.contains("==ERROR:") && line.contains("AddressSanitizer")
    }

    fn parse_block(block: &str) -> AsanReport {
        let error_type_raw = Self::extract_error_type(block);
        let kind = CrashKind::parse(&error_type_raw);
        let pid = Self::extract_pid(block);
        let thread_id = Self::extract_thread(block);
        let access = Self::extract_access(block);
        let crash_stack = Self::parse_crash_stack(block);
        let allocation = Self::parse_allocation_info(block);

        AsanReport {
            kind,
            access,
            crash_stack,
            allocation,
            thread_id,
            pid,
            raw_text: block.to_owned(),
            error_type_raw,
        }
    }

    /// Extract the short error-type string from the header line.
    fn extract_error_type(block: &str) -> String {
        for line in block.lines() {
            if let Some(token) = asan_bug_type(line) {
                return token;
            }
        }
        "unknown".to_owned()
    }

    /// Given `==PID==ERROR: AddressSanitizer: <rest>` return `<rest>`.
    fn after_asan_colon(line: &str) -> Option<&str> {
        let idx = line.find("ERROR:")?;
        let after = &line[idx + 6..]; // skip "ERROR:"
        let colon = after.find(':')?;
        Some(after[colon + 1..].trim_start())
    }

    fn extract_pid(block: &str) -> Option<u32> {
        for line in block.lines() {
            // Lines start with "==PID==ERROR:"
            if let Some(rest) = line.strip_prefix("==") {
                let end = rest.find("==")?;
                return rest[..end].parse().ok();
            }
        }
        None
    }

    fn extract_thread(block: &str) -> Option<u32> {
        for line in block.lines() {
            if let Some(idx) = line.find(" thread T") {
                let rest = &line[idx + 9..];
                let num: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(n) = num.parse::<u32>() {
                    return Some(n);
                }
            }
        }
        None
    }

    fn extract_access(block: &str) -> Option<AccessInfo> {
        for line in block.lines() {
            let trimmed = line.trim();
            let (is_read, rest) = if let Some(r) = trimmed.strip_prefix("READ ") {
                (true, r)
            } else if let Some(r) = trimmed.strip_prefix("WRITE ") {
                (false, r)
            } else {
                continue;
            };

            // "of size N at 0xADDR …"
            let size = extract_value_after(rest, "of size")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let address = extract_hex_after(rest, "at ").unwrap_or(0);
            return Some(AccessInfo { is_read, size, address });
        }
        None
    }

    fn parse_crash_stack(block: &str) -> Vec<StackFrame> {
        Self::parse_frames_after(block, None)
    }

    fn parse_allocation_info(block: &str) -> Option<AllocationInfo> {
        let alloc_anchor = block
            .lines()
            .position(|l| l.to_ascii_lowercase().contains("allocated by thread"));
        let free_anchor = block
            .lines()
            .position(|l| l.to_ascii_lowercase().contains("freed by thread"));

        if alloc_anchor.is_none() && free_anchor.is_none() {
            return None;
        }

        let alloc_stack = alloc_anchor.map_or_else(Vec::new, |idx| {
            let sub_text: String = block.lines().skip(idx + 1).collect::<Vec<_>>().join("\n");
            Self::parse_frames_after(&sub_text, None)
        });

        let free_stack = free_anchor.map_or_else(Vec::new, |idx| {
            let sub_text: String = block.lines().skip(idx + 1).collect::<Vec<_>>().join("\n");
            Self::parse_frames_after(&sub_text, None)
        });

        // Try to extract heap address from "located 0 bytes … of 32-byte heap region [0xADDR, 0xADDR)"
        let address = Self::extract_heap_region_addr(block).unwrap_or(0);

        Some(AllocationInfo {
            address,
            size: None,
            alloc_stack,
            free_stack,
        })
    }

    fn extract_heap_region_addr(block: &str) -> Option<u64> {
        for line in block.lines() {
            if (line.contains("heap region") || line.contains("allocated here"))
                && let Some(bracket) = line.find('[') {
                    let rest = &line[bracket + 1..];
                    let end = rest.find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                        .unwrap_or(rest.len());
                    return parse_hex_u64(&rest[..end]);
                }
        }
        None
    }

    fn parse_frames_after(text: &str, _anchor: Option<&str>) -> Vec<StackFrame> {
        let mut frames = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if let Some(frame) = Self::try_parse_frame(trimmed) {
                frames.push(frame);
            } else if !frames.is_empty()
                && !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && !trimmed.starts_with("0x")
            {
                break;
            }
        }
        frames
    }

    fn try_parse_frame(s: &str) -> Option<StackFrame> {
        let s = s.trim();
        if !s.starts_with('#') {
            return None;
        }
        let s = &s[1..];
        let mut it = s.splitn(2, ' ');
        let idx: usize = it.next()?.trim().parse().ok()?;
        let rest = it.next().unwrap_or("").trim();

        let (address, rest) = if rest.starts_with("0x") || rest.starts_with("0X") {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let addr = parse_hex_u64(&rest[..end]);
            (addr, rest[end..].trim())
        } else {
            (None, rest)
        };

        let (function, module, file, line, column) =
            rest.strip_prefix("in ").map_or_else(|| rest.strip_prefix('(').map_or((None, None, None, None, None), |after_paren| {
                // "(module+0xOFFSET)" format
                let module_part = after_paren.split('+').next().map(str::to_owned);
                (None, module_part, None, None, None)
            }), |after_in| {
                let mut it2 = after_in.splitn(2, ' ');
                let func = it2.next().map(str::to_owned);
                let loc = it2.next().unwrap_or("").trim();
                let (f, ln, col) = parse_location(loc);
                (func, None, f, ln, col)
            });

        Some(StackFrame { index: idx, address, function, module, file, line, column })
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Parse the first `ASan` crash report from `text`.
///
/// Returns `None` when no recognisable `ASan` header is found.
#[must_use]
pub fn parse_asan_output(text: &str) -> Option<AsanReport> {
    AsanReportParser::parse(text)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

use crate::parse_hex_u64;

/// Extract the bug type from an `ASan` header line, e.g. `heap-buffer-overflow`
/// from `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x…`.
///
/// Returns `None` when the line is not an `ASan` error header.
///
/// This is the single definition of the rule. Two extractors used to carry
/// their own, and each was wrong where the other was right: taking the first
/// token after the colon mis-reads `attempting double-free` as `attempting`,
/// while scanning for the first token containing `-`/`overflow`/`free` misses
/// the hyphen-free types (`SEGV`, `FPE`) entirely.
pub(crate) fn asan_bug_type(line: &str) -> Option<String> {
    let rest = AsanReportParser::after_asan_colon(line)?;
    let mut tokens = rest.split_whitespace();
    let mut token = tokens.next()?;
    // ASan prefixes a couple of bug types with a filler verb — the type is the
    // word after it ("attempting double-free on 0x…").
    if token == "attempting" {
        token = tokens.next()?;
    }
    let token = token.trim_end_matches([':', ',']);
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

fn extract_value_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let idx = s.find(key)?;
    let rest = s[idx + key.len()..].trim_start();
    Some(rest.split_whitespace().next().unwrap_or(""))
}

fn extract_hex_after(s: &str, needle: &str) -> Option<u64> {
    let idx = s.find(needle)?;
    let rest = s[idx + needle.len()..].trim_start();
    let token = rest.split_whitespace().next()?;
    parse_hex_u64(token)
}

fn parse_location(s: &str) -> (Option<String>, Option<u32>, Option<u32>) {
    if s.is_empty() {
        return (None, None, None);
    }
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    match parts.as_slice() {
        [col_s, line_s, file] => {
            let col = col_s.parse().ok();
            if let Ok(ln) = line_s.parse::<u32>() {
                return (Some((*file).to_owned()), Some(ln), col);
            }
            if let Ok(ln) = col_s.parse::<u32>() {
                let f = format!("{file}:{line_s}");
                return (Some(f), Some(ln), None);
            }
            (Some(s.to_owned()), None, None)
        }
        [line_s, file] => (Some((*file).to_owned()), line_s.parse().ok(), None),
        [file] => (Some((*file).to_owned()), None, None),
        _ => (Some(s.to_owned()), None, None),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const HEAP_OVERFLOW: &str = r"==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000050 thread T0
READ of size 4 at 0x602000000050 thread T0
    #0 0x0000000000401234 in foo /home/user/test.c:42:5
    #1 0x0000000000401300 in bar /home/user/test.c:60
    #2 0x00007fff8a000000 in main /home/user/main.c:10

0x602000000050 is located 0 bytes to the right of 80-byte heap region [0x602000000000,0x602000000050)
allocated by thread T0 here:
    #0 0x7f0000001234 in malloc
    #1 0x000000000040f000 in create_buffer /src/buf.c:10
";

    const UAF: &str = r"==99==ERROR: AddressSanitizer: use-after-free on address 0x6020000000b0 thread T1
READ of size 8 at 0x6020000000b0 thread T1
    #0 0x401abc in read_freed /src/main.c:30:3

freed by thread T1 here:
    #0 0x401def in free_buf /src/main.c:20:5

allocated by thread T0 here:
    #0 0x401111 in alloc_buf /src/main.c:10:3
";

    #[test]
    fn test_parse_heap_overflow() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        assert_eq!(report.kind, CrashKind::HeapBufferOverflow);
        assert_eq!(report.pid, Some(12345));
    }

    #[test]
    fn test_parse_access_info() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        let acc = report.access.unwrap();
        assert!(acc.is_read);
        assert_eq!(acc.size, 4);
        assert_eq!(acc.address, 0x6020_0000_0050);
    }

    #[test]
    fn test_parse_crash_stack() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        assert_eq!(report.crash_stack.len(), 3);
        assert_eq!(report.crash_stack[0].index, 0);
        assert_eq!(report.crash_stack[0].function.as_deref(), Some("foo"));
        assert_eq!(report.crash_stack[0].file.as_deref(), Some("/home/user/test.c"));
        assert_eq!(report.crash_stack[0].line, Some(42));
        assert_eq!(report.crash_stack[0].column, Some(5));
    }

    #[test]
    fn test_parse_uaf_kind() {
        let report = parse_asan_output(UAF).unwrap();
        assert_eq!(report.kind, CrashKind::UseAfterFree);
    }

    #[test]
    fn test_parse_uaf_allocation_info() {
        let report = parse_asan_output(UAF).unwrap();
        let alloc = report.allocation.unwrap();
        assert!(!alloc.alloc_stack.is_empty());
        assert!(!alloc.free_stack.is_empty());
    }

    #[test]
    fn test_parse_all_multiple_reports() {
        let two = format!("{HEAP_OVERFLOW}\n{UAF}");
        let reports = AsanReportParser::parse_all(&two);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_parse_no_report() {
        assert!(parse_asan_output("nothing here").is_none());
    }

    #[test]
    fn test_dedup_key() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        let key = report.dedup_key(2);
        assert!(key.contains("heap-buffer-overflow"));
        assert!(key.contains("foo"));
    }

    #[test]
    fn test_crash_kind_severity() {
        assert!(CrashKind::UseAfterFree.severity_score() >= 8);
        assert!(CrashKind::MemoryLeak.severity_score() < 8);
    }

    #[test]
    fn test_crash_kind_exploitable() {
        assert!(CrashKind::UseAfterFree.is_likely_exploitable());
        assert!(!CrashKind::MemoryLeak.is_likely_exploitable());
    }

    #[test]
    fn test_crash_kind_display() {
        assert_eq!(CrashKind::HeapBufferOverflow.to_string(), "heap-buffer-overflow");
        assert_eq!(CrashKind::DoubleFree.to_string(), "double-free");
    }

    #[test]
    fn test_crash_kind_from_str() {
        assert_eq!(CrashKind::parse("heap-buffer-overflow"), CrashKind::HeapBufferOverflow);
        assert_eq!(CrashKind::parse("HEAP-BUFFER-OVERFLOW"), CrashKind::HeapBufferOverflow);
        assert_eq!(CrashKind::parse("use-after-free"), CrashKind::UseAfterFree);
        assert_eq!(CrashKind::parse("heap-use-after-free"), CrashKind::UseAfterFree);
        assert!(matches!(CrashKind::parse("not-a-real-error"), CrashKind::Unknown(_)));
    }

    #[test]
    fn test_report_summary() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        let s = report.summary();
        assert!(s.contains("heap-buffer-overflow"));
    }

    #[test]
    fn test_report_display() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        let s = format!("{report}");
        assert!(!s.is_empty());
    }

    #[test]
    fn test_top_function() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        assert_eq!(report.top_function(), Some("foo"));
    }

    #[test]
    fn test_stack_frame_display() {
        let frame = StackFrame {
            index: 0,
            address: Some(0x0040_1234),
            function: Some("main".into()),
            module: None,
            file: Some("test.c".into()),
            line: Some(10),
            column: None,
        };
        let s = frame.display_line();
        assert!(s.contains("main"));
        assert!(s.contains("test.c:10"));
    }

    #[test]
    fn test_access_info_display() {
        let a = AccessInfo { is_read: true, size: 4, address: 0x1000 };
        let s = format!("{a}");
        assert!(s.contains("READ"));
    }

    #[test]
    fn test_report_is_exploitable() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        assert!(report.is_exploitable());
    }

    #[test]
    fn test_parse_thread_id() {
        let report = parse_asan_output(HEAP_OVERFLOW).unwrap();
        assert_eq!(report.thread_id, Some(0));
    }
}
