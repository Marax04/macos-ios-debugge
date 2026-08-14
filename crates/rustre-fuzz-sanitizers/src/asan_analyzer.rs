//! `AddressSanitizer` output analyzer — text-to-structured-report parser.
//!
//! Parses ASAN stack traces from raw text, categorises the bug type
//! (heap-buffer-overflow, use-after-free, stack-overflow, etc.), extracts
//! allocation and deallocation information, and produces a structured report.
//!
//! # Relationship to [`crate::asan_runtime`]
//!
//! This module is the **static analysis / parsing** side: it takes existing ASAN
//! text output and converts it to [`AsanReport`].  It does not simulate memory.
//!
//! [`crate::asan_runtime`] is the **runtime simulation** side: it implements
//! shadow memory, heap redzones, quarantine, and load/store callbacks so that
//! ASAN-style detection can be performed in-process without LLVM instrumentation.
//! The two modules are **intentionally kept separate** and are not duplicates.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Bug categories ─────────────────────────────────────────────────────────────

/// All ASAN bug categories, mapped from the header line of the report.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AsanBugType {
    HeapBufferOverflow,
    HeapUseAfterFree,
    StackBufferOverflow,
    StackBufferUnderflow,
    GlobalBufferOverflow,
    UseAfterReturn,
    UseAfterScope,
    DoubleFree,
    BadFree,
    AllocDeallocMismatch,
    NullDereference,
    StackOverflow,
    MemoryLeak,
    Odr,
    InitializationOrderFiasco,
    ContainerOverflow,
    UndefinedBehavior,
    Unknown(String),
}

impl std::str::FromStr for AsanBugType {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

impl AsanBugType {
    /// Parse from the raw error-type string in an ASAN report.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.trim() {
            "heap-buffer-overflow" => Self::HeapBufferOverflow,
            "heap-use-after-free" | "use-after-free" => Self::HeapUseAfterFree,
            "stack-buffer-overflow" => Self::StackBufferOverflow,
            "stack-buffer-underflow" => Self::StackBufferUnderflow,
            "global-buffer-overflow" => Self::GlobalBufferOverflow,
            "use-after-return" => Self::UseAfterReturn,
            "use-after-scope" => Self::UseAfterScope,
            "double-free" => Self::DoubleFree,
            "bad-free" => Self::BadFree,
            "alloc-dealloc-mismatch" => Self::AllocDeallocMismatch,
            "null-dereference" => Self::NullDereference,
            "stack-overflow" => Self::StackOverflow,
            "memory-leak" | "leak" => Self::MemoryLeak,
            "odr-violation" => Self::Odr,
            "initialization-order-fiasco" => Self::InitializationOrderFiasco,
            "container-overflow" => Self::ContainerOverflow,
            s if s.contains("undefined") => Self::UndefinedBehavior,
            other => Self::Unknown(other.to_string()),
        }
    }

    /// Exploitability score 0–10.
    #[must_use]
    pub const fn exploitability_score(&self) -> u8 {
        match self {
            Self::HeapUseAfterFree => 9,
            Self::HeapBufferOverflow | Self::StackBufferOverflow | Self::DoubleFree => 8,
            Self::GlobalBufferOverflow | Self::UseAfterReturn => 7,
            Self::StackBufferUnderflow | Self::BadFree | Self::UseAfterScope => 6,
            Self::AllocDeallocMismatch | Self::StackOverflow | Self::ContainerOverflow => 5,
            Self::NullDereference => 4,
            Self::UndefinedBehavior | Self::Unknown(_) => 3,
            Self::InitializationOrderFiasco | Self::Odr => 2,
            Self::MemoryLeak => 1,
            }
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(&self) -> &str {
        match self {
            Self::HeapBufferOverflow => "heap-buffer-overflow",
            Self::HeapUseAfterFree => "heap-use-after-free",
            Self::StackBufferOverflow => "stack-buffer-overflow",
            Self::StackBufferUnderflow => "stack-buffer-underflow",
            Self::GlobalBufferOverflow => "global-buffer-overflow",
            Self::UseAfterReturn => "use-after-return",
            Self::UseAfterScope => "use-after-scope",
            Self::DoubleFree => "double-free",
            Self::BadFree => "bad-free",
            Self::AllocDeallocMismatch => "alloc-dealloc-mismatch",
            Self::NullDereference => "null-dereference",
            Self::StackOverflow => "stack-overflow",
            Self::MemoryLeak => "memory-leak",
            Self::Odr => "odr-violation",
            Self::InitializationOrderFiasco => "initialization-order-fiasco",
            Self::ContainerOverflow => "container-overflow",
            Self::UndefinedBehavior => "undefined-behavior",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

// ── Stack frame ────────────────────────────────────────────────────────────────

/// A single frame from an ASAN stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsanFrame {
    /// Frame index (0-based).
    pub index: usize,
    /// Program counter address.
    pub address: Option<u64>,
    /// Function name (demangled when available).
    pub function: Option<String>,
    /// Source file path.
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Column within the line.
    pub column: Option<u32>,
    /// Object/module name (e.g., shared library).
    pub module: Option<String>,
    /// Offset within the module.
    pub module_offset: Option<u64>,
}

impl AsanFrame {
    /// One-line human-readable representation.
    #[must_use]
    pub fn display(&self) -> String {
        let addr = self.address.map_or_else(|| "???".to_owned(), |a| format!("0x{a:x}"));
        let func = self.function.as_deref().unwrap_or("<unknown>");
        let loc = match (&self.file, self.line) {
            (Some(f), Some(l)) => format!(" ({f}:{l})"),
            (Some(f), None) => format!(" ({f})"),
            _ => String::new(),
        };
        let modinfo = match (&self.module, self.module_offset) {
            (Some(m), Some(off)) => format!(" [{m}+0x{off:x}]"),
            (Some(m), None) => format!(" [{m}]"),
            _ => String::new(),
        };
        format!("#{} {} in {}{}{}", self.index, addr, func, loc, modinfo)
    }

    /// Returns `true` if this frame belongs to an ASAN runtime frame.
    #[must_use]
    pub fn is_sanitizer_frame(&self) -> bool {
        let runtime_prefixes = [
            "__asan", "__lsan", "__msan", "__ubsan", "__tsan",
            "sanitizer_", "asan_", "AddressSanitizer",
        ];
        self.function.as_deref().is_some_and(|f| {
            runtime_prefixes.iter().any(|p| f.contains(p))
        })
    }
}

// ── AllocationInfo ─────────────────────────────────────────────────────────────

/// Heap allocation metadata extracted from an ASAN report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationInfo {
    /// The base address of the allocation.
    pub address: u64,
    /// Allocation size in bytes.
    pub size: usize,
    /// Thread that allocated the memory.
    pub thread: Option<u32>,
    /// Stack trace at allocation site.
    pub alloc_frames: Vec<AsanFrame>,
    /// Stack trace at deallocation site (for use-after-free).
    pub free_frames: Vec<AsanFrame>,
    /// Whether the memory was freed before the fault.
    pub was_freed: bool,
}

impl AllocationInfo {
    #[must_use]
    pub const fn new(address: u64, size: usize) -> Self {
        Self {
            address,
            size,
            thread: None,
            alloc_frames: Vec::new(),
            free_frames: Vec::new(),
            was_freed: false,
        }
    }
}

// ── AsanReport ────────────────────────────────────────────────────────────────

/// A fully-parsed ASAN crash report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsanReport {
    /// Bug category.
    pub bug_type: AsanBugType,
    /// Whether the faulting access was a read or write.
    pub is_write: Option<bool>,
    /// Number of bytes involved in the access.
    pub access_size: Option<usize>,
    /// The faulting memory address.
    pub fault_address: Option<u64>,
    /// Process ID from the report header.
    pub pid: Option<u32>,
    /// Thread that triggered the fault.
    pub fault_thread: Option<u32>,
    /// Stack frames at the point of the fault.
    pub fault_stack: Vec<AsanFrame>,
    /// Allocation metadata for the involved memory region.
    pub allocation: Option<AllocationInfo>,
    /// Shadow memory bytes around the fault (raw hex).
    pub shadow_bytes: Vec<u8>,
    /// Raw text of the complete report.
    pub raw: String,
    /// Computed exploitability score (0–10).
    pub exploitability: u8,
}

impl AsanReport {
    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let addr = self.fault_address.map_or_else(|| "?".to_owned(), |a| format!("0x{a:x}"));
        let access = self.access_size.map_or_else(|| "?".to_owned(), |s| s.to_string());
        let rw = match self.is_write {
            Some(true) => "WRITE",
            Some(false) => "READ",
            None => "?",
        };
        format!(
            "[exploitability={}/10] {} {} of {} bytes at {} | top-frame: {}",
            self.exploitability,
            self.bug_type.label(),
            rw,
            access,
            addr,
            self.fault_stack.first().map(AsanFrame::display).unwrap_or_default()
        )
    }

    /// Returns frames that are not ASAN runtime frames (i.e. user code).
    #[must_use]
    pub fn user_frames(&self) -> Vec<&AsanFrame> {
        self.fault_stack.iter().filter(|f| !f.is_sanitizer_frame()).collect()
    }
}

// ── AsanAnalyzer ──────────────────────────────────────────────────────────────

/// Stateless ASAN report analyzer.
pub struct AsanAnalyzer;

impl AsanAnalyzer {
    /// Parse an ASAN crash report from raw text.
    #[must_use]
    pub fn parse(text: &str) -> AsanReport {
        let bug_type = Self::detect_bug_type(text);
        let (is_write, access_size, fault_address) = Self::parse_access_line(text);
        let pid = Self::parse_pid(text);
        let fault_thread = Self::parse_fault_thread(text);
        let fault_stack = Self::parse_fault_stack(text);
        let allocation = Self::parse_allocation(text, &bug_type);
        let shadow_bytes = Self::parse_shadow_bytes(text);
        let exploitability = bug_type.exploitability_score();

        AsanReport {
            bug_type,
            is_write,
            access_size,
            fault_address,
            pid,
            fault_thread,
            fault_stack,
            allocation,
            shadow_bytes,
            raw: text.to_owned(),
            exploitability,
        }
    }

    /// Maximum lines processed per `parse_all` call (dos-memory-exhaustion guard).
    const MAX_LINES: usize = 1_000_000;

    /// Parse multiple ASAN reports from a single log containing several crashes.
    #[must_use]
    pub fn parse_all(text: &str) -> Vec<AsanReport> {
        let lines: Vec<&str> = text.lines().take(Self::MAX_LINES).collect();
        let mut boundaries: Vec<usize> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("==ERROR:") {
                boundaries.push(i);
            }
        }
        if boundaries.is_empty() {
            return vec![Self::parse(text)];
        }
        let mut reports = Vec::new();
        for (idx, &start) in boundaries.iter().enumerate() {
            let end = if idx + 1 < boundaries.len() { boundaries[idx + 1] } else { lines.len() };
            let block = lines[start..end].join("\n");
            reports.push(Self::parse(&block));
        }
        reports
    }

    // ── Detection helpers ─────────────────────────────────────────────────────

    fn detect_bug_type(text: &str) -> AsanBugType {
        for line in text.lines() {
            if line.contains("==ERROR:")
                && let Some(after_asan) = Self::after_colon_part(line) {
                    // "heap-buffer-overflow on address ..." → take first token
                    let first = after_asan.split_whitespace().next().unwrap_or("").trim_end_matches(':');
                    if !first.is_empty() {
                        return AsanBugType::parse(first);
                    }
                }
        }
        AsanBugType::Unknown("unknown".into())
    }

    fn after_colon_part(line: &str) -> Option<&str> {
        let idx = line.find("ERROR:")?;
        let rest = &line[idx + 6..];
        let colon = rest.find(':')?;
        Some(rest[colon + 1..].trim_start())
    }

    fn parse_access_line(text: &str) -> (Option<bool>, Option<usize>, Option<u64>) {
        for line in text.lines() {
            let t = line.trim();
            let (is_write, rest) = if let Some(r) = t.strip_prefix("READ ") {
                (false, r)
            } else if let Some(r) = t.strip_prefix("WRITE ") {
                (true, r)
            } else {
                continue;
            };
            let size = Self::parse_kv(rest, "of size").and_then(|s| s.parse().ok());
            let addr = Self::parse_hex_after(rest, "at ");
            return (Some(is_write), size, addr);
        }
        (None, None, None)
    }

    fn parse_pid(text: &str) -> Option<u32> {
        // "==12345==ERROR:" — PID is between the ==
        for line in text.lines() {
            if line.starts_with("==") && line.contains("==ERROR:") {
                let inner = &line[2..];
                let end = inner.find("==")?;
                return inner[..end].parse().ok();
            }
        }
        None
    }

    fn parse_fault_thread(text: &str) -> Option<u32> {
        for line in text.lines() {
            if let Some(idx) = line.find(" thread T") {
                let rest = &line[idx + 9..];
                let num: String = rest.chars().take_while(char::is_ascii_digit).collect();
                return num.parse().ok();
            }
        }
        None
    }

    fn parse_fault_stack(text: &str) -> Vec<AsanFrame> {
        let lines: Vec<&str> = text.lines().collect();
        // Find the first stack trace section after the ERROR line
        let start = lines
            .iter()
            .position(|l| l.contains("==ERROR:"))
            .map_or(0, |i| i + 1);
        Self::collect_frames(&lines[start..])
    }

    fn parse_allocation(text: &str, bug_type: &AsanBugType) -> Option<AllocationInfo> {
        let addr = Self::parse_alloc_address(text)?;
        let size = Self::parse_alloc_size(text).unwrap_or(0);
        let mut info = AllocationInfo::new(addr, size);

        // Try to parse allocation stack
        let lines: Vec<&str> = text.lines().collect();
        if let Some(alloc_pos) = lines.iter().position(|l| {
            l.to_ascii_lowercase().contains("allocated by thread")
                || l.to_ascii_lowercase().contains("is located")
        }) {
            info.alloc_frames = Self::collect_frames(&lines[alloc_pos + 1..]);
        }

        // Try to parse free stack for UAF
        if matches!(bug_type, AsanBugType::HeapUseAfterFree | AsanBugType::DoubleFree) {
            info.was_freed = true;
            if let Some(free_pos) = lines.iter().position(|l| {
                l.to_ascii_lowercase().contains("freed by thread")
                    || l.to_ascii_lowercase().contains("previously freed")
            }) {
                info.free_frames = Self::collect_frames(&lines[free_pos + 1..]);
            }
        }

        Some(info)
    }

    fn parse_alloc_address(text: &str) -> Option<u64> {
        for line in text.lines() {
            if line.contains("on address ")
                && let Some(idx) = line.find("on address ") {
                    let rest = &line[idx + 11..];
                    let token = rest.split_whitespace().next()?;
                    return parse_hex_u64(token);
                }
        }
        None
    }

    fn parse_alloc_size(text: &str) -> Option<usize> {
        for line in text.lines() {
            // "is located N bytes to the right of N-byte region"
            // "is located N bytes after N-byte region"
            if line.contains("-byte region") || line.contains("bytes to the") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for (i, &part) in parts.iter().enumerate() {
                    if (part == "bytes" || part.ends_with("-byte")) && i > 0
                        && let Ok(n) = parts[i - 1].parse::<usize>() {
                            return Some(n);
                        }
                }
            }
        }
        None
    }

    fn parse_shadow_bytes(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut in_shadow = false;
        for line in text.lines() {
            if line.contains("Shadow bytes around the buggy address:") {
                in_shadow = true;
                continue;
            }
            if in_shadow {
                if line.trim().is_empty() || (!line.contains("=>") && !line.trim().starts_with("0x")) {
                    if !bytes.is_empty() {
                        break;
                    }
                    continue;
                }
                // Lines look like: "0x7f... shadow: 00 00 fa fa..."
                let hex_part = line.split(':').nth(1).unwrap_or("").trim();
                for tok in hex_part.split_whitespace() {
                    let clean = tok.trim_start_matches('[').trim_end_matches(']');
                    if let Ok(b) = u8::from_str_radix(clean, 16) {
                        bytes.push(b);
                    }
                }
            }
        }
        bytes
    }

    // ── Frame collection ──────────────────────────────────────────────────────

    fn collect_frames(lines: &[&str]) -> Vec<AsanFrame> {
        let mut frames = Vec::new();
        for &line in lines {
            if let Some(frame) = Self::try_parse_frame(line) {
                frames.push(frame);
            } else if !frames.is_empty() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("0x") {
                    break;
                }
            }
        }
        frames
    }

    fn try_parse_frame(s: &str) -> Option<AsanFrame> {
        let s = s.trim();
        if !s.starts_with('#') {
            return None;
        }
        let s = &s[1..];
        let mut parts = s.splitn(2, ' ');
        let idx: usize = parts.next()?.trim().parse().ok()?;
        let rest = parts.next().unwrap_or("").trim();

        let (address, rest) = if rest.starts_with("0x") || rest.starts_with("0X") {
            let end = rest.find(' ').unwrap_or(rest.len());
            (parse_hex_u64(&rest[..end]), rest[end..].trim())
        } else {
            (None, rest)
        };

        let (function, file, line, column, module, module_offset) = rest.strip_prefix("in ").map_or_else(|| if rest.contains('(') {
            // Module+offset: "(libfoo.so+0x1234)"
            let (m, off) = parse_module_offset(rest);
            (None, None, None, None, m, off)
        } else {
            (Some(rest.to_owned()), None, None, None, None, None)
        }, |after_in| {
            let mut it = after_in.splitn(2, ' ');
            let func = it.next().map(std::borrow::ToOwned::to_owned);
            let loc = it.next().unwrap_or("").trim();
            let (f, l, c) = parse_location(loc);
            (func, f, l, c, None, None)
        });

        Some(AsanFrame {
            index: idx,
            address,
            function,
            file,
            line,
            column,
            module,
            module_offset,
        })
    }

    // ── Generic helpers ───────────────────────────────────────────────────────

    fn parse_kv<'a>(s: &'a str, key: &str) -> Option<&'a str> {
        let idx = s.find(key)?;
        Some(s[idx + key.len()..].split_whitespace().next().unwrap_or(""))
    }

    fn parse_hex_after(s: &str, needle: &str) -> Option<u64> {
        let idx = s.find(needle)?;
        let rest = s[idx + needle.len()..].trim_start();
        parse_hex_u64(rest.split_whitespace().next()?)
    }
}

// ── CrashDiff ─────────────────────────────────────────────────────────────────

/// Compare two ASAN reports and describe differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashDiff {
    pub same_bug_type: bool,
    pub same_fault_address: bool,
    pub stack_distance: usize,
    pub matching_frames: usize,
}

impl CrashDiff {
    /// Compute the diff between two reports.
    #[must_use]
    pub fn compute(a: &AsanReport, b: &AsanReport) -> Self {
        let same_bug_type = a.bug_type == b.bug_type;
        let same_fault_address = a.fault_address == b.fault_address;
        let (matching, distance) = compare_stacks(&a.fault_stack, &b.fault_stack);
        Self {
            same_bug_type,
            same_fault_address,
            stack_distance: distance,
            matching_frames: matching,
        }
    }

    /// `true` when the two reports are likely the same bug.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        self.same_bug_type && self.matching_frames >= 2
    }
}

// ── BugTypeStatistics ─────────────────────────────────────────────────────────

/// Aggregate counts across many ASAN reports.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BugTypeStatistics {
    pub counts: HashMap<String, usize>,
    pub total: usize,
    pub max_exploitability: u8,
}

impl BugTypeStatistics {
    /// Add a report to the statistics.
    pub fn add(&mut self, report: &AsanReport) {
        *self.counts.entry(report.bug_type.label().to_string()).or_insert(0) += 1;
        self.total += 1;
        if report.exploitability > self.max_exploitability {
            self.max_exploitability = report.exploitability;
        }
    }

    /// Return the most common bug type.
    #[must_use]
    pub fn most_common(&self) -> Option<(&str, usize)> {
        // Ties must not be resolved by `HashMap` iteration order: that order is
        // unspecified and re-seeded every process, so the "most common" bug
        // type could change between runs on identical data. Keys are unique, so
        // falling back to the smallest one is a total order.
        self.counts
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, &v)| (k.as_str(), v))
    }
}

// ── Helper free functions ─────────────────────────────────────────────────────

use crate::parse_hex_u64;

fn parse_location(s: &str) -> (Option<String>, Option<u32>, Option<u32>) {
    if s.is_empty() {
        return (None, None, None);
    }
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    match parts.as_slice() {
        [col_s, line_s, file] => {
            let col = col_s.parse().ok();
            if let Ok(ln) = line_s.parse::<u32>() {
                return (Some(file.to_string()), Some(ln), col);
            }
            (Some(s.to_string()), None, None)
        }
        [line_s, file] => (Some(file.to_string()), line_s.parse().ok(), None),
        [file] => (Some(file.to_string()), None, None),
        _ => (Some(s.to_string()), None, None),
    }
}

fn parse_module_offset(s: &str) -> (Option<String>, Option<u64>) {
    // "(libfoo.so+0x1234)" or "in (/path/to/lib.so+0x5678)"
    let inner = s.trim_start_matches('(').trim_end_matches(')');
    inner.rfind('+').map_or_else(|| (Some(inner.to_string()), None), |plus| {
        let module = inner[..plus].trim().to_string();
        let offset = parse_hex_u64(&inner[plus + 1..]);
        (Some(module), offset)
    })
}

fn compare_stacks(a: &[AsanFrame], b: &[AsanFrame]) -> (usize, usize) {
    let matching = a.iter().zip(b.iter()).filter(|(af, bf)| {
        af.function.is_some() && af.function == bf.function
    }).count();
    let distance = a.len().max(b.len()) - matching;
    (matching, distance)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const ASAN_HEAP_OVERFLOW: &str = r"==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000ef58 at pc 0x555555557a3f
READ of size 4 at 0x60200000ef58 thread T0
    #0 0x555555557a3e in read_buffer /home/user/test.c:42:5
    #1 0x555555556789 in main /home/user/test.c:100:3
    #2 0x7ffff7a2d082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082)
0x60200000ef58 is located 0 bytes to the right of 8-byte region [0x60200000ef50,0x60200000ef58)
allocated by thread T0 here:
    #0 0x7ffff7c8b780 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.6+0xe3780)
    #1 0x555555556700 in setup /home/user/test.c:30:10
";

    const ASAN_UAF: &str = r"==99==ERROR: AddressSanitizer: heap-use-after-free on address 0xdeadbeef
WRITE of size 8 at 0xdeadbeef thread T2
    #0 0x1000 in do_write /src/main.c:10:3
    #1 0x2000 in run /src/main.c:50:1
freed by thread T1 here:
    #0 0x3000 in cleanup /src/main.c:5:3
allocated by thread T0 here:
    #0 0x4000 in init /src/main.c:1:3
";

    #[test]
    fn test_parse_bug_type_heap_overflow() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert_eq!(r.bug_type, AsanBugType::HeapBufferOverflow);
    }

    #[test]
    fn test_parse_bug_type_uaf() {
        let r = AsanAnalyzer::parse(ASAN_UAF);
        assert_eq!(r.bug_type, AsanBugType::HeapUseAfterFree);
    }

    #[test]
    fn test_parse_pid() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert_eq!(r.pid, Some(12345));
    }

    #[test]
    fn test_parse_is_read() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert_eq!(r.is_write, Some(false));
    }

    #[test]
    fn test_parse_is_write_uaf() {
        let r = AsanAnalyzer::parse(ASAN_UAF);
        assert_eq!(r.is_write, Some(true));
    }

    #[test]
    fn test_parse_access_size() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert_eq!(r.access_size, Some(4));
    }

    #[test]
    fn test_parse_fault_address() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert_eq!(r.fault_address, Some(0x6020_0000_ef58));
    }

    #[test]
    fn test_parse_fault_stack_frames() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert!(r.fault_stack.len() >= 2);
        assert_eq!(r.fault_stack[0].index, 0);
    }

    #[test]
    fn test_frame_function_name() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert_eq!(r.fault_stack[0].function.as_deref(), Some("read_buffer"));
    }

    #[test]
    fn test_frame_file_and_line() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let f = &r.fault_stack[0];
        assert!(f.file.as_deref().unwrap_or("").contains("test.c"));
        assert_eq!(f.line, Some(42));
    }

    #[test]
    fn test_allocation_address() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let alloc = r.allocation.unwrap();
        assert_eq!(alloc.address, 0x6020_0000_ef58);
    }

    #[test]
    fn test_uaf_was_freed() {
        let r = AsanAnalyzer::parse(ASAN_UAF);
        let alloc = r.allocation.unwrap();
        assert!(alloc.was_freed);
    }

    #[test]
    fn test_exploitability_score_uaf() {
        assert_eq!(AsanBugType::HeapUseAfterFree.exploitability_score(), 9);
    }

    #[test]
    fn test_exploitability_score_leak() {
        assert_eq!(AsanBugType::MemoryLeak.exploitability_score(), 1);
    }

    #[test]
    fn test_report_exploitability_field() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        assert_eq!(r.exploitability, AsanBugType::HeapBufferOverflow.exploitability_score());
    }

    #[test]
    fn test_user_frames_excludes_sanitizer() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let user = r.user_frames();
        assert!(!user.is_empty());
        assert!(user.iter().all(|f| !f.is_sanitizer_frame()));
    }

    #[test]
    fn test_summary_non_empty() {
        let r = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let s = r.summary();
        assert!(s.contains("heap-buffer-overflow"));
    }

    #[test]
    fn test_parse_all_multiple_reports() {
        let text = format!("{ASAN_HEAP_OVERFLOW}\n{ASAN_UAF}");
        let reports = AsanAnalyzer::parse_all(&text);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_crash_diff_same_bug() {
        let a = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let b = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let diff = CrashDiff::compute(&a, &b);
        assert!(diff.same_bug_type);
    }

    #[test]
    fn test_crash_diff_different_bugs() {
        let a = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let b = AsanAnalyzer::parse(ASAN_UAF);
        let diff = CrashDiff::compute(&a, &b);
        assert!(!diff.same_bug_type);
    }

    #[test]
    fn test_bug_type_statistics() {
        let mut stats = BugTypeStatistics::default();
        let r1 = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let r2 = AsanAnalyzer::parse(ASAN_HEAP_OVERFLOW);
        let r3 = AsanAnalyzer::parse(ASAN_UAF);
        stats.add(&r1);
        stats.add(&r2);
        stats.add(&r3);
        assert_eq!(stats.total, 3);
        let (kind, count) = stats.most_common().unwrap();
        assert_eq!(kind, "heap-buffer-overflow");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_asanbugtype_from_str_unknown() {
        let t = AsanBugType::parse("weird-new-bug");
        assert!(matches!(t, AsanBugType::Unknown(_)));
    }

    #[test]
    fn test_asanbugtype_label_roundtrip() {
        let t = AsanBugType::DoubleFree;
        assert_eq!(t.label(), "double-free");
    }

    #[test]
    fn test_parse_hex_u64_with_prefix() {
        assert_eq!(parse_hex_u64("0xdeadbeef"), Some(0xdead_beef));
    }

    #[test]
    fn test_parse_hex_u64_without_prefix() {
        assert_eq!(parse_hex_u64("deadbeef"), Some(0xdead_beef));
    }

    #[test]
    fn test_frame_display() {
        let f = AsanFrame {
            index: 0,
            address: Some(0x1000),
            function: Some("my_func".into()),
            file: Some("src/main.c".into()),
            line: Some(42),
            column: None,
            module: None,
            module_offset: None,
        };
        let d = f.display();
        assert!(d.contains("my_func"));
        assert!(d.contains("0x1000"));
    }
}
