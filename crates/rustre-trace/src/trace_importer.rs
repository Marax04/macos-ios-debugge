//! Import traces produced by PIN, `DynamoRIO`, QEMU, and other dynamic
//! instrumentation frameworks into a unified [`TraceSession`].
//!
//! Provides [`TraceImporter`], [`TraceFormat`], and [`ImportResult`].

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{TraceEvent, TraceSession};

// ─── ImportError ─────────────────────────────────────────────────────────────

/// Errors produced during trace import.
#[derive(Debug, Error)]
pub enum ImportError {
    /// The file could not be opened.
    #[error("cannot open file {path}: {reason}")]
    Open { path: PathBuf, reason: String },
    /// The file format was not recognised.
    #[error("unknown trace format for {path}")]
    UnknownFormat { path: PathBuf },
    /// A line in the trace file was malformed.
    #[error("parse error at line {line}: {reason}")]
    Parse { line: usize, reason: String },
    /// A required field was missing from the trace header.
    #[error("missing header field: {field}")]
    MissingHeader { field: String },
    /// The format is known but not yet implemented.
    #[error("import for format {format} not implemented")]
    NotImplemented { format: String },
    /// The trace file is empty.
    #[error("trace file is empty")]
    Empty,
    /// Generic I/O error.
    #[error("I/O error: {0}")]
    Io(String),
}

// ─── TraceFormat ─────────────────────────────────────────────────────────────

/// Recognised trace file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceFormat {
    /// PIN's `inscount` text format: `"0x<addr> <size>"` per line.
    PinText,
    /// PIN's `itrace` binary format: little-endian `u64` addresses.
    PinBinary,
    /// `DynamoRIO`'s `drcov` text format used for coverage.
    DrcovText,
    /// `DynamoRIO`'s `memtrace` format: `"<type> <addr> <size>"` per line.
    DrMemtraceText,
    /// QEMU execution log (`-d in_asm`): lines starting with `"0x<addr>:"`.
    QemuInAsm,
    /// Intel PT (Processor Trace) sideband text as exported by `perf script`.
    IntelPtText,
    /// `RustRE`'s own JSON trace format.
    RustreJson,
    /// A simple CSV format: `"<seq>,<addr>,<size>,<tid>,<ts_ns>"`.
    SimpleCsv,
    /// Auto-detect: infer format from magic bytes / extension.
    Auto,
}

impl TraceFormat {
    /// Return the human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PinText => "PIN text",
            Self::PinBinary => "PIN binary",
            Self::DrcovText => "DynamoRIO drcov",
            Self::DrMemtraceText => "DynamoRIO memtrace",
            Self::QemuInAsm => "QEMU in_asm",
            Self::IntelPtText => "Intel PT text",
            Self::RustreJson => "RustRE JSON",
            Self::SimpleCsv => "Simple CSV",
            Self::Auto => "auto-detect",
        }
    }

    /// Detect the format of a file from its extension and magic bytes.
    #[must_use]
    pub fn detect(path: &Path, first_bytes: &[u8]) -> Self {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        // Check for RustRE JSON: starts with `{`
        if first_bytes.first() == Some(&b'{') {
            return Self::RustreJson;
        }

        // PIN binary: starts with 0x50494e42 ('PINB') or all u64 stream
        if first_bytes.starts_with(b"PINB") {
            return Self::PinBinary;
        }

        // drcov has a distinctive header
        if first_bytes.starts_with(b"DRCOV VERSION:") {
            return Self::DrcovText;
        }

        match ext.as_str() {
            "csv" => Self::SimpleCsv,
            "json" => Self::RustreJson,
            "bin" => Self::PinBinary,
            "log" => {
                if first_bytes.starts_with(b"0x") || first_bytes.starts_with(b"IN:") {
                    Self::QemuInAsm
                } else {
                    Self::PinText
                }
            }
            _ => {
                // Fall back to line-content heuristics
                if first_bytes.starts_with(b"0x") {
                    Self::PinText
                } else if first_bytes.starts_with(b"IN:") || first_bytes.starts_with(b"----------------") {
                    Self::QemuInAsm
                } else {
                    Self::PinText
                }
            }
        }
    }
}

impl std::fmt::Display for TraceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─── ImportOptions ────────────────────────────────────────────────────────────

/// Options controlling trace import behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportOptions {
    /// Maximum number of events to import (0 = unlimited).
    pub max_events: usize,
    /// Only import events from this thread (None = all threads).
    pub thread_filter: Option<u32>,
    /// Only import instructions in `[base_addr, base_addr + size)`.
    pub address_filter: Option<(u64, u64)>,
    /// Session name to assign to the imported trace.
    pub session_name: String,
    /// Architecture hint string (e.g. `"x86_64"`, `"aarch64"`).
    pub arch: String,
    /// Default thread ID to assign when the format carries no thread info.
    pub default_thread_id: u32,
    /// Whether to record memory events in addition to instructions.
    pub include_memory: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            max_events: 0,
            thread_filter: None,
            address_filter: None,
            session_name: "imported".to_string(),
            arch: "unknown".to_string(),
            default_thread_id: 1,
            include_memory: false,
        }
    }
}

impl ImportOptions {
    /// Create default options for the given session name.
    #[must_use]
    pub fn new(session_name: impl Into<String>) -> Self {
        Self {
            session_name: session_name.into(),
            ..Default::default()
        }
    }

    /// Set the architecture.
    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = arch.into();
        self
    }

    /// Limit the number of imported events.
    #[must_use]
    pub const fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Filter to a specific thread.
    #[must_use]
    pub const fn with_thread(mut self, tid: u32) -> Self {
        self.thread_filter = Some(tid);
        self
    }

    /// Filter to an address range.
    #[must_use]
    pub const fn with_address_range(mut self, base: u64, size: u64) -> Self {
        self.address_filter = Some((base, base.saturating_add(size)));
        self
    }
}

// ─── ImportResult ─────────────────────────────────────────────────────────────

/// Summary of a completed import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// The imported trace session.
    pub session: TraceSession,
    /// Format that was detected/used.
    pub format: TraceFormat,
    /// Number of lines (or records) parsed from the input.
    pub lines_parsed: usize,
    /// Number of events that were skipped due to filters.
    pub events_filtered: usize,
    /// Number of lines that could not be parsed.
    pub parse_errors: usize,
    /// Source file path.
    pub source_path: PathBuf,
    /// Warnings collected during import.
    pub warnings: Vec<String>,
    /// Wall-clock time spent importing, in milliseconds.
    pub elapsed_ms: u64,
}

impl ImportResult {
    /// Return the number of successfully imported events.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.session.record_count()
    }

    /// Return the parse success rate as a percentage.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.lines_parsed == 0 {
            return 100.0;
        }
        // Use saturating_sub: parse_errors can exceed lines_parsed when the
        // drcov importer counts errors on lines that were not counted as
        // lines_parsed (e.g. unrecognised BB-table entries).
        let ok = self.lines_parsed.saturating_sub(self.parse_errors);
        (ok as f64 / self.lines_parsed as f64) * 100.0
    }
}

impl std::fmt::Display for ImportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "format={} events={} filtered={} errors={} success={:.1}%",
            self.format,
            self.event_count(),
            self.events_filtered,
            self.parse_errors,
            self.success_rate()
        )
    }
}

// ─── TraceImporter ────────────────────────────────────────────────────────────

/// Imports traces from files in various formats.
///
/// # Example
/// ```no_run
/// # use rustre_trace::trace_importer::{TraceImporter, TraceFormat, ImportOptions};
/// # use std::path::Path;
/// let opts = ImportOptions::new("my-trace").with_arch("x86_64");
/// let result = TraceImporter::import_file(Path::new("trace.log"), TraceFormat::Auto, opts).unwrap();
/// println!("{}", result);
/// ```
pub struct TraceImporter;

impl TraceImporter {
    /// Import a trace from a file at `path`.
    ///
    /// # Errors
    /// Returns [`ImportError`] if the file cannot be opened, format detection
    /// fails, or the content is malformed.
    pub fn import_file(
        path: &Path,
        format: TraceFormat,
        opts: ImportOptions,
    ) -> Result<ImportResult, ImportError> {
        let start = std::time::Instant::now();

        let file = std::fs::File::open(path).map_err(|e| ImportError::Open {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;

        let mut data = Vec::new();
        BufReader::new(file)
            .read_to_end(&mut data)
            .map_err(|e| ImportError::Io(e.to_string()))?;

        if data.is_empty() {
            return Err(ImportError::Empty);
        }

        let resolved_format = if format == TraceFormat::Auto {
            TraceFormat::detect(path, &data[..data.len().min(64)])
        } else {
            format
        };

        let mut result =
            Self::import_bytes(&data, path, resolved_format, opts)?;
        result.elapsed_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Import a trace from raw bytes.
    ///
    /// # Errors
    /// Returns [`ImportError`] on format errors or malformed content.
    pub fn import_bytes(
        data: &[u8],
        source_path: &Path,
        format: TraceFormat,
        opts: ImportOptions,
    ) -> Result<ImportResult, ImportError> {
        match format {
            TraceFormat::PinText => Self::import_pin_text(data, source_path, opts, format),
            TraceFormat::SimpleCsv => Self::import_simple_csv(data, source_path, opts, format),
            TraceFormat::QemuInAsm => Self::import_qemu_in_asm(data, source_path, opts, format),
            TraceFormat::DrcovText => Self::import_drcov(data, source_path, opts, format),
            TraceFormat::DrMemtraceText => {
                Self::import_dr_memtrace(data, source_path, opts, format)
            }
            TraceFormat::PinBinary => Self::import_pin_binary(data, source_path, opts, format),
            TraceFormat::RustreJson => Self::import_rustre_json(data, source_path, opts, format),
            TraceFormat::IntelPtText => {
                Err(ImportError::NotImplemented {
                    format: "Intel PT text".to_string(),
                })
            }
            TraceFormat::Auto => Err(ImportError::UnknownFormat {
                path: source_path.to_owned(),
            }),
        }
    }

    // ── PIN text ──────────────────────────────────────────────────────────────

    /// Import PIN's text instruction trace: `"0x<addr> <size>"` per line.
    fn import_pin_text(
        data: &[u8],
        source_path: &Path,
        opts: ImportOptions,
        format: TraceFormat,
    ) -> Result<ImportResult, ImportError> {
        let mut session = TraceSession::new(&opts.session_name, &opts.arch);
        let mut lines_parsed = 0;
        let mut parse_errors = 0;
        let mut events_filtered = 0;
        let mut ts: u64 = 0;

        for (line_no, line) in BufReader::new(data).lines().enumerate() {
            let line = line.map_err(|e| ImportError::Io(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            lines_parsed += 1;

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                parse_errors += 1;
                continue;
            }

            let addr = match Self::parse_hex_addr(parts[0]) {
                Some(a) => a,
                None => {
                    parse_errors += 1;
                    continue;
                }
            };

            let size: u8 = parts
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(4);

            if let Some((lo, hi)) = opts.address_filter {
                if addr < lo || addr >= hi {
                    events_filtered += 1;
                    continue;
                }
            }

            session.push(
                TraceEvent::Instruction { addr, size },
                opts.default_thread_id,
                ts,
            );
            ts += 100;

            if opts.max_events > 0 && session.record_count() >= opts.max_events {
                break;
            }

            let _ = line_no;
        }

        Ok(ImportResult {
            session,
            format,
            lines_parsed,
            events_filtered,
            parse_errors,
            source_path: source_path.to_owned(),
            warnings: Vec::new(),
            elapsed_ms: 0,
        })
    }

    // ── Simple CSV ────────────────────────────────────────────────────────────

    /// Import a simple CSV: `"<seq>,<addr>,<size>,<tid>,<ts_ns>"`.
    fn import_simple_csv(
        data: &[u8],
        source_path: &Path,
        opts: ImportOptions,
        format: TraceFormat,
    ) -> Result<ImportResult, ImportError> {
        let mut session = TraceSession::new(&opts.session_name, &opts.arch);
        let mut lines_parsed = 0;
        let mut parse_errors = 0;
        let mut events_filtered = 0;

        for line in BufReader::new(data).lines() {
            let line = line.map_err(|e| ImportError::Io(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("seq") {
                continue;
            }
            lines_parsed += 1;

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 3 {
                parse_errors += 1;
                continue;
            }

            let addr = match Self::parse_hex_or_dec(parts[1]) {
                Some(a) => a,
                None => {
                    parse_errors += 1;
                    continue;
                }
            };

            let size: u8 = parts[2].trim().parse().unwrap_or(4);
            let tid: u32 = parts
                .get(3)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(opts.default_thread_id);
            let ts: u64 = parts
                .get(4)
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);

            if let Some(filter_tid) = opts.thread_filter {
                if tid != filter_tid {
                    events_filtered += 1;
                    continue;
                }
            }

            if let Some((lo, hi)) = opts.address_filter {
                if addr < lo || addr >= hi {
                    events_filtered += 1;
                    continue;
                }
            }

            session.push(TraceEvent::Instruction { addr, size }, tid, ts);

            if opts.max_events > 0 && session.record_count() >= opts.max_events {
                break;
            }
        }

        Ok(ImportResult {
            session,
            format,
            lines_parsed,
            events_filtered,
            parse_errors,
            source_path: source_path.to_owned(),
            warnings: Vec::new(),
            elapsed_ms: 0,
        })
    }

    // ── QEMU in_asm ───────────────────────────────────────────────────────────

    /// Import QEMU `-d in_asm` log: lines `"0x<addr>:  <mnemonic> ..."`.
    fn import_qemu_in_asm(
        data: &[u8],
        source_path: &Path,
        opts: ImportOptions,
        format: TraceFormat,
    ) -> Result<ImportResult, ImportError> {
        let mut session = TraceSession::new(&opts.session_name, &opts.arch);
        let mut lines_parsed = 0;
        let mut parse_errors = 0;
        let mut events_filtered = 0;
        let mut ts: u64 = 0;

        for line in BufReader::new(data).lines() {
            let line = line.map_err(|e| ImportError::Io(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with("IN:") || line.starts_with("----") {
                continue;
            }
            lines_parsed += 1;

            // QEMU format: "0x00001000:  55                   push   rbp"
            let colon_pos = match line.find(':') {
                Some(p) => p,
                None => {
                    parse_errors += 1;
                    continue;
                }
            };

            let addr_str = line[..colon_pos].trim();
            let addr = match Self::parse_hex_addr(addr_str) {
                Some(a) => a,
                None => {
                    parse_errors += 1;
                    continue;
                }
            };

            // Count the hex bytes in the instruction encoding portion.
            let after = line[colon_pos + 1..].trim();
            let hex_end = after
                .find(|c: char| !c.is_ascii_hexdigit() && c != ' ')
                .unwrap_or(after.len());
            let hex_part = after[..hex_end].trim();
            let size: u8 = (hex_part
                .split_whitespace()
                .count()
                .min(15)) as u8;
            let size = if size == 0 { 4 } else { size };

            if let Some((lo, hi)) = opts.address_filter {
                if addr < lo || addr >= hi {
                    events_filtered += 1;
                    continue;
                }
            }

            session.push(
                TraceEvent::Instruction { addr, size },
                opts.default_thread_id,
                ts,
            );
            ts += 100;

            if opts.max_events > 0 && session.record_count() >= opts.max_events {
                break;
            }
        }

        Ok(ImportResult {
            session,
            format,
            lines_parsed,
            events_filtered,
            parse_errors,
            source_path: source_path.to_owned(),
            warnings: Vec::new(),
            elapsed_ms: 0,
        })
    }

    // ── DynamoRIO drcov ───────────────────────────────────────────────────────

    /// Import `DynamoRIO` `drcov` text format.
    ///
    /// The format has a header section followed by `"BB Table: <n> bbs"` and
    /// then one `"module[<idx>]: <start> <size>:<id>"` line per basic block.
    fn import_drcov(
        data: &[u8],
        source_path: &Path,
        opts: ImportOptions,
        format: TraceFormat,
    ) -> Result<ImportResult, ImportError> {
        let mut session = TraceSession::new(&opts.session_name, &opts.arch);
        let mut lines_parsed = 0;
        let mut parse_errors = 0;
        let mut events_filtered = 0;
        let mut in_bb_table = false;
        let mut ts: u64 = 0;
        let mut module_bases: HashMap<u32, u64> = HashMap::new();

        for line in BufReader::new(data).lines() {
            let line = line.map_err(|e| ImportError::Io(e.to_string()))?;
            let trimmed = line.trim();

            if trimmed.starts_with("DRCOV VERSION:") || trimmed.starts_with("DRCOV FLAVOR:") {
                continue;
            }

            // Module table: "Module Table: version 2, count <n>"
            if trimmed.starts_with("Module Table:") {
                continue;
            }

            // Module entry: " 0,    <base>,   <end>,   <entry>,    0,  0,   <path>"
            if trimmed.starts_with("BB Table:") {
                in_bb_table = true;
                continue;
            }

            // Module entries before BB table
            if !in_bb_table {
                // Try to parse module: " <idx>, <base>, <end>, ..."
                let parts: Vec<&str> = trimmed.split(',').collect();
                if parts.len() >= 3 {
                    let idx = parts[0].trim().parse::<u32>().ok();
                    let base = Self::parse_hex_or_dec(parts[1].trim());
                    if let (Some(idx), Some(base)) = (idx, base) {
                        module_bases.insert(idx, base);
                    }
                }
                continue;
            }

            lines_parsed += 1;

            // BB entry: "module[<idx>]+<offset>: <size>"
            // or binary format packed structs (simplified to text here)
            if trimmed.starts_with("module[") {
                let rest = &trimmed[7..];
                let bracket_end = match rest.find(']') {
                    Some(p) => p,
                    None => {
                        parse_errors += 1;
                        continue;
                    }
                };
                let mod_idx: u32 = rest[..bracket_end].parse().unwrap_or(0);
                let rest = rest[bracket_end + 1..].trim_start_matches('+');
                let colon = match rest.find(':') {
                    Some(p) => p,
                    None => {
                        parse_errors += 1;
                        continue;
                    }
                };
                let offset = Self::parse_hex_or_dec(rest[..colon].trim()).unwrap_or(0);
                let size: u8 = rest[colon + 1..]
                    .trim()
                    .parse()
                    .unwrap_or(4)
                    .min(255) as u8;
                let base = module_bases.get(&mod_idx).copied().unwrap_or(0);
                let addr = base.wrapping_add(offset);

                if let Some((lo, hi)) = opts.address_filter {
                    if addr < lo || addr >= hi {
                        events_filtered += 1;
                        continue;
                    }
                }

                session.push(
                    TraceEvent::Instruction { addr, size },
                    opts.default_thread_id,
                    ts,
                );
                ts += 100;
            } else {
                parse_errors += 1;
            }

            if opts.max_events > 0 && session.record_count() >= opts.max_events {
                break;
            }
        }

        Ok(ImportResult {
            session,
            format,
            lines_parsed,
            events_filtered,
            parse_errors,
            source_path: source_path.to_owned(),
            warnings: Vec::new(),
            elapsed_ms: 0,
        })
    }

    // ── DynamoRIO memtrace ────────────────────────────────────────────────────

    /// Import `DynamoRIO` memtrace text: `"<type> <addr> <size>"`.
    fn import_dr_memtrace(
        data: &[u8],
        source_path: &Path,
        opts: ImportOptions,
        format: TraceFormat,
    ) -> Result<ImportResult, ImportError> {
        let mut session = TraceSession::new(&opts.session_name, &opts.arch);
        let mut lines_parsed = 0;
        let mut parse_errors = 0;
        let mut events_filtered = 0;
        let mut ts: u64 = 0;

        for line in BufReader::new(data).lines() {
            let line = line.map_err(|e| ImportError::Io(e.to_string()))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            lines_parsed += 1;

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                parse_errors += 1;
                continue;
            }

            let event_type = parts[0];
            let addr = match Self::parse_hex_or_dec(parts[1]) {
                Some(a) => a,
                None => {
                    parse_errors += 1;
                    continue;
                }
            };
            let size: u8 = parts[2].parse().unwrap_or(4).min(255) as u8;

            if let Some((lo, hi)) = opts.address_filter {
                if addr < lo || addr >= hi {
                    events_filtered += 1;
                    continue;
                }
            }

            let event = match event_type {
                "I" | "instr" => TraceEvent::Instruction { addr, size },
                "R" | "read" => TraceEvent::MemRead {
                    addr,
                    size,
                    value: 0,
                },
                "W" | "write" => TraceEvent::MemWrite {
                    addr,
                    size,
                    value: 0,
                },
                _ => {
                    parse_errors += 1;
                    continue;
                }
            };

            if !opts.include_memory && !matches!(event, TraceEvent::Instruction { .. }) {
                events_filtered += 1;
                continue;
            }

            session.push(event, opts.default_thread_id, ts);
            ts += 100;

            if opts.max_events > 0 && session.record_count() >= opts.max_events {
                break;
            }
        }

        Ok(ImportResult {
            session,
            format,
            lines_parsed,
            events_filtered,
            parse_errors,
            source_path: source_path.to_owned(),
            warnings: Vec::new(),
            elapsed_ms: 0,
        })
    }

    // ── PIN binary ────────────────────────────────────────────────────────────

    /// Import PIN's binary trace: raw little-endian `u64` addresses.
    fn import_pin_binary(
        data: &[u8],
        source_path: &Path,
        opts: ImportOptions,
        format: TraceFormat,
    ) -> Result<ImportResult, ImportError> {
        if data.len() < 8 {
            return Err(ImportError::Empty);
        }

        // Skip optional 4-byte magic header "PINB".
        let start_offset = if data.starts_with(b"PINB") { 4 } else { 0 };
        let payload = &data[start_offset..];

        let mut session = TraceSession::new(&opts.session_name, &opts.arch);
        let mut lines_parsed = 0;
        let mut events_filtered = 0;
        let mut ts: u64 = 0;

        let mut pos = 0;
        while pos + 8 <= payload.len() {
            let addr = u64::from_le_bytes([
                payload[pos],
                payload[pos + 1],
                payload[pos + 2],
                payload[pos + 3],
                payload[pos + 4],
                payload[pos + 5],
                payload[pos + 6],
                payload[pos + 7],
            ]);
            pos += 8;
            lines_parsed += 1;

            if addr == 0 {
                continue;
            }

            if let Some((lo, hi)) = opts.address_filter {
                if addr < lo || addr >= hi {
                    events_filtered += 1;
                    continue;
                }
            }

            session.push(
                TraceEvent::Instruction { addr, size: 4 },
                opts.default_thread_id,
                ts,
            );
            ts += 100;

            if opts.max_events > 0 && session.record_count() >= opts.max_events {
                break;
            }
        }

        Ok(ImportResult {
            session,
            format,
            lines_parsed,
            events_filtered,
            parse_errors: 0,
            source_path: source_path.to_owned(),
            warnings: Vec::new(),
            elapsed_ms: 0,
        })
    }

    // ── RustRE JSON ───────────────────────────────────────────────────────────

    /// Import a `RustRE` JSON-serialized [`crate::Trace`].
    fn import_rustre_json(
        data: &[u8],
        source_path: &Path,
        opts: ImportOptions,
        format: TraceFormat,
    ) -> Result<ImportResult, ImportError> {
        let trace: crate::Trace = serde_json::from_slice(data)
            .map_err(|e| ImportError::Parse { line: 0, reason: e.to_string() })?;

        let mut filtered_session = TraceSession::new(&opts.session_name, &opts.arch);
        let mut events_filtered = 0;

        for rec in &trace.session.records {
            if let Some(filter_tid) = opts.thread_filter {
                if rec.thread_id != filter_tid {
                    events_filtered += 1;
                    continue;
                }
            }
            if opts.max_events > 0 && filtered_session.record_count() >= opts.max_events {
                break;
            }
            filtered_session.push(rec.event.clone(), rec.thread_id, rec.timestamp_ns);
        }

        let total = trace.session.record_count();

        Ok(ImportResult {
            session: filtered_session,
            format,
            lines_parsed: total,
            events_filtered,
            parse_errors: 0,
            source_path: source_path.to_owned(),
            warnings: Vec::new(),
            elapsed_ms: 0,
        })
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Parse a `"0x..."` or plain hex address string into a `u64`.
    fn parse_hex_addr(s: &str) -> Option<u64> {
        let s = s.trim();
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        u64::from_str_radix(s, 16).ok()
    }

    /// Parse a hex (`"0x..."`) or decimal string.
    fn parse_hex_or_dec(s: &str) -> Option<u64> {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            s.parse().ok()
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn dummy_path() -> &'static Path {
        Path::new("test.log")
    }

    fn default_opts() -> ImportOptions {
        ImportOptions::new("test").with_arch("x86_64")
    }

    #[test]
    fn test_pin_text_basic() {
        let data = b"0x401000 4\n0x401004 3\n0x401007 5\n";
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::PinText,
            default_opts(),
        )
        .unwrap();
        assert_eq!(result.event_count(), 3);
        assert_eq!(result.parse_errors, 0);
    }

    #[test]
    fn test_pin_text_skip_comments() {
        let data = b"# comment\n0x1000 4\n# another\n0x1004 4\n";
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::PinText,
            default_opts(),
        )
        .unwrap();
        assert_eq!(result.event_count(), 2);
    }

    #[test]
    fn test_simple_csv_basic() {
        let data = b"0,0x401000,4,1,100\n1,0x401004,3,1,200\n";
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::SimpleCsv,
            default_opts(),
        )
        .unwrap();
        assert_eq!(result.event_count(), 2);
    }

    #[test]
    fn test_simple_csv_skip_header() {
        let data = b"seq,addr,size,tid,ts\n0,0x1000,4,1,0\n";
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::SimpleCsv,
            default_opts(),
        )
        .unwrap();
        assert_eq!(result.event_count(), 1);
    }

    #[test]
    fn test_qemu_in_asm_basic() {
        let data = b"IN: main\n0x00401000:  55             push   rbp\n0x00401001:  48 89 e5       mov    rbp, rsp\n";
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::QemuInAsm,
            default_opts(),
        )
        .unwrap();
        assert_eq!(result.event_count(), 2);
    }

    #[test]
    fn test_pin_binary_basic() {
        let mut data = b"PINB".to_vec();
        let addrs: [u64; 3] = [0x1000, 0x1004, 0x1008];
        for addr in addrs {
            data.extend_from_slice(&addr.to_le_bytes());
        }
        let result = TraceImporter::import_bytes(
            &data,
            dummy_path(),
            TraceFormat::PinBinary,
            default_opts(),
        )
        .unwrap();
        assert_eq!(result.event_count(), 3);
    }

    #[test]
    fn test_max_events_limit() {
        let lines: String = (0..100)
            .map(|i| format!("0x{:04x} 4\n", 0x1000 + i * 4))
            .collect();
        let opts = default_opts().with_max_events(10);
        let result = TraceImporter::import_bytes(
            lines.as_bytes(),
            dummy_path(),
            TraceFormat::PinText,
            opts,
        )
        .unwrap();
        assert_eq!(result.event_count(), 10);
    }

    #[test]
    fn test_address_filter() {
        let data = b"0x1000 4\n0x2000 4\n0x3000 4\n";
        let opts = default_opts().with_address_range(0x2000, 0x1000);
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::PinText,
            opts,
        )
        .unwrap();
        assert_eq!(result.event_count(), 1);
        assert_eq!(result.events_filtered, 2);
    }

    #[test]
    fn test_dr_memtrace_instructions_only() {
        let data = b"I 0x1000 4\nR 0x2000 8\nW 0x3000 4\nI 0x1004 3\n";
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::DrMemtraceText,
            default_opts(),
        )
        .unwrap();
        // include_memory is false by default
        assert_eq!(result.event_count(), 2);
    }

    #[test]
    fn test_dr_memtrace_with_memory() {
        let data = b"I 0x1000 4\nR 0x2000 8\nW 0x3000 4\n";
        let mut opts = default_opts();
        opts.include_memory = true;
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::DrMemtraceText,
            opts,
        )
        .unwrap();
        assert_eq!(result.event_count(), 3);
    }

    #[test]
    fn test_format_detect_from_bytes() {
        let rustre_json = b"{\"session\":{}}";
        assert_eq!(
            TraceFormat::detect(dummy_path(), rustre_json),
            TraceFormat::RustreJson
        );

        let drcov = b"DRCOV VERSION: 2\n";
        assert_eq!(
            TraceFormat::detect(dummy_path(), drcov),
            TraceFormat::DrcovText
        );

        let pin_binary = b"PINB\x00\x10\x40\x00";
        assert_eq!(
            TraceFormat::detect(dummy_path(), pin_binary),
            TraceFormat::PinBinary
        );
    }

    #[test]
    fn test_parse_hex_addr() {
        assert_eq!(TraceImporter::parse_hex_addr("0x401000"), Some(0x401000));
        assert_eq!(TraceImporter::parse_hex_addr("0X1000"), Some(0x1000));
        assert_eq!(TraceImporter::parse_hex_addr("abc"), Some(0xabc));
        assert_eq!(TraceImporter::parse_hex_addr("gggg"), None);
    }

    #[test]
    fn test_success_rate() {
        let data = b"0x1000 4\nBADLINE\n0x1004 4\n";
        let result = TraceImporter::import_bytes(
            data,
            dummy_path(),
            TraceFormat::PinText,
            default_opts(),
        )
        .unwrap();
        assert!(result.success_rate() < 100.0);
    }
}
