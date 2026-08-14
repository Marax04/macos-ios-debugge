//! `procmon_log_parser` — Parse Process Monitor CSV export logs.
//!
//! Process Monitor (from Sysinternals) can export its event log to CSV.
//! This module reads such exports, parses every row into a typed `ProcmonEvent`,
//! and provides filtering / aggregation helpers.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

// ── EventClass ────────────────────────────────────────────────────────────────

/// High-level category of a Process Monitor event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventClass {
    /// File-system read/write/create/delete operations.
    FileSystem,
    /// Windows registry read/write/delete operations.
    Registry,
    /// Network connect/send/receive operations.
    Network,
    /// Process/thread creation and termination.
    Process,
    /// Profiling events (thread profiling, etc.).
    Profiling,
    /// Unknown or unsupported class.
    Unknown,
}

impl FromStr for EventClass {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.trim() {
            "File System" | "FileSystem" => Ok(Self::FileSystem),
            "Registry" => Ok(Self::Registry),
            "Network" => Ok(Self::Network),
            "Process" | "Process Activity" => Ok(Self::Process),
            "Profiling" => Ok(Self::Profiling),
            _ => Ok(Self::Unknown),
        }
    }
}

impl fmt::Display for EventClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSystem => write!(f, "FileSystem"),
            Self::Registry => write!(f, "Registry"),
            Self::Network => write!(f, "Network"),
            Self::Process => write!(f, "Process"),
            Self::Profiling => write!(f, "Profiling"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── ResultCode ────────────────────────────────────────────────────────────────

/// Windows NTSTATUS / Win32 result code for an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResultCode {
    /// `STATUS_SUCCESS` / `ERROR_SUCCESS`.
    Success,
    /// `STATUS_ACCESS_DENIED` / `ERROR_ACCESS_DENIED`.
    AccessDenied,
    /// `STATUS_OBJECT_NAME_NOT_FOUND` / `ERROR_FILE_NOT_FOUND`.
    NotFound,
    /// `STATUS_BUFFER_OVERFLOW`.
    BufferOverflow,
    /// `STATUS_END_OF_FILE` / EOF.
    EndOfFile,
    /// `STATUS_OBJECT_NAME_COLLISION` / file already exists.
    NameCollision,
    /// Any other result stored as the raw string.
    Other(String),
}

impl FromStr for ResultCode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.trim() {
            "SUCCESS" | "success" => Ok(Self::Success),
            "ACCESS DENIED" | "ACCESS_DENIED" => Ok(Self::AccessDenied),
            "NAME NOT FOUND" | "PATH NOT FOUND" | "NO SUCH FILE" => Ok(Self::NotFound),
            "BUFFER OVERFLOW" => Ok(Self::BufferOverflow),
            "END OF FILE" => Ok(Self::EndOfFile),
            "NAME COLLISION" | "OBJECT NAME COLLISION" => Ok(Self::NameCollision),
            other => Ok(Self::Other(other.to_string())),
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::AccessDenied => write!(f, "ACCESS DENIED"),
            Self::NotFound => write!(f, "NAME NOT FOUND"),
            Self::BufferOverflow => write!(f, "BUFFER OVERFLOW"),
            Self::EndOfFile => write!(f, "END OF FILE"),
            Self::NameCollision => write!(f, "NAME COLLISION"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

// ── ProcmonEvent ──────────────────────────────────────────────────────────────

/// A single row from a Process Monitor CSV export.
#[derive(Debug, Clone)]
pub struct ProcmonEvent {
    /// Sequence number (row index in the CSV, 0-based).
    pub sequence: u64,
    /// Timestamp string as recorded by Procmon (e.g. `"9:14:07.6441847 AM"`).
    pub time_of_day: String,
    /// Image name (process exe basename, e.g. `"notepad.exe"`).
    pub process_name: String,
    /// Numeric process identifier.
    pub pid: u32,
    /// High-level event category.
    pub event_class: EventClass,
    /// Fine-grained operation name (e.g. `"ReadFile"`, `"RegQueryValue"`).
    pub operation: String,
    /// Path / registry key / network address involved.
    pub path: String,
    /// Operation result.
    pub result: ResultCode,
    /// Free-text detail field (varies by operation).
    pub detail: String,
}

impl ProcmonEvent {
    /// Returns `true` if this event's result indicates success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.result == ResultCode::Success
    }

    /// Returns `true` if the operation failed for any reason.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        !self.is_success()
    }

    /// Returns `true` if this is a file-system event.
    #[must_use]
    pub fn is_file_system(&self) -> bool {
        self.event_class == EventClass::FileSystem
    }

    /// Returns `true` if this is a registry event.
    #[must_use]
    pub fn is_registry(&self) -> bool {
        self.event_class == EventClass::Registry
    }
}

impl fmt::Display for ProcmonEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (pid={}) {} {} -> {}",
            self.sequence,
            self.process_name,
            self.pid,
            self.operation,
            self.path,
            self.result,
        )
    }
}

// ── CSV parsing helpers ───────────────────────────────────────────────────────

/// Naive CSV field splitter that respects double-quoted fields containing commas.
fn split_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    // Check for escaped quote "".
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        current.push('"');
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current = String::new();
            }
            other => current.push(other),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Column indices for the standard Procmon CSV export header.
#[derive(Debug, Default)]
struct ColumnMap {
    time_of_day: Option<usize>,
    process_name: Option<usize>,
    pid: Option<usize>,
    event_class: Option<usize>,
    operation: Option<usize>,
    path: Option<usize>,
    result: Option<usize>,
    detail: Option<usize>,
}

impl ColumnMap {
    fn from_header(fields: &[String]) -> Self {
        let mut cm = Self::default();
        for (i, f) in fields.iter().enumerate() {
            match f.as_str() {
                "Time of Day" | "TimeOfDay" | "Time" => cm.time_of_day = Some(i),
                "Process Name" | "ProcessName" => cm.process_name = Some(i),
                "PID" | "Pid" => cm.pid = Some(i),
                "Event Class" | "EventClass" | "Category" => cm.event_class = Some(i),
                "Operation" => cm.operation = Some(i),
                "Path" => cm.path = Some(i),
                "Result" => cm.result = Some(i),
                "Detail" => cm.detail = Some(i),
                _ => {}
            }
        }
        cm
    }

    fn get(fields: &[String], idx: Option<usize>) -> &str {
        idx.and_then(|i| fields.get(i)).map_or("", String::as_str)
    }
}

// ── ParseError ────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing a Procmon CSV log.
#[derive(Debug)]
pub enum ParseError {
    /// The CSV text is empty or contains no header.
    EmptyInput,
    /// The header row is missing required columns.
    MissingColumns(Vec<&'static str>),
    /// A specific data row could not be parsed.
    MalformedRow { line_number: usize, reason: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "CSV input is empty"),
            Self::MissingColumns(cols) => write!(f, "missing columns: {}", cols.join(", ")),
            Self::MalformedRow { line_number, reason } => {
                write!(f, "malformed row at line {line_number}: {reason}")
            }
        }
    }
}

// ── ProcmonLogParser ──────────────────────────────────────────────────────────

/// Parses Process Monitor CSV export files into a typed event list.
pub struct ProcmonLogParser {
    /// Events parsed from the last [`parse_csv_log`] / [`parse_str`] call.
    pub events: Vec<ProcmonEvent>,
    /// Non-fatal parse warnings (e.g. rows with unexpected column counts).
    pub warnings: Vec<String>,
    /// Lines that could not be parsed at all.
    pub skipped_lines: usize,
}

impl ProcmonLogParser {
    /// Create a new, empty parser.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            warnings: Vec::new(),
            skipped_lines: 0,
        }
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    /// Parse a Procmon CSV log from a string slice.
    ///
    /// The first non-empty line is treated as the header.  Subsequent lines are
    /// data rows. Returns `Err` only for fatal problems (missing header, no
    /// recognisable columns); individual bad rows are counted in
    /// `self.skipped_lines`.
    pub fn parse_str(&mut self, csv: &str) -> Result<(), ParseError> {
        self.events.clear();
        self.warnings.clear();
        self.skipped_lines = 0;

        let mut lines = csv.lines().enumerate().filter(|(_, l)| !l.trim().is_empty());

        let (_, header_line) = lines.next().ok_or(ParseError::EmptyInput)?;
        let header_fields = split_csv_row(header_line);
        let cm = ColumnMap::from_header(&header_fields);

        // Require at least process_name and operation.
        let mut missing = Vec::new();
        if cm.process_name.is_none() { missing.push("Process Name"); }
        if cm.operation.is_none() { missing.push("Operation"); }
        if !missing.is_empty() {
            return Err(ParseError::MissingColumns(missing));
        }

        for (line_no, line) in lines {
            let fields = split_csv_row(line);
            let pid_str = ColumnMap::get(&fields, cm.pid);
            let pid: u32 = pid_str.parse().unwrap_or(0);

            let event_class = ColumnMap::get(&fields, cm.event_class)
                .parse::<EventClass>()
                .unwrap_or(EventClass::Unknown);

            let result = ColumnMap::get(&fields, cm.result)
                .parse::<ResultCode>()
                .unwrap_or(ResultCode::Other(String::new()));

            let event = ProcmonEvent {
                sequence: (self.events.len() + self.skipped_lines) as u64,
                time_of_day: ColumnMap::get(&fields, cm.time_of_day).to_string(),
                process_name: ColumnMap::get(&fields, cm.process_name).to_string(),
                pid,
                event_class,
                operation: ColumnMap::get(&fields, cm.operation).to_string(),
                path: ColumnMap::get(&fields, cm.path).to_string(),
                result,
                detail: ColumnMap::get(&fields, cm.detail).to_string(),
            };

            if event.process_name.is_empty() && event.operation.is_empty() {
                self.skipped_lines += 1;
                self.warnings.push(format!("line {line_no}: empty process_name and operation"));
            } else {
                self.events.push(event);
            }
        }

        Ok(())
    }

    /// Total number of events successfully parsed.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Return all events for the given process name (case-insensitive).
    #[must_use]
    pub fn events_for_process(&self, name: &str) -> Vec<&ProcmonEvent> {
        let lower = name.to_lowercase();
        self.events
            .iter()
            .filter(|e| e.process_name.to_lowercase() == lower)
            .collect()
    }

    /// Return all events of the given class.
    #[must_use]
    pub fn events_by_class(&self, class: EventClass) -> Vec<&ProcmonEvent> {
        self.events
            .iter()
            .filter(|e| e.event_class == class)
            .collect()
    }

    /// Return all failed events.
    #[must_use]
    pub fn failed_events(&self) -> Vec<&ProcmonEvent> {
        self.events.iter().filter(|e| e.is_failure()).collect()
    }

    /// Count events grouped by process name.
    #[must_use]
    pub fn events_per_process(&self) -> HashMap<&str, usize> {
        let mut map: HashMap<&str, usize> = HashMap::new();
        for e in &self.events {
            *map.entry(e.process_name.as_str()).or_insert(0) += 1;
        }
        map
    }

    /// Count events grouped by event class.
    #[must_use]
    pub fn events_per_class(&self) -> HashMap<EventClass, usize> {
        let mut map: HashMap<EventClass, usize> = HashMap::new();
        for e in &self.events {
            *map.entry(e.event_class).or_insert(0) += 1;
        }
        map
    }

    /// Return unique paths accessed for a given process and event class.
    #[must_use]
    pub fn unique_paths(&self, process: &str, class: EventClass) -> Vec<&str> {
        let lower = process.to_lowercase();
        let mut paths: Vec<&str> = self
            .events
            .iter()
            .filter(|e| {
                e.event_class == class && e.process_name.to_lowercase() == lower
            })
            .map(|e| e.path.as_str())
            .filter(|p| !p.is_empty())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        paths
    }

    /// Return all registry keys written by any process.
    #[must_use]
    pub fn registry_writes(&self) -> Vec<&ProcmonEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.event_class == EventClass::Registry
                    && (e.operation.contains("SetValue")
                        || e.operation.contains("CreateKey")
                        || e.operation.contains("DeleteKey")
                        || e.operation.contains("DeleteValue"))
                    && e.is_success()
            })
            .collect()
    }

    /// Return all network events.
    #[must_use]
    pub fn network_events(&self) -> Vec<&ProcmonEvent> {
        self.events_by_class(EventClass::Network)
    }

    /// Return all process-creation events.
    #[must_use]
    pub fn process_creates(&self) -> Vec<&ProcmonEvent> {
        self.events
            .iter()
            .filter(|e| {
                e.event_class == EventClass::Process
                    && e.operation.contains("Process Create")
                    && e.is_success()
            })
            .collect()
    }

    /// Find events where the path contains `needle` (case-insensitive).
    #[must_use]
    pub fn find_by_path(&self, needle: &str) -> Vec<&ProcmonEvent> {
        let lower = needle.to_lowercase();
        self.events
            .iter()
            .filter(|e| e.path.to_lowercase().contains(&lower))
            .collect()
    }
}

impl Default for ProcmonLogParser {
    fn default() -> Self {
        Self::new()
    }
}

// ── parse_csv_log (free function) ─────────────────────────────────────────────

/// Convenience function: parse a Procmon CSV string and return the event list.
///
/// # Errors
/// Returns `ParseError` if the input is empty or missing required columns.
pub fn parse_csv_log(csv: &str) -> Result<Vec<ProcmonEvent>, ParseError> {
    let mut parser = ProcmonLogParser::new();
    parser.parse_str(csv)?;
    Ok(parser.events)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CSV: &str = r#"Time of Day,Process Name,PID,Event Class,Operation,Path,Result,Detail
9:14:07.000 AM,notepad.exe,1234,File System,ReadFile,C:\Users\user\test.txt,SUCCESS,"Offset: 0, Length: 100"
9:14:07.001 AM,notepad.exe,1234,File System,WriteFile,C:\Users\user\out.txt,SUCCESS,"Offset: 0, Length: 50"
9:14:07.002 AM,regedit.exe,5678,Registry,RegSetValue,HKCU\Software\Test\Value,SUCCESS,"Type: REG_SZ, Length: 12"
9:14:07.003 AM,chrome.exe,9012,Network,TCP Send,93.184.216.34:80,SUCCESS,"Length: 512"
9:14:07.004 AM,notepad.exe,1234,File System,ReadFile,C:\missing.txt,NAME NOT FOUND,""
"#;

    #[test]
    fn test_parse_event_count() {
        let events = parse_csv_log(SAMPLE_CSV).unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn test_event_class_parsed() {
        let events = parse_csv_log(SAMPLE_CSV).unwrap();
        assert_eq!(events[0].event_class, EventClass::FileSystem);
        assert_eq!(events[2].event_class, EventClass::Registry);
        assert_eq!(events[3].event_class, EventClass::Network);
    }

    #[test]
    fn test_result_parsed() {
        let events = parse_csv_log(SAMPLE_CSV).unwrap();
        assert!(events[0].is_success());
        assert!(events[4].is_failure());
        assert_eq!(events[4].result, ResultCode::NotFound);
    }

    #[test]
    fn test_events_for_process() {
        let mut parser = ProcmonLogParser::new();
        parser.parse_str(SAMPLE_CSV).unwrap();
        let notepad = parser.events_for_process("notepad.exe");
        assert_eq!(notepad.len(), 3);
    }

    #[test]
    fn test_events_by_class() {
        let mut parser = ProcmonLogParser::new();
        parser.parse_str(SAMPLE_CSV).unwrap();
        let fs = parser.events_by_class(EventClass::FileSystem);
        assert_eq!(fs.len(), 3);
    }

    #[test]
    fn test_failed_events() {
        let mut parser = ProcmonLogParser::new();
        parser.parse_str(SAMPLE_CSV).unwrap();
        let failed = parser.failed_events();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].path, r"C:\missing.txt");
    }

    #[test]
    fn test_registry_writes() {
        let mut parser = ProcmonLogParser::new();
        parser.parse_str(SAMPLE_CSV).unwrap();
        let writes = parser.registry_writes();
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn test_find_by_path() {
        let mut parser = ProcmonLogParser::new();
        parser.parse_str(SAMPLE_CSV).unwrap();
        let results = parser.find_by_path("users");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_empty_input() {
        let result = parse_csv_log("");
        assert!(matches!(result, Err(ParseError::EmptyInput)));
    }

    #[test]
    fn test_missing_columns() {
        let csv = "Time of Day,PID\n9:00 AM,1234\n";
        let result = parse_csv_log(csv);
        assert!(matches!(result, Err(ParseError::MissingColumns(_))));
    }

    #[test]
    fn test_split_csv_row_quoted() {
        let row = r#"a,"b,c",d"#;
        let fields = split_csv_row(row);
        assert_eq!(fields, vec!["a", "b,c", "d"]);
    }

    #[test]
    fn test_events_per_process() {
        let mut parser = ProcmonLogParser::new();
        parser.parse_str(SAMPLE_CSV).unwrap();
        let counts = parser.events_per_process();
        assert_eq!(counts.get("notepad.exe"), Some(&3));
        assert_eq!(counts.get("chrome.exe"), Some(&1));
    }
}
