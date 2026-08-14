//! `UndefinedBehaviorSanitizer` (`UBSan`) report parser.
//!
//! Parses the textual output produced by a UBSan-instrumented binary into
//! structured Rust types for further analysis or deduplication.
//!
//! # Key types
//!
//! * [`UbsanReportParser`] — stateless parser entry-point.
//! * [`UbReport`] — a single parsed `UBSan` diagnostic message.
//! * [`UbKind`] — category of the undefined-behaviour violation.
//! * Free function [`parse_ubsan_output`] — convenience wrapper.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── UbKind ────────────────────────────────────────────────────────────────────

/// Category of undefined behaviour detected by `UBSan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UbKind {
    IntegerOverflow,
    IntegerDivisionByZero,
    SignedIntegerOverflow,
    UnsignedIntegerOverflow,
    NullPointerDereference,
    NullArgument,
    OutOfBoundsAccess,
    ShiftExponent,
    InvalidBoolValue,
    InvalidEnumValue,
    UnreachableCode,
    ReturnFromNonVoidFunction,
    PointerOverflow,
    Vlabound,
    Alignment,
    ObjectSize,
    ImplicitIntegerTruncation,
    ImplicitIntegerSignChange,
    ImplicitUnsignedIntegerTruncation,
    ImplicitSignedIntegerTruncation,
    FloatCastOverflow,
    FunctionTypeMismatch,
    VtablePointerInvalid,
    /// Unknown violation type.
    Unknown(String),
}

impl UbKind {
    /// Attempt to recognise the `UBSan` check name emitted in the report.
    #[must_use]
    pub fn from_check_name(s: &str) -> Self {
        let lower = s.trim().to_ascii_lowercase();
        match lower.as_str() {
            "signed-integer-overflow" | "add-overflow" | "sub-overflow" | "mul-overflow" => {
                Self::SignedIntegerOverflow
            }
            "unsigned-integer-overflow" => Self::UnsignedIntegerOverflow,
            "integer-overflow" | "integer overflow" => Self::IntegerOverflow,
            "divide-by-zero" | "division-by-zero" | "integer division by zero" => {
                Self::IntegerDivisionByZero
            }
            "null-dereference" | "load of null pointer"
            | "store to null pointer"
            | "null pointer dereference" => Self::NullPointerDereference,
            "null-argument" | "null pointer passed as argument" => Self::NullArgument,
            "out-of-bounds" | "index out of bounds" => Self::OutOfBoundsAccess,
            "shift-exponent" | "shift" => Self::ShiftExponent,
            "bool" | "load of value which is not a valid value for type bool" => {
                Self::InvalidBoolValue
            }
            "enum" | "load of value which is not a valid value for type" => {
                Self::InvalidEnumValue
            }
            "unreachable" | "execution reached an unreachable program point" => {
                Self::UnreachableCode
            }
            "nonnull-return" | "return" | "non-null return value" => {
                Self::ReturnFromNonVoidFunction
            }
            "pointer-overflow" => Self::PointerOverflow,
            "vla-bound" => Self::Vlabound,
            "alignment" | "misaligned-pointer-use" => Self::Alignment,
            "object-size" | "type-limits" => Self::ObjectSize,
            "implicit-integer-truncation" => Self::ImplicitIntegerTruncation,
            "implicit-integer-sign-change" => Self::ImplicitIntegerSignChange,
            "implicit-unsigned-integer-truncation" => Self::ImplicitUnsignedIntegerTruncation,
            "implicit-signed-integer-truncation" => Self::ImplicitSignedIntegerTruncation,
            "float-cast-overflow" => Self::FloatCastOverflow,
            "function" | "function-type-mismatch" | "indirect call through pointer" => {
                Self::FunctionTypeMismatch
            }
            "vptr" | "vtable" | "invalid vptr" => Self::VtablePointerInvalid,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Short canonical name for this kind.
    #[must_use]
    pub const fn canonical_name(&self) -> &str {
        match self {
            Self::IntegerOverflow => "integer-overflow",
            Self::IntegerDivisionByZero => "divide-by-zero",
            Self::SignedIntegerOverflow => "signed-integer-overflow",
            Self::UnsignedIntegerOverflow => "unsigned-integer-overflow",
            Self::NullPointerDereference => "null-dereference",
            Self::NullArgument => "null-argument",
            Self::OutOfBoundsAccess => "out-of-bounds",
            Self::ShiftExponent => "shift-exponent",
            Self::InvalidBoolValue => "invalid-bool",
            Self::InvalidEnumValue => "invalid-enum",
            Self::UnreachableCode => "unreachable",
            Self::ReturnFromNonVoidFunction => "nonnull-return",
            Self::PointerOverflow => "pointer-overflow",
            Self::Vlabound => "vla-bound",
            Self::Alignment => "alignment",
            Self::ObjectSize => "object-size",
            Self::ImplicitIntegerTruncation => "implicit-truncation",
            Self::ImplicitIntegerSignChange => "implicit-sign-change",
            Self::ImplicitUnsignedIntegerTruncation => "implicit-unsigned-truncation",
            Self::ImplicitSignedIntegerTruncation => "implicit-signed-truncation",
            Self::FloatCastOverflow => "float-cast-overflow",
            Self::FunctionTypeMismatch => "function-type-mismatch",
            Self::VtablePointerInvalid => "invalid-vptr",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Whether this violation is in the security-relevant class.
    #[must_use]
    pub const fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Self::NullPointerDereference
                | Self::OutOfBoundsAccess
                | Self::IntegerOverflow
                | Self::SignedIntegerOverflow
                | Self::UnsignedIntegerOverflow
                | Self::IntegerDivisionByZero
                | Self::PointerOverflow
                | Self::FunctionTypeMismatch
                | Self::VtablePointerInvalid
        )
    }
}

impl fmt::Display for UbKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical_name())
    }
}

// ── SourceLocation ────────────────────────────────────────────────────────────

/// Source code location associated with a `UBSan` diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Absolute or relative source file path.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number, if available.
    pub column: Option<u32>,
}

impl SourceLocation {
    /// Parse a `file:line:column` or `file:line` string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let parts: Vec<&str> = s.rsplitn(3, ':').collect();
        match parts.as_slice() {
            [col_s, line_s, file] => {
                let line = line_s.parse::<u32>().ok()?;
                let column = col_s.parse::<u32>().ok();
                Some(Self { file: (*file).to_owned(), line, column })
            }
            [line_s, file] => {
                let line = line_s.parse::<u32>().ok()?;
                Some(Self { file: (*file).to_owned(), line, column: None })
            }
            _ => None,
        }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)?;
        if let Some(c) = self.column {
            write!(f, ":{c}")?;
        }
        Ok(())
    }
}

// ── UbReport ──────────────────────────────────────────────────────────────────

/// A single parsed `UBSan` violation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbReport {
    /// Category of the undefined behaviour.
    pub kind: UbKind,
    /// Source location of the violation, if parseable.
    pub location: Option<SourceLocation>,
    /// The human-readable description line emitted by `UBSan`.
    pub description: String,
    /// Runtime value information extracted from the message (e.g. the integer
    /// value that overflowed, or the pointer that was null).
    pub runtime_value: Option<RuntimeValue>,
    /// Additional note/context lines that followed the primary error line.
    pub notes: Vec<String>,
    /// Raw text of the report block.
    pub raw_text: String,
}

impl UbReport {
    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let loc = self
            .location
            .as_ref()
            .map_or_else(|| "<unknown>".to_owned(), std::string::ToString::to_string);
        format!("[UBSan] {} at {} — {}", self.kind, loc, self.description)
    }

    /// Deduplication key: kind + source location (file + line, without column).
    #[must_use]
    pub fn dedup_key(&self) -> String {
        let loc = self.location.as_ref().map_or_else(|| "?:?".to_owned(), |l| format!("{}:{}", l.file, l.line));
        format!("{}|{}", self.kind, loc)
    }

    /// Returns `true` if this violation is security-relevant.
    #[must_use]
    pub const fn is_security_relevant(&self) -> bool {
        self.kind.is_security_relevant()
    }
}

impl fmt::Display for UbReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── RuntimeValue ─────────────────────────────────────────────────────────────

/// A runtime value extracted from the `UBSan` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeValue {
    /// An integer value (overflowed operand, shift amount, etc.).
    Integer(i128),
    /// An unsigned integer value.
    Unsigned(u128),
    /// A pointer / address.
    Address(u64),
    /// A floating-point value.
    Float(f64),
    /// A raw string extracted verbatim.
    Text(String),
}

impl fmt::Display for RuntimeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(v) => write!(f, "{v}"),
            Self::Unsigned(v) => write!(f, "{v}"),
            Self::Address(v) => write!(f, "{v:#018x}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Text(s) => write!(f, "{s}"),
        }
    }
}

// ── UbsanReportParser ─────────────────────────────────────────────────────────

/// Stateless parser for `UBSan` textual diagnostics.
///
/// `UBSan` writes one line per violation to stderr in the form:
/// ```text
/// path/to/file.c:42:7: runtime error: <description>
/// ```
/// Optional subsequent lines provide context ("note: …", value lines, etc.).
pub struct UbsanReportParser;

impl UbsanReportParser {
    /// Maximum lines processed per `parse_all` call (dos-memory-exhaustion guard).
    const MAX_LINES: usize = 1_000_000;

    /// Parse all `UBSan` violations found in `text`.
    #[must_use]
    pub fn parse_all(text: &str) -> Vec<UbReport> {
        let lines: Vec<&str> = text.lines().take(Self::MAX_LINES).collect();
        let mut reports = Vec::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            if let Some(report) = Self::try_parse_error_line(line, &lines, i + 1) {
                // Advance past the note lines that were consumed.
                let consumed = report.notes.len();
                reports.push(report);
                i += consumed;
            }
            i += 1;
        }
        reports
    }

    /// Parse the first `UBSan` violation found in `text`.
    #[must_use]
    pub fn parse(text: &str) -> Option<UbReport> {
        Self::parse_all(text).into_iter().next()
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn try_parse_error_line(
        line: &str,
        all_lines: &[&str],
        next_idx: usize,
    ) -> Option<UbReport> {
        // UBSan format: "file:line:col: runtime error: <desc>"
        // Some builds omit "runtime error:" and emit the check name directly.
        let (loc_part, desc) = if let Some(idx) = line.find(": runtime error: ") {
            let loc = &line[..idx];
            let d = &line[idx + 17..];
            (loc.to_owned(), d.to_owned())
        } else if let Some(idx) = line.find(": error: ") {
            let loc = &line[..idx];
            let d = &line[idx + 9..];
            (loc.to_owned(), d.to_owned())
        } else {
            return None;
        };

        let location = SourceLocation::parse(&loc_part);

        // Detect kind from description text.
        let kind = Self::infer_kind(&desc);

        // Collect note lines.
        let mut notes = Vec::new();
        let mut j = next_idx;
        while j < all_lines.len() {
            let note_line = all_lines[j].trim();
            if note_line.starts_with("note: ") || note_line.starts_with("    ") {
                notes.push(note_line.to_owned());
                j += 1;
            } else {
                break;
            }
        }

        let runtime_value = Self::extract_runtime_value(&desc);

        let raw_text = {
            let mut parts = vec![line.to_owned()];
            parts.extend(notes.iter().cloned());
            parts.join("\n")
        };

        Some(UbReport { kind, location, description: desc, runtime_value, notes, raw_text })
    }

    fn infer_kind(desc: &str) -> UbKind {
        let lower = desc.to_ascii_lowercase();
        if lower.contains("signed integer overflow")
            || lower.contains("overflow: ")
            || lower.contains("overflows")
        {
            if lower.contains("unsigned") {
                UbKind::UnsignedIntegerOverflow
            } else {
                UbKind::SignedIntegerOverflow
            }
        } else if lower.contains("division by zero") || lower.contains("divide by zero") {
            UbKind::IntegerDivisionByZero
        } else if lower.contains("null pointer") || lower.contains("null-pointer") {
            UbKind::NullPointerDereference
        } else if lower.contains("index") && lower.contains("out of bound") {
            UbKind::OutOfBoundsAccess
        } else if lower.contains("shift exponent") || lower.contains("shift amount") {
            UbKind::ShiftExponent
        } else if lower.contains("not a valid value for type bool") {
            UbKind::InvalidBoolValue
        } else if lower.contains("not a valid value for type") {
            UbKind::InvalidEnumValue
        } else if lower.contains("unreachable program point") || lower.contains("__builtin_unreachable") {
            UbKind::UnreachableCode
        } else if lower.contains("pointer overflow") {
            UbKind::PointerOverflow
        } else if lower.contains("misaligned") || lower.contains("alignment") {
            UbKind::Alignment
        } else if lower.contains("float") && lower.contains("overflow") {
            UbKind::FloatCastOverflow
        } else if lower.contains("function called through pointer") {
            UbKind::FunctionTypeMismatch
        } else if lower.contains("vtable") || lower.contains("vptr") {
            UbKind::VtablePointerInvalid
        } else if lower.contains("implicit") && lower.contains("truncation") {
            UbKind::ImplicitIntegerTruncation
        } else if lower.contains("implicit") && lower.contains("sign") {
            UbKind::ImplicitIntegerSignChange
        } else {
            UbKind::Unknown(desc.split_whitespace().take(4).collect::<Vec<_>>().join(" "))
        }
    }

    fn extract_runtime_value(desc: &str) -> Option<RuntimeValue> {
        // Look for patterns like "value N", "result is N", "is N which"
        for prefix in &["value ", "result is ", " is "] {
            if let Some(idx) = desc.find(prefix) {
                let rest = &desc[idx + prefix.len()..];
                let token: String = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(',')
                    .trim_end_matches(')')
                    .to_owned();

                if token.starts_with("0x") || token.starts_with("0X") {
                    let hex = &token[2..];
                    if let Ok(v) = u64::from_str_radix(hex, 16) {
                        return Some(RuntimeValue::Address(v));
                    }
                } else if let Ok(v) = token.parse::<i128>() {
                    return Some(RuntimeValue::Integer(v));
                } else if let Ok(v) = token.parse::<u128>() {
                    return Some(RuntimeValue::Unsigned(v));
                } else if let Ok(v) = token.parse::<f64>() {
                    return Some(RuntimeValue::Float(v));
                } else if !token.is_empty() {
                    return Some(RuntimeValue::Text(token));
                }
            }
        }
        None
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Parse all `UBSan` violations from `text`.
///
/// Returns an empty `Vec` when no violations are found.
#[must_use]
pub fn parse_ubsan_output(text: &str) -> Vec<UbReport> {
    UbsanReportParser::parse_all(text)
}

// ── UbsanReportBatch ─────────────────────────────────────────────────────────

/// A collection of parsed `UBSan` reports with aggregate helpers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UbsanReportBatch {
    pub reports: Vec<UbReport>,
}

impl UbsanReportBatch {
    /// Build from raw text.
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        Self { reports: parse_ubsan_output(text) }
    }

    /// Number of unique violation locations.
    #[must_use]
    pub fn unique_locations(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for r in &self.reports {
            seen.insert(r.dedup_key());
        }
        seen.len()
    }

    /// Filter to only security-relevant violations.
    #[must_use]
    pub fn security_relevant(&self) -> Vec<&UbReport> {
        self.reports.iter().filter(|r| r.is_security_relevant()).collect()
    }

    /// Count violations grouped by kind canonical name.
    #[must_use]
    pub fn by_kind(&self) -> std::collections::HashMap<String, usize> {
        let mut map = std::collections::HashMap::new();
        for r in &self.reports {
            *map.entry(r.kind.to_string()).or_insert(0) += 1;
        }
        map
    }

    /// All violations from a specific source file.
    #[must_use]
    pub fn from_file<'a>(&'a self, file_pattern: &str) -> Vec<&'a UbReport> {
        self.reports
            .iter()
            .filter(|r| {
                r.location
                    .as_ref()
                    .is_some_and(|l| l.file.contains(file_pattern))
            })
            .collect()
    }

    /// Total number of violations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.reports.len()
    }

    /// True when there are no violations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const OVERFLOW: &str =
        "/src/main.c:42:10: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'";

    const NULL_DEREF: &str =
        "/src/utils.c:10:5: runtime error: null pointer dereference";

    const DIV_ZERO: &str =
        "/src/math.c:7:3: runtime error: division by zero";

    const SHIFT: &str =
        "/src/bits.c:15:8: runtime error: shift exponent 64 is too large for 64-bit type 'long'";

    const INVALID_BOOL: &str =
        "/src/flags.c:22:1: runtime error: load of value 2, which is not a valid value for type bool";

    const WITH_NOTE: &str = concat!(
        "/src/buf.c:100:3: runtime error: index 10 out of bounds for type 'int [5]'\n",
        "note: pointer points here\n",
        "    0x00 0x00 0x00 0x00\n",
    );

    #[test]
    fn test_parse_overflow() {
        let reports = parse_ubsan_output(OVERFLOW);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].kind, UbKind::SignedIntegerOverflow);
        let loc = reports[0].location.as_ref().unwrap();
        assert_eq!(loc.file, "/src/main.c");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, Some(10));
    }

    #[test]
    fn test_parse_null_deref() {
        let reports = parse_ubsan_output(NULL_DEREF);
        assert_eq!(reports[0].kind, UbKind::NullPointerDereference);
    }

    #[test]
    fn test_parse_div_zero() {
        let reports = parse_ubsan_output(DIV_ZERO);
        assert_eq!(reports[0].kind, UbKind::IntegerDivisionByZero);
    }

    #[test]
    fn test_parse_shift() {
        let reports = parse_ubsan_output(SHIFT);
        assert_eq!(reports[0].kind, UbKind::ShiftExponent);
    }

    #[test]
    fn test_parse_invalid_bool() {
        let reports = parse_ubsan_output(INVALID_BOOL);
        assert_eq!(reports[0].kind, UbKind::InvalidBoolValue);
    }

    #[test]
    fn test_parse_with_note_lines() {
        let reports = parse_ubsan_output(WITH_NOTE);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].kind, UbKind::OutOfBoundsAccess);
        assert!(!reports[0].notes.is_empty());
    }

    #[test]
    fn test_parse_multiple() {
        let text = format!("{OVERFLOW}\n{NULL_DEREF}\n{DIV_ZERO}");
        let reports = parse_ubsan_output(&text);
        assert_eq!(reports.len(), 3);
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_ubsan_output("nothing here").is_empty());
    }

    #[test]
    fn test_report_summary() {
        let reports = parse_ubsan_output(OVERFLOW);
        let s = reports[0].summary();
        assert!(s.contains("UBSan"));
        assert!(s.contains("signed-integer-overflow"));
    }

    #[test]
    fn test_report_display() {
        let reports = parse_ubsan_output(OVERFLOW);
        let s = format!("{}", reports[0]);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_dedup_key() {
        let reports = parse_ubsan_output(OVERFLOW);
        let key = reports[0].dedup_key();
        assert!(key.contains("signed-integer-overflow"));
        assert!(key.contains("/src/main.c:42"));
    }

    #[test]
    fn test_is_security_relevant() {
        let overflow_reports = parse_ubsan_output(OVERFLOW);
        assert!(overflow_reports[0].is_security_relevant());

        let unreachable = "/src/x.c:5:1: runtime error: execution reached an unreachable program point";
        let rep = parse_ubsan_output(unreachable);
        assert!(!rep.is_empty());
        assert!(!rep[0].is_security_relevant());
    }

    #[test]
    fn test_runtime_value_integer() {
        let reports = parse_ubsan_output(OVERFLOW);
        if let Some(RuntimeValue::Integer(v)) = &reports[0].runtime_value {
            assert_eq!(*v, 2_147_483_647);
        }
    }

    #[test]
    fn test_batch_from_text() {
        let text = format!("{OVERFLOW}\n{NULL_DEREF}\n{DIV_ZERO}");
        let batch = UbsanReportBatch::from_text(&text);
        assert_eq!(batch.len(), 3);
        assert!(!batch.is_empty());
    }

    #[test]
    fn test_batch_unique_locations() {
        let text = format!("{OVERFLOW}\n{NULL_DEREF}\n{DIV_ZERO}");
        let batch = UbsanReportBatch::from_text(&text);
        assert_eq!(batch.unique_locations(), 3);
    }

    #[test]
    fn test_batch_security_relevant() {
        let text = format!("{OVERFLOW}\n{NULL_DEREF}\n{DIV_ZERO}");
        let batch = UbsanReportBatch::from_text(&text);
        let sec = batch.security_relevant();
        assert!(!sec.is_empty());
    }

    #[test]
    fn test_batch_by_kind() {
        let text = format!("{OVERFLOW}\n{NULL_DEREF}\n{DIV_ZERO}");
        let batch = UbsanReportBatch::from_text(&text);
        let by_kind = batch.by_kind();
        assert_eq!(*by_kind.get("signed-integer-overflow").unwrap(), 1);
    }

    #[test]
    fn test_batch_from_file() {
        let text = format!("{OVERFLOW}\n{NULL_DEREF}\n{DIV_ZERO}");
        let batch = UbsanReportBatch::from_text(&text);
        let main = batch.from_file("main.c");
        assert_eq!(main.len(), 1);
    }

    #[test]
    fn test_ubkind_canonical() {
        assert_eq!(UbKind::SignedIntegerOverflow.canonical_name(), "signed-integer-overflow");
        assert_eq!(UbKind::IntegerDivisionByZero.canonical_name(), "divide-by-zero");
    }

    #[test]
    fn test_ubkind_display() {
        assert_eq!(UbKind::NullPointerDereference.to_string(), "null-dereference");
    }

    #[test]
    fn test_ubkind_from_check_name() {
        assert_eq!(
            UbKind::from_check_name("signed-integer-overflow"),
            UbKind::SignedIntegerOverflow
        );
        assert_eq!(
            UbKind::from_check_name("divide-by-zero"),
            UbKind::IntegerDivisionByZero
        );
    }

    #[test]
    fn test_source_location_parse() {
        let loc = SourceLocation::parse("/foo/bar.c:42:7").unwrap();
        assert_eq!(loc.file, "/foo/bar.c");
        assert_eq!(loc.line, 42);
        assert_eq!(loc.column, Some(7));
    }

    #[test]
    fn test_source_location_display() {
        let loc = SourceLocation { file: "a.c".into(), line: 10, column: Some(3) };
        assert_eq!(loc.to_string(), "a.c:10:3");
    }

    #[test]
    fn test_runtime_value_display() {
        assert_eq!(RuntimeValue::Integer(-5).to_string(), "-5");
        assert_eq!(RuntimeValue::Unsigned(42).to_string(), "42");
        assert_eq!(RuntimeValue::Text("foo".into()).to_string(), "foo");
    }
}
