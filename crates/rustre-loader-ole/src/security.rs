//! OLE2 security scanning — threat detection for malicious Office documents.

use super::OleFile;

// ── Threat types ──────────────────────────────────────────────────────────────

/// A specific OLE/Office threat category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OleThreat {
    /// VBA macros are present.
    VbaMacros,
    /// Auto-executing macros (`Auto_Open`, `Document_Open`, etc.).
    AutoExecMacro,
    /// Embedded OLE object.
    EmbeddedOleObject,
    /// `Ole10Native` payload (binary embedded executable).
    Ole10NativePayload,
    /// A stream with a suspicious name.
    SuspiciousStream(String),
    /// `PowerShell` invocation found in VBA source.
    PowerShellInVba,
    /// Shell command invocation in VBA source.
    ShellCommandInVba,
    /// External OLE link (server/source outside the document).
    ExternalOleLink,
}

impl OleThreat {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::VbaMacros => "VbaMacros",
            Self::AutoExecMacro => "AutoExecMacro",
            Self::EmbeddedOleObject => "EmbeddedOleObject",
            Self::Ole10NativePayload => "Ole10NativePayload",
            Self::SuspiciousStream(_) => "SuspiciousStream",
            Self::PowerShellInVba => "PowerShellInVba",
            Self::ShellCommandInVba => "ShellCommandInVba",
            Self::ExternalOleLink => "ExternalOleLink",
        }
    }
}

// ── Threat level ──────────────────────────────────────────────────────────────

/// Severity of a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    /// Informational.
    Low,
    /// Possibly suspicious.
    Medium,
    /// Likely malicious.
    High,
    /// Almost certainly malicious.
    Critical,
}

impl ThreatLevel {
    /// Numeric weight for risk score calculation.
    #[must_use]
    pub const fn weight(self) -> u8 {
        match self {
            Self::Low => 2,
            Self::Medium => 8,
            Self::High => 20,
            Self::Critical => 40,
        }
    }
}

// ── OleThreatEntry ────────────────────────────────────────────────────────────

/// A single detected threat instance.
#[derive(Debug, Clone)]
pub struct OleThreatEntry {
    /// The threat category.
    pub threat: OleThreat,
    /// Severity.
    pub level: ThreatLevel,
    /// Human-readable description.
    pub description: String,
    /// Name of the OLE stream involved, if applicable.
    pub stream_name: Option<String>,
}

// ── OleSecurityReport ─────────────────────────────────────────────────────────

/// Aggregated security report for an OLE2 file.
#[derive(Debug, Clone)]
pub struct OleSecurityReport {
    /// Individual threat entries.
    pub threats: Vec<OleThreatEntry>,
    /// Overall risk score 0–100.
    pub risk_score: u8,
    /// Whether VBA macros were found.
    pub has_macros: bool,
    /// Whether embedded OLE objects were found.
    pub has_embedded_objects: bool,
}

// ── Suspicious stream name list ───────────────────────────────────────────────

/// Stream/storage names associated with known attack vectors.
static SUSPICIOUS_NAMES: &[(&str, ThreatLevel, &str)] = &[
    (
        "CVE",
        ThreatLevel::Critical,
        "Stream name contains CVE reference",
    ),
    (
        "exploit",
        ThreatLevel::Critical,
        "Stream name contains 'exploit'",
    ),
    (
        "shellcode",
        ThreatLevel::Critical,
        "Stream name contains 'shellcode'",
    ),
    (
        "payload",
        ThreatLevel::High,
        "Stream name contains 'payload'",
    ),
    (
        "dropped",
        ThreatLevel::High,
        "Stream name contains 'dropped'",
    ),
    (
        "download",
        ThreatLevel::High,
        "Stream name contains 'download'",
    ),
    ("http", ThreatLevel::Medium, "Stream name contains 'http'"),
    ("cmd", ThreatLevel::Medium, "Stream name contains 'cmd'"),
    (
        "powershell",
        ThreatLevel::High,
        "Stream name contains 'powershell'",
    ),
    (
        "base64",
        ThreatLevel::Medium,
        "Stream name contains 'base64'",
    ),
];

// ── Public scanning API ───────────────────────────────────────────────────────

/// Scan raw OLE bytes for threats without full file parsing.
///
/// This function parses the OLE header and directory, then delegates to
/// the structured scan functions.
#[must_use]
pub fn scan_ole(data: &[u8]) -> OleSecurityReport {
    match OleFile::parse(data) {
        Ok(ole) => {
            let mut threats = Vec::new();
            threats.extend(scan_vba_streams(&ole));
            threats.extend(scan_embedded_objects(&ole));
            threats.extend(scan_stream_names(&ole));
            let has_macros = threats
                .iter()
                .any(|t| matches!(t.threat, OleThreat::VbaMacros | OleThreat::AutoExecMacro));
            let has_embedded_objects = threats.iter().any(|t| {
                matches!(
                    t.threat,
                    OleThreat::EmbeddedOleObject | OleThreat::Ole10NativePayload
                )
            });
            let risk_score = calculate_risk_score(&threats);
            OleSecurityReport {
                threats,
                risk_score,
                has_macros,
                has_embedded_objects,
            }
        }
        Err(_) => OleSecurityReport {
            threats: vec![],
            risk_score: 0,
            has_macros: false,
            has_embedded_objects: false,
        },
    }
}

/// Scan for VBA-related streams.
#[must_use]
pub fn scan_vba_streams(ole: &OleFile) -> Vec<OleThreatEntry> {
    let mut entries = Vec::new();
    for entry in &ole.directory {
        if entry.name == "VBA"
            || entry.name == "Macros"
            || entry.name == "_VBA_PROJECT_CUR"
            || entry.name == "VBAProject"
        {
            entries.push(OleThreatEntry {
                threat: OleThreat::VbaMacros,
                level: ThreatLevel::High,
                description: format!("VBA macros storage found: '{}'", entry.name),
                stream_name: Some(entry.name.clone()),
            });
        }
        // Check for auto-exec streams by name
        let lower = entry.name.to_lowercase();
        if lower.contains("autoopen")
            || lower.contains("auto_open")
            || lower.contains("document_open")
            || lower.contains("workbook_open")
            || lower.contains("autoexec")
        {
            entries.push(OleThreatEntry {
                threat: OleThreat::AutoExecMacro,
                level: ThreatLevel::Critical,
                description: format!("Auto-executing macro stream: '{}'", entry.name),
                stream_name: Some(entry.name.clone()),
            });
        }
        // External OLE link detection
        if lower.contains("olelink") || lower == "\x01ole" || lower.contains("ole1link") {
            entries.push(OleThreatEntry {
                threat: OleThreat::ExternalOleLink,
                level: ThreatLevel::Medium,
                description: format!("Possible external OLE link stream: '{}'", entry.name),
                stream_name: Some(entry.name.clone()),
            });
        }
    }
    entries
}

/// Scan for embedded OLE object streams.
#[must_use]
pub fn scan_embedded_objects(ole: &OleFile) -> Vec<OleThreatEntry> {
    let mut entries = Vec::new();
    for entry in &ole.directory {
        let name = entry.name.as_str();
        if name == "ObjectPool" {
            entries.push(OleThreatEntry {
                threat: OleThreat::EmbeddedOleObject,
                level: ThreatLevel::Medium,
                description: "ObjectPool storage present — may contain embedded objects"
                    .to_string(),
                stream_name: Some(name.to_string()),
            });
        }
        if name == "\x01Ole10Native" || name == "Ole10Native" {
            entries.push(OleThreatEntry {
                threat: OleThreat::Ole10NativePayload,
                level: ThreatLevel::Critical,
                description: "Ole10Native stream — may contain a packaged executable".to_string(),
                stream_name: Some(name.to_string()),
            });
        }
    }
    entries
}

/// Scan stream names for suspicious patterns.
#[must_use]
pub fn scan_stream_names(ole: &OleFile) -> Vec<OleThreatEntry> {
    let mut entries = Vec::new();
    for entry in &ole.directory {
        let lower = entry.name.to_lowercase();
        for &(keyword, level, description) in SUSPICIOUS_NAMES {
            if lower.contains(keyword) {
                entries.push(OleThreatEntry {
                    threat: OleThreat::SuspiciousStream(entry.name.clone()),
                    level,
                    description: format!("{description}: '{}'", entry.name),
                    stream_name: Some(entry.name.clone()),
                });
                break; // One match per stream
            }
        }
    }
    entries
}

/// Calculate a risk score 0–100 from threat entries.
#[must_use]
pub fn calculate_risk_score(threats: &[OleThreatEntry]) -> u8 {
    let raw: u32 = threats.iter().map(|t| u32::from(t.level.weight())).sum();
    raw.min(100) as u8
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OleDirectoryEntry, OleFile, OleHeader};

    const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    fn make_header_bytes() -> Vec<u8> {
        let mut d = vec![0u8; 512];
        d[..8].copy_from_slice(&OLE_MAGIC);
        d[24..26].copy_from_slice(&0x003Eu16.to_le_bytes());
        d[26..28].copy_from_slice(&3u16.to_le_bytes());
        d[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        d[30..32].copy_from_slice(&9u16.to_le_bytes());
        d[32..34].copy_from_slice(&6u16.to_le_bytes());
        d[44..48].copy_from_slice(&2u32.to_le_bytes());
        d[48..52].copy_from_slice(&1u32.to_le_bytes());
        d[60..64].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        d[64..68].copy_from_slice(&0u32.to_le_bytes());
        d
    }

    fn entry(name: &str, kind: u8) -> OleDirectoryEntry {
        OleDirectoryEntry {
            name: name.to_string(),
            entry_type: kind,
            color: 1,
            child_sid: 0xFFFF_FFFF,
            left_sid: 0xFFFF_FFFF,
            right_sid: 0xFFFF_FFFF,
            start_sector: 0,
            size: 0,
            created: 0,
            modified: 0,
        }
    }

    fn make_ole(entries: Vec<OleDirectoryEntry>) -> OleFile {
        let header = OleHeader::parse(&make_header_bytes()).unwrap();
        OleFile {
            header,
            directory: entries,
        }
    }

    // ── scan_vba_streams ──────────────────────────────────────────────────────

    #[test]
    fn test_scan_vba_streams_empty() {
        let ole = make_ole(vec![entry("WordDocument", 2)]);
        assert!(scan_vba_streams(&ole).is_empty());
    }

    #[test]
    fn test_scan_vba_streams_vba_storage() {
        let ole = make_ole(vec![entry("VBA", 1)]);
        let threats = scan_vba_streams(&ole);
        assert!(!threats.is_empty());
        assert!(
            threats
                .iter()
                .any(|t| matches!(t.threat, OleThreat::VbaMacros))
        );
    }

    #[test]
    fn test_scan_vba_streams_vbaproject() {
        let ole = make_ole(vec![entry("VBAProject", 2)]);
        let threats = scan_vba_streams(&ole);
        assert!(
            threats
                .iter()
                .any(|t| matches!(t.threat, OleThreat::VbaMacros))
        );
    }

    #[test]
    fn test_scan_vba_streams_macros_storage() {
        let ole = make_ole(vec![entry("Macros", 1)]);
        let threats = scan_vba_streams(&ole);
        assert!(!threats.is_empty());
    }

    // ── scan_embedded_objects ─────────────────────────────────────────────────

    #[test]
    fn test_scan_embedded_objects_none() {
        let ole = make_ole(vec![entry("WordDocument", 2)]);
        assert!(scan_embedded_objects(&ole).is_empty());
    }

    #[test]
    fn test_scan_embedded_objects_object_pool() {
        let ole = make_ole(vec![entry("ObjectPool", 1)]);
        let threats = scan_embedded_objects(&ole);
        assert!(
            threats
                .iter()
                .any(|t| matches!(t.threat, OleThreat::EmbeddedOleObject))
        );
    }

    #[test]
    fn test_scan_embedded_objects_ole10native() {
        let ole = make_ole(vec![entry("Ole10Native", 2)]);
        let threats = scan_embedded_objects(&ole);
        assert!(
            threats
                .iter()
                .any(|t| matches!(t.threat, OleThreat::Ole10NativePayload))
        );
        assert_eq!(
            threats
                .iter()
                .find(|t| matches!(t.threat, OleThreat::Ole10NativePayload))
                .unwrap()
                .level,
            ThreatLevel::Critical
        );
    }

    // ── scan_stream_names ─────────────────────────────────────────────────────

    #[test]
    fn test_scan_stream_names_clean() {
        let ole = make_ole(vec![entry("WordDocument", 2)]);
        assert!(scan_stream_names(&ole).is_empty());
    }

    #[test]
    fn test_scan_stream_names_http() {
        let ole = make_ole(vec![entry("http_payload", 2)]);
        let threats = scan_stream_names(&ole);
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_scan_stream_names_payload() {
        let ole = make_ole(vec![entry("payload", 2)]);
        let threats = scan_stream_names(&ole);
        assert!(!threats.is_empty());
        let t = &threats[0];
        assert_eq!(t.level, ThreatLevel::High);
    }

    #[test]
    fn test_scan_stream_names_exploit() {
        let ole = make_ole(vec![entry("exploit_stream", 2)]);
        let threats = scan_stream_names(&ole);
        assert!(threats.iter().any(|t| t.level == ThreatLevel::Critical));
    }

    // ── calculate_risk_score ─────────────────────────────────────────────────

    #[test]
    fn test_risk_score_zero() {
        assert_eq!(calculate_risk_score(&[]), 0);
    }

    #[test]
    fn test_risk_score_high_threat() {
        let t = OleThreatEntry {
            threat: OleThreat::VbaMacros,
            level: ThreatLevel::High,
            description: String::new(),
            stream_name: None,
        };
        assert!(calculate_risk_score(&[t]) > 0);
    }

    #[test]
    fn test_risk_score_capped_100() {
        let threats: Vec<OleThreatEntry> = (0..10)
            .map(|_| OleThreatEntry {
                threat: OleThreat::Ole10NativePayload,
                level: ThreatLevel::Critical,
                description: String::new(),
                stream_name: None,
            })
            .collect();
        assert_eq!(calculate_risk_score(&threats), 100);
    }

    // ── scan_ole ─────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_ole_invalid_data() {
        let report = scan_ole(b"not an ole file");
        assert_eq!(report.risk_score, 0);
        assert!(!report.has_macros);
    }

    // ── OleThreat::name ──────────────────────────────────────────────────────

    #[test]
    fn test_ole_threat_name_vba() {
        assert_eq!(OleThreat::VbaMacros.name(), "VbaMacros");
    }

    #[test]
    fn test_ole_threat_name_suspicious_stream() {
        let t = OleThreat::SuspiciousStream("exploit".to_string());
        assert_eq!(t.name(), "SuspiciousStream");
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Medium);
        assert!(ThreatLevel::Medium > ThreatLevel::Low);
    }

    #[test]
    fn test_threat_level_weights() {
        assert!(ThreatLevel::Critical.weight() > ThreatLevel::High.weight());
        assert!(ThreatLevel::High.weight() > ThreatLevel::Medium.weight());
        assert!(ThreatLevel::Medium.weight() > ThreatLevel::Low.weight());
    }

    // ── OleSecurityReport ─────────────────────────────────────────────────────

    #[test]
    fn test_ole_security_report_fields() {
        let report = OleSecurityReport {
            threats: vec![],
            risk_score: 0,
            has_macros: false,
            has_embedded_objects: false,
        };
        assert!(!report.has_macros);
        assert!(!report.has_embedded_objects);
        assert_eq!(report.risk_score, 0);
    }
}
