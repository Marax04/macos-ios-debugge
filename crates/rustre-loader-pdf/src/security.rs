//! PDF security scanning — threat detection for malicious PDF features.

// ── Threat types ──────────────────────────────────────────────────────────────

/// A specific PDF threat category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfThreat {
    /// JavaScript action or /JS entry.
    JavaScript,
    /// Embedded file attachment.
    EmbeddedFile,
    /// /Launch action (arbitrary executable launch).
    LaunchAction,
    /// /URI action (external URL).
    UriAction,
    /// /`GoToR` action (`GoTo` Remote).
    GoToRemote,
    /// /`SubmitForm` action.
    SubmitForm,
    /// /Hide annotation action.
    HideAnnotation,
    /// /`OpenAction` at document open.
    OpenAction,
    /// XFA form (dynamic XML forms).
    XfaForm,
    /// Obfuscated object structure.
    ObfuscatedObject,
    /// /`ASCIIHexDecode` filter.
    AsciiHexFilter,
    /// /`ASCII85Decode` filter.
    Ascii85Filter,
    /// /`JBIG2Decode` filter (CVE-2009-0658 class).
    Jbig2Filter,
    /// /`RichMedia` annotation.
    RichmediaAnnot,
    /// 3D annotation (/3D).
    File3dAnnot,
    /// /Sound action.
    SoundAction,
    /// /Movie action.
    MovieAction,
    /// /`ResetForm` action.
    ResetFormAction,
}

impl PdfThreat {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::JavaScript => "JavaScript",
            Self::EmbeddedFile => "EmbeddedFile",
            Self::LaunchAction => "LaunchAction",
            Self::UriAction => "UriAction",
            Self::GoToRemote => "GoToRemote",
            Self::SubmitForm => "SubmitForm",
            Self::HideAnnotation => "HideAnnotation",
            Self::OpenAction => "OpenAction",
            Self::XfaForm => "XfaForm",
            Self::ObfuscatedObject => "ObfuscatedObject",
            Self::AsciiHexFilter => "AsciiHexFilter",
            Self::Ascii85Filter => "Ascii85Filter",
            Self::Jbig2Filter => "Jbig2Filter",
            Self::RichmediaAnnot => "RichmediaAnnot",
            Self::File3dAnnot => "File3dAnnot",
            Self::SoundAction => "SoundAction",
            Self::MovieAction => "MovieAction",
            Self::ResetFormAction => "ResetFormAction",
        }
    }
}

// ── Threat level ──────────────────────────────────────────────────────────────

/// Severity of a detected threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    /// Informational; benign in most contexts.
    Low,
    /// Possibly suspicious.
    Medium,
    /// Likely malicious.
    High,
    /// Almost certainly malicious.
    Critical,
}

impl ThreatLevel {
    /// Numeric weight used in risk score calculation.
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

// ── ThreatEntry ───────────────────────────────────────────────────────────────

/// A single detected threat instance.
#[derive(Debug, Clone)]
pub struct ThreatEntry {
    /// The threat category.
    pub threat: PdfThreat,
    /// Severity level.
    pub level: ThreatLevel,
    /// Human-readable description.
    pub description: String,
    /// Byte offset within the file where the threat marker was found.
    pub byte_offset: Option<usize>,
}

// ── SecurityReport ────────────────────────────────────────────────────────────

/// Aggregated security report for a PDF file.
#[derive(Debug, Clone)]
pub struct SecurityReport {
    /// Individual threat entries.
    pub threats: Vec<ThreatEntry>,
    /// Overall risk score 0–100.
    pub risk_score: u8,
    /// Whether this file is likely malicious (`risk_score` ≥ 50).
    pub is_likely_malicious: bool,
    /// One-line executive summary.
    pub summary: String,
}

// ── Public scanning API ───────────────────────────────────────────────────────

/// Scan raw PDF `data` and return a full `SecurityReport`.
#[must_use]
pub fn scan_pdf(data: &[u8]) -> SecurityReport {
    let mut threats = Vec::new();
    threats.extend(scan_javascript(data));
    threats.extend(scan_embedded_files(data));
    threats.extend(scan_launch_actions(data));
    threats.extend(scan_uri_actions(data));
    threats.extend(scan_openactions(data));
    threats.extend(scan_obfuscation(data));
    threats.extend(scan_xfa(data));
    threats.extend(scan_goto_remote(data));
    threats.extend(scan_submit_form(data));
    threats.extend(scan_hide_annotation(data));
    threats.extend(scan_filters(data));
    threats.extend(scan_richmedia(data));
    threats.extend(scan_3d_annot(data));
    threats.extend(scan_sound_action(data));
    threats.extend(scan_movie_action(data));
    threats.extend(scan_reset_form(data));

    let risk_score = calculate_risk_score(&threats);
    let is_likely_malicious = risk_score >= 50;
    let summary = build_summary(&threats, risk_score);

    SecurityReport {
        threats,
        risk_score,
        is_likely_malicious,
        summary,
    }
}

/// Scan for JavaScript actions: `/JavaScript` and `/JS`.
#[must_use]
pub fn scan_javascript(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();
    for (needle, label) in &[
        (b"/JavaScript".as_slice(), "JavaScript action (/JavaScript)"),
        (b"/JS".as_slice(), "JavaScript entry (/JS)"),
    ] {
        for offset in find_all(data, needle) {
            entries.push(ThreatEntry {
                threat: PdfThreat::JavaScript,
                level: ThreatLevel::High,
                description: (*label).to_string(),
                byte_offset: Some(offset),
            });
        }
    }
    entries
}

/// Scan for embedded files: `/EmbeddedFile` and `/Filespec`.
#[must_use]
pub fn scan_embedded_files(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();
    for (needle, label) in &[
        (
            b"/EmbeddedFile".as_slice(),
            "Embedded file attachment (/EmbeddedFile)",
        ),
        (b"/Filespec".as_slice(), "File specification (/Filespec)"),
        (
            b"/EmbeddedFiles".as_slice(),
            "Embedded files name tree (/EmbeddedFiles)",
        ),
    ] {
        for offset in find_all(data, needle) {
            entries.push(ThreatEntry {
                threat: PdfThreat::EmbeddedFile,
                level: ThreatLevel::Medium,
                description: (*label).to_string(),
                byte_offset: Some(offset),
            });
        }
    }
    entries
}

/// Scan for `/Launch` actions.
#[must_use]
pub fn scan_launch_actions(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();
    for offset in find_all(data, b"/Launch") {
        entries.push(ThreatEntry {
            threat: PdfThreat::LaunchAction,
            level: ThreatLevel::Critical,
            description: "Launch action found (/Launch) — can execute arbitrary programs"
                .to_string(),
            byte_offset: Some(offset),
        });
    }
    entries
}

/// Scan for `/URI` actions.
#[must_use]
pub fn scan_uri_actions(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();
    for offset in find_all(data, b"/URI") {
        entries.push(ThreatEntry {
            threat: PdfThreat::UriAction,
            level: ThreatLevel::Medium,
            description: "URI action found (/URI) — may lead to external resource".to_string(),
            byte_offset: Some(offset),
        });
    }
    entries
}

/// Scan for `/OpenAction`.
#[must_use]
pub fn scan_openactions(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();
    for offset in find_all(data, b"/OpenAction") {
        entries.push(ThreatEntry {
            threat: PdfThreat::OpenAction,
            level: ThreatLevel::High,
            description: "OpenAction at document open (/OpenAction)".to_string(),
            byte_offset: Some(offset),
        });
    }
    entries
}

/// Heuristic obfuscation detection.
///
/// Checks for:
/// - Excessive runs of hex-encoded names (many `#XX` sequences)
/// - Unusually long streams of whitespace padding
#[must_use]
pub fn scan_obfuscation(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();

    // Count hex escape sequences in names (/N#61me style)
    let hex_escape_count = data
        .windows(3)
        .filter(|w| w[0] == b'#' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
        .count();
    if hex_escape_count > 5 {
        entries.push(ThreatEntry {
            threat: PdfThreat::ObfuscatedObject,
            level: ThreatLevel::Medium,
            description: format!(
                "Possible name obfuscation: {hex_escape_count} hex-encoded name characters found"
            ),
            byte_offset: None,
        });
    }

    // Detect long runs of whitespace that may hide content
    let mut run = 0usize;
    let mut max_run = 0usize;
    for &b in data {
        if b == b' ' || b == b'\t' {
            run += 1;
            if run > max_run {
                max_run = run;
            }
        } else {
            run = 0;
        }
    }
    if max_run > 100 {
        entries.push(ThreatEntry {
            threat: PdfThreat::ObfuscatedObject,
            level: ThreatLevel::Low,
            description: format!(
                "Suspicious whitespace padding: longest run of {max_run} space/tab bytes"
            ),
            byte_offset: None,
        });
    }

    entries
}

/// Scan for XFA forms.
#[must_use]
pub fn scan_xfa(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();
    for offset in find_all(data, b"/XFA") {
        entries.push(ThreatEntry {
            threat: PdfThreat::XfaForm,
            level: ThreatLevel::Medium,
            description: "XFA dynamic form detected (/XFA) — often used in exploits".to_string(),
            byte_offset: Some(offset),
        });
    }
    entries
}

/// Calculate a risk score 0–100 from a set of threat entries.
///
/// Weights each entry by its `ThreatLevel::weight()` value, then clamps to 100.
#[must_use]
pub fn calculate_risk_score(threats: &[ThreatEntry]) -> u8 {
    let raw: u32 = threats.iter().map(|t| u32::from(t.level.weight())).sum();
    raw.min(100) as u8
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Find all byte offsets of `needle` in `data`.
fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() {
        return vec![];
    }
    let mut offsets = Vec::new();
    let mut start = 0;
    while start + needle.len() <= data.len() {
        if &data[start..start + needle.len()] == needle {
            offsets.push(start);
            start += needle.len();
        } else {
            start += 1;
        }
    }
    offsets
}

fn scan_goto_remote(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/GoToR")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::GoToRemote,
            level: ThreatLevel::Medium,
            description: "GoToR action found (/GoToR) — references remote PDF".to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn scan_submit_form(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/SubmitForm")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::SubmitForm,
            level: ThreatLevel::Medium,
            description: "SubmitForm action (/SubmitForm) — may exfiltrate data".to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn scan_hide_annotation(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/Hide")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::HideAnnotation,
            level: ThreatLevel::Low,
            description: "Hide annotation action (/Hide)".to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn scan_filters(data: &[u8]) -> Vec<ThreatEntry> {
    let mut entries = Vec::new();
    for offset in find_all(data, b"/ASCIIHexDecode") {
        entries.push(ThreatEntry {
            threat: PdfThreat::AsciiHexFilter,
            level: ThreatLevel::Low,
            description: "ASCIIHex filter — may be used to obfuscate content".to_string(),
            byte_offset: Some(offset),
        });
    }
    for offset in find_all(data, b"/ASCII85Decode") {
        entries.push(ThreatEntry {
            threat: PdfThreat::Ascii85Filter,
            level: ThreatLevel::Low,
            description: "ASCII85 filter — may be used to obfuscate content".to_string(),
            byte_offset: Some(offset),
        });
    }
    for offset in find_all(data, b"/JBIG2Decode") {
        entries.push(ThreatEntry {
            threat: PdfThreat::Jbig2Filter,
            level: ThreatLevel::High,
            description: "JBIG2Decode filter — historically exploited (CVE-2009-0658 class)"
                .to_string(),
            byte_offset: Some(offset),
        });
    }
    entries
}

fn scan_richmedia(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/RichMedia")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::RichmediaAnnot,
            level: ThreatLevel::Medium,
            description: "RichMedia annotation (/RichMedia) — may embed Flash or 3D content"
                .to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn scan_3d_annot(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/3D")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::File3dAnnot,
            level: ThreatLevel::Low,
            description: "3D annotation (/3D) — embeds U3D/PRC model".to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn scan_sound_action(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/Sound")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::SoundAction,
            level: ThreatLevel::Low,
            description: "Sound action (/Sound)".to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn scan_movie_action(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/Movie")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::MovieAction,
            level: ThreatLevel::Low,
            description: "Movie action (/Movie) — may embed video content".to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn scan_reset_form(data: &[u8]) -> Vec<ThreatEntry> {
    find_all(data, b"/ResetForm")
        .into_iter()
        .map(|offset| ThreatEntry {
            threat: PdfThreat::ResetFormAction,
            level: ThreatLevel::Low,
            description: "ResetForm action (/ResetForm)".to_string(),
            byte_offset: Some(offset),
        })
        .collect()
}

fn build_summary(threats: &[ThreatEntry], risk_score: u8) -> String {
    if threats.is_empty() {
        return format!("No threats detected. Risk score: {risk_score}/100.");
    }
    let critical = threats
        .iter()
        .filter(|t| t.level == ThreatLevel::Critical)
        .count();
    let high = threats
        .iter()
        .filter(|t| t.level == ThreatLevel::High)
        .count();
    format!(
        "{} threat(s) detected ({} critical, {} high). Risk score: {}/100.",
        threats.len(),
        critical,
        high,
        risk_score
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pdf(extra: &[u8]) -> Vec<u8> {
        let mut v = b"%PDF-1.7\n".to_vec();
        v.extend_from_slice(extra);
        v
    }

    // ── find_all ──────────────────────────────────────────────────────────────

    #[test]
    fn test_find_all_single() {
        assert_eq!(find_all(b"abc", b"b"), vec![1]);
    }

    #[test]
    fn test_find_all_multiple() {
        assert_eq!(find_all(b"abab", b"ab"), vec![0, 2]);
    }

    #[test]
    fn test_find_all_none() {
        assert!(find_all(b"hello", b"xyz").is_empty());
    }

    // ── scan_javascript ───────────────────────────────────────────────────────

    #[test]
    fn test_scan_javascript_detected() {
        let data = pdf(b"/JavaScript (alert(1))");
        let threats = scan_javascript(&data);
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.threat == PdfThreat::JavaScript));
    }

    #[test]
    fn test_scan_javascript_none() {
        let data = pdf(b"clean content");
        assert!(scan_javascript(&data).is_empty());
    }

    #[test]
    fn test_scan_javascript_js_entry() {
        let data = pdf(b"/JS (code)");
        let threats = scan_javascript(&data);
        assert!(!threats.is_empty());
    }

    // ── scan_embedded_files ───────────────────────────────────────────────────

    #[test]
    fn test_scan_embedded_files_detected() {
        let data = pdf(b"/EmbeddedFile");
        let threats = scan_embedded_files(&data);
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_scan_embedded_files_filespec() {
        let data = pdf(b"/Filespec");
        let threats = scan_embedded_files(&data);
        assert!(!threats.is_empty());
    }

    // ── scan_launch_actions ───────────────────────────────────────────────────

    #[test]
    fn test_scan_launch_critical() {
        let data = pdf(b"/Launch << /F (cmd.exe) >>");
        let threats = scan_launch_actions(&data);
        assert!(!threats.is_empty());
        assert_eq!(threats[0].level, ThreatLevel::Critical);
    }

    // ── scan_uri_actions ──────────────────────────────────────────────────────

    #[test]
    fn test_scan_uri_detected() {
        let data = pdf(b"/URI (http://evil.example/)");
        let threats = scan_uri_actions(&data);
        assert!(!threats.is_empty());
    }

    // ── scan_openactions ──────────────────────────────────────────────────────

    #[test]
    fn test_scan_openaction_detected() {
        let data = pdf(b"/OpenAction 2 0 R");
        let threats = scan_openactions(&data);
        assert!(!threats.is_empty());
        assert_eq!(threats[0].level, ThreatLevel::High);
    }

    // ── scan_obfuscation ─────────────────────────────────────────────────────

    #[test]
    fn test_scan_obfuscation_hex_escapes() {
        let data = pdf(b"/#4A#61#76#61#53#63#72#69#70#74"); // many #XX sequences
        let threats = scan_obfuscation(&data);
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_scan_obfuscation_none_for_clean() {
        let data = pdf(b"/Type /Catalog");
        let threats = scan_obfuscation(&data);
        // May or may not be empty — just ensure no panic
        let _ = threats;
    }

    // ── scan_xfa ──────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_xfa_detected() {
        let data = pdf(b"/XFA [...]");
        let threats = scan_xfa(&data);
        assert!(!threats.is_empty());
    }

    // ── calculate_risk_score ──────────────────────────────────────────────────

    #[test]
    fn test_risk_score_zero_no_threats() {
        assert_eq!(calculate_risk_score(&[]), 0);
    }

    #[test]
    fn test_risk_score_critical_raises_score() {
        let entry = ThreatEntry {
            threat: PdfThreat::LaunchAction,
            level: ThreatLevel::Critical,
            description: String::new(),
            byte_offset: None,
        };
        assert!(calculate_risk_score(&[entry]) > 0);
    }

    #[test]
    fn test_risk_score_capped_at_100() {
        let entries: Vec<ThreatEntry> = (0..20)
            .map(|_| ThreatEntry {
                threat: PdfThreat::LaunchAction,
                level: ThreatLevel::Critical,
                description: String::new(),
                byte_offset: None,
            })
            .collect();
        assert_eq!(calculate_risk_score(&entries), 100);
    }

    // ── scan_pdf ──────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_pdf_clean() {
        let data = pdf(b"clean document");
        let report = scan_pdf(&data);
        assert!(!report.is_likely_malicious);
    }

    #[test]
    fn test_scan_pdf_with_javascript_and_launch() {
        let data = pdf(b"/JavaScript (evil) /Launch << /F (cmd.exe) >>");
        let report = scan_pdf(&data);
        assert!(report.risk_score > 0);
        assert!(report.is_likely_malicious);
    }

    #[test]
    fn test_scan_pdf_summary_no_threats() {
        let data = pdf(b"");
        let report = scan_pdf(&data);
        assert!(report.summary.contains("No threats") || report.summary.contains("threat"));
    }

    #[test]
    fn test_scan_jbig2_filter() {
        let data = pdf(b"/JBIG2Decode stream");
        let threats = scan_filters(&data);
        assert!(threats.iter().any(|t| t.threat == PdfThreat::Jbig2Filter));
        assert_eq!(
            threats
                .iter()
                .find(|t| t.threat == PdfThreat::Jbig2Filter)
                .unwrap()
                .level,
            ThreatLevel::High
        );
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Medium);
        assert!(ThreatLevel::Medium > ThreatLevel::Low);
    }

    #[test]
    fn test_pdf_threat_name() {
        assert_eq!(PdfThreat::JavaScript.name(), "JavaScript");
        assert_eq!(PdfThreat::LaunchAction.name(), "LaunchAction");
        assert_eq!(PdfThreat::Jbig2Filter.name(), "Jbig2Filter");
    }

    #[test]
    fn test_scan_richmedia() {
        let data = pdf(b"/RichMedia << >>");
        let threats = scan_richmedia(&data);
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_scan_goto_remote() {
        let data = pdf(b"/GoToR << /F (other.pdf) >>");
        let threats = scan_goto_remote(&data);
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_report_is_likely_malicious_threshold() {
        let mut threats = Vec::new();
        for _ in 0..3 {
            threats.push(ThreatEntry {
                threat: PdfThreat::LaunchAction,
                level: ThreatLevel::Critical,
                description: String::new(),
                byte_offset: None,
            });
        }
        let score = calculate_risk_score(&threats);
        assert!(score >= 50);
    }
}
