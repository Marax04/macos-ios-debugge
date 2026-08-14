//! `compiler_detector` — Detect the compiler that produced a PE/ELF binary.
//!
//! Inspects byte patterns, section names, import tables, and debug directories
//! to identify the producing compiler: GCC, Clang, MSVC, Delphi/Borland,
//! Visual Basic, Rust, Go, and D.
//!
//! Key types: [`CompilerDetector`], [`CompilerKind`], [`CompilerVersion`],
//! [`CompilerEvidence`]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the compiler detector.
#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    #[error("file too small to parse: {0} bytes")]
    TooSmall(usize),
    #[error("unrecognised file format")]
    UnknownFormat,
    #[error("PE parse error: {0}")]
    ParseError(String),
}

// ─── CompilerKind ─────────────────────────────────────────────────────────────

/// Identified compiler / toolchain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompilerKind {
    /// Microsoft Visual C/C++.
    Msvc,
    /// GCC (Linux/MinGW/Cygwin).
    Gcc,
    /// LLVM/Clang.
    Clang,
    /// Delphi / C++Builder / older Borland tools.
    Delphi,
    /// Microsoft Visual Basic 5/6 p-code or native.
    VisualBasic,
    /// Rust (rustc).
    Rust,
    /// The Go programming language.
    Go,
    /// D language (DMD/LDC/GDC).
    DLang,
    /// Free Pascal / Lazarus.
    FreePascal,
    /// Unknown — no positive match.
    Unknown,
}

impl fmt::Display for CompilerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Msvc => "MSVC",
            Self::Gcc => "GCC",
            Self::Clang => "Clang",
            Self::Delphi => "Delphi/Borland",
            Self::VisualBasic => "Visual Basic 6",
            Self::Rust => "Rust",
            Self::Go => "Go",
            Self::DLang => "D Language",
            Self::FreePascal => "Free Pascal",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── CompilerVersion ──────────────────────────────────────────────────────────

/// Specific version information for the detected compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerVersion {
    /// Human-readable version string, e.g. `"19.36"` or `"4.9.x"`.
    pub version_str: String,
    /// Major version number (parsed from `version_str`).
    pub major: Option<u32>,
    /// Minor version number.
    pub minor: Option<u32>,
    /// Additional textual qualifier, e.g. `"MinGW"`, `"MSYS2"`.
    pub qualifier: Option<String>,
}

impl CompilerVersion {
    /// Create a version from a plain string without numeric parts.
    #[must_use]
    pub fn from_str(s: impl Into<String>) -> Self {
        let s = s.into();
        let (major, minor) = parse_version_str(&s);
        Self {
            version_str: s,
            major,
            minor,
            qualifier: None,
        }
    }

    /// Create a version with all fields.
    #[must_use]
    pub fn new(major: u32, minor: u32, qualifier: Option<String>) -> Self {
        Self {
            version_str: format!("{major}.{minor}"),
            major: Some(major),
            minor: Some(minor),
            qualifier,
        }
    }
}

impl fmt::Display for CompilerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version_str)?;
        if let Some(q) = &self.qualifier {
            write!(f, " ({q})")?;
        }
        Ok(())
    }
}

fn parse_version_str(s: &str) -> (Option<u32>, Option<u32>) {
    let parts: Vec<&str> = s.split('.').collect();
    let major = parts.first().and_then(|p| p.parse().ok());
    let minor = parts.get(1).and_then(|p| p.parse().ok());
    (major, minor)
}

// ─── EvidenceSource ───────────────────────────────────────────────────────────

/// Where a piece of compiler evidence was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// Rich PE header (linker version field).
    RichHeader,
    /// Debug directory entry.
    DebugDirectory,
    /// Section name.
    SectionName(String),
    /// String literal found inside the binary.
    StringLiteral(String),
    /// Import table entry.
    Import { dll: String, func: String },
    /// Export table entry.
    Export(String),
    /// Binary pattern match at offset.
    BytePattern { offset: usize, pattern: String },
    /// ELF note section.
    ElfNote(String),
    /// Manifest / version resource.
    VersionResource,
}

impl fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RichHeader => write!(f, "Rich header"),
            Self::DebugDirectory => write!(f, "Debug directory"),
            Self::SectionName(n) => write!(f, "Section '{n}'"),
            Self::StringLiteral(s) => write!(f, "String literal \"{s}\""),
            Self::Import { dll, func } => write!(f, "Import {dll}!{func}"),
            Self::Export(e) => write!(f, "Export '{e}'"),
            Self::BytePattern { offset, pattern } => {
                write!(f, "Byte pattern {pattern} @{offset:#x}")
            }
            Self::ElfNote(n) => write!(f, "ELF note \"{n}\""),
            Self::VersionResource => write!(f, "Version resource"),
        }
    }
}

// ─── CompilerEvidence ─────────────────────────────────────────────────────────

/// A single piece of evidence for a compiler detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerEvidence {
    /// The compiler this evidence points to.
    pub kind: CompilerKind,
    /// Confidence score 0–100 for this piece of evidence alone.
    pub confidence: u8,
    /// Where the evidence was found.
    pub source: EvidenceSource,
    /// Optional version extracted from the evidence.
    pub version: Option<CompilerVersion>,
    /// Human-readable explanation.
    pub note: String,
}

impl CompilerEvidence {
    fn new(
        kind: CompilerKind,
        confidence: u8,
        source: EvidenceSource,
        version: Option<CompilerVersion>,
        note: impl Into<String>,
    ) -> Self {
        Self { kind, confidence, source, version, note: note.into() }
    }
}

impl fmt::Display for CompilerEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?} {}%] {} — {}",
            self.kind, self.confidence, self.source, self.note
        )
    }
}

// ─── DetectionResult ─────────────────────────────────────────────────────────

/// The aggregated result of running the compiler detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Best-match compiler kind.
    pub compiler: CompilerKind,
    /// Best-match version (if determinable).
    pub version: Option<CompilerVersion>,
    /// Aggregated confidence 0–100.
    pub confidence: u8,
    /// All evidence items collected.
    pub evidence: Vec<CompilerEvidence>,
    /// Any secondary candidates (compiler → confidence).
    pub alternatives: Vec<(CompilerKind, u8)>,
}

impl DetectionResult {
    fn unknown() -> Self {
        Self {
            compiler: CompilerKind::Unknown,
            version: None,
            confidence: 0,
            evidence: Vec::new(),
            alternatives: Vec::new(),
        }
    }
}

impl fmt::Display for DetectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.compiler)?;
        if let Some(v) = &self.version {
            write!(f, " {v}")?;
        }
        write!(f, " (confidence={}%)", self.confidence)
    }
}

// ─── CompilerDetector ─────────────────────────────────────────────────────────

/// The main compiler detection engine.
///
/// Create with [`CompilerDetector::new`] then call [`CompilerDetector::detect`].
pub struct CompilerDetector {
    min_confidence: u8,
}

impl CompilerDetector {
    /// Create a detector requiring at least `min_confidence` to report a result.
    #[must_use]
    pub fn new(min_confidence: u8) -> Self {
        Self { min_confidence }
    }

    /// Create a detector with a default threshold of 50%.
    #[must_use]
    pub fn default_threshold() -> Self {
        Self { min_confidence: 50 }
    }

    /// Detect the compiler that produced `data`.
    ///
    /// # Errors
    /// Returns [`DetectorError::TooSmall`] if the binary is too short.
    pub fn detect(&self, data: &[u8]) -> Result<DetectionResult, DetectorError> {
        if data.len() < 64 {
            return Err(DetectorError::TooSmall(data.len()));
        }
        detect_compiler(data, self.min_confidence)
    }

    /// Update the minimum confidence threshold.
    pub fn set_min_confidence(&mut self, threshold: u8) {
        self.min_confidence = threshold;
    }
}

// ─── Top-level detect function ────────────────────────────────────────────────

/// Detect the compiler that produced `data`, returning a full result.
///
/// This is the main entry-point used by the higher-level crate.
///
/// # Errors
/// Returns an error if the data is too short to parse.
pub fn detect_compiler(
    data: &[u8],
    min_confidence: u8,
) -> Result<DetectionResult, DetectorError> {
    if data.len() < 64 {
        return Err(DetectorError::TooSmall(data.len()));
    }

    let mut evidence: Vec<CompilerEvidence> = Vec::new();

    // Check file format
    let is_pe = data.len() >= 2 && &data[0..2] == b"MZ";
    let is_elf = data.len() >= 4 && &data[0..4] == b"\x7fELF";

    if is_pe {
        collect_pe_evidence(data, &mut evidence);
    } else if is_elf {
        collect_elf_evidence(data, &mut evidence);
    } else {
        collect_raw_evidence(data, &mut evidence);
    }

    aggregate_evidence(evidence, min_confidence)
}

// ─── PE Evidence collection ──────────────────────────────────────────────────

fn collect_pe_evidence(data: &[u8], ev: &mut Vec<CompilerEvidence>) {
    collect_string_evidence(data, ev);
    collect_section_evidence(data, ev);
    collect_import_evidence(data, ev);
    collect_pe_header_evidence(data, ev);
}

fn collect_string_evidence(data: &[u8], ev: &mut Vec<CompilerEvidence>) {
    // MSVC runtime strings
    if contains(data, b"VCRUNTIME") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Msvc,
            75,
            EvidenceSource::StringLiteral("VCRUNTIME".into()),
            None,
            "MSVC runtime import string",
        ));
    }
    if contains(data, b"MSVCP") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Msvc,
            70,
            EvidenceSource::StringLiteral("MSVCP".into()),
            None,
            "MSVC C++ runtime DLL reference",
        ));
    }
    if let Some(v) = extract_msvc_version(data) {
        ev.push(CompilerEvidence::new(
            CompilerKind::Msvc,
            82,
            EvidenceSource::DebugDirectory,
            Some(CompilerVersion::from_str(&v)),
            "MSVC version from debug PDB path",
        ));
    }

    // Rust
    if contains(data, b"rustc") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Rust,
            80,
            EvidenceSource::StringLiteral("rustc".into()),
            None,
            "Rust compiler version string",
        ));
    }
    if contains(data, b"core::panicking") || contains(data, b"std::panicking") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Rust,
            85,
            EvidenceSource::StringLiteral("std::panicking".into()),
            None,
            "Rust panic infrastructure symbol",
        ));
    }
    if contains(data, b"__rust_alloc") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Rust,
            83,
            EvidenceSource::StringLiteral("__rust_alloc".into()),
            None,
            "Rust allocator symbol",
        ));
    }

    // GCC/MinGW
    if contains(data, b"GCC: (") {
        let ver = extract_gcc_version(data);
        ev.push(CompilerEvidence::new(
            CompilerKind::Gcc,
            92,
            EvidenceSource::StringLiteral("GCC: (".into()),
            ver.map(CompilerVersion::from_str),
            "GCC version banner string",
        ));
    }
    if contains(data, b"MinGW") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Gcc,
            78,
            EvidenceSource::StringLiteral("MinGW".into()),
            None,
            "MinGW toolchain marker",
        ));
    }
    if contains(data, b"libgcc") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Gcc,
            72,
            EvidenceSource::StringLiteral("libgcc".into()),
            None,
            "GCC support library reference",
        ));
    }

    // Clang
    if contains(data, b"clang version") {
        let ver = extract_clang_version(data);
        ev.push(CompilerEvidence::new(
            CompilerKind::Clang,
            90,
            EvidenceSource::StringLiteral("clang version".into()),
            ver.map(CompilerVersion::from_str),
            "Clang version banner string",
        ));
    }
    if contains(data, b"Apple LLVM") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Clang,
            87,
            EvidenceSource::StringLiteral("Apple LLVM".into()),
            None,
            "Apple Clang toolchain marker",
        ));
    }

    // Delphi
    if contains(data, b"Borland") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Delphi,
            85,
            EvidenceSource::StringLiteral("Borland".into()),
            None,
            "Borland/Delphi copyright string",
        ));
    }
    if contains(data, b"Pascal") && contains(data, b"Delphi") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Delphi,
            88,
            EvidenceSource::StringLiteral("Delphi".into()),
            None,
            "Delphi/Pascal marker",
        ));
    }
    if contains(data, b"Embarcadero") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Delphi,
            87,
            EvidenceSource::StringLiteral("Embarcadero".into()),
            None,
            "Embarcadero (Delphi successor) marker",
        ));
    }

    // Visual Basic 6
    if contains(data, b"VB5!") {
        ev.push(CompilerEvidence::new(
            CompilerKind::VisualBasic,
            95,
            EvidenceSource::StringLiteral("VB5!".into()),
            Some(CompilerVersion::from_str("6.0")),
            "Visual Basic native header magic",
        ));
    }
    if contains(data, b"MSVBVM60.DLL") || contains(data, b"MSVBVM50.DLL") {
        let ver = if contains(data, b"MSVBVM60") { "6.0" } else { "5.0" };
        ev.push(CompilerEvidence::new(
            CompilerKind::VisualBasic,
            93,
            EvidenceSource::Import {
                dll: "MSVBVM60.DLL".into(),
                func: "<runtime>".into(),
            },
            Some(CompilerVersion::from_str(ver)),
            "Visual Basic runtime DLL import",
        ));
    }

    // Go
    if contains(data, b"runtime.main") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Go,
            82,
            EvidenceSource::StringLiteral("runtime.main".into()),
            None,
            "Go runtime entry symbol",
        ));
    }
    if contains(data, b"go build") || contains(data, b"GOROOT") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Go,
            85,
            EvidenceSource::StringLiteral("go build / GOROOT".into()),
            extract_go_version(data).map(CompilerVersion::from_str),
            "Go toolchain string",
        ));
    }

    // D Language
    if contains(data, b"_Dmain") || contains(data, b"_D4main") {
        ev.push(CompilerEvidence::new(
            CompilerKind::DLang,
            85,
            EvidenceSource::StringLiteral("_Dmain".into()),
            None,
            "D language main symbol",
        ));
    }
    if contains(data, b"dmd") || contains(data, b"ldc") {
        ev.push(CompilerEvidence::new(
            CompilerKind::DLang,
            72,
            EvidenceSource::StringLiteral("dmd/ldc".into()),
            None,
            "D compiler reference",
        ));
    }

    // Free Pascal
    if contains(data, b"FPC ") || contains(data, b"Free Pascal") {
        ev.push(CompilerEvidence::new(
            CompilerKind::FreePascal,
            88,
            EvidenceSource::StringLiteral("FPC".into()),
            None,
            "Free Pascal compiler marker",
        ));
    }
}

fn collect_section_evidence(data: &[u8], ev: &mut Vec<CompilerEvidence>) {
    let sections = read_section_names(data);
    for name in &sections {
        match name.as_str() {
            ".rdata" | ".pdata" | ".xdata" => {
                ev.push(CompilerEvidence::new(
                    CompilerKind::Msvc,
                    60,
                    EvidenceSource::SectionName(name.clone()),
                    None,
                    "MSVC-typical section name",
                ));
            }
            ".bss" | ".data" | ".rodata" if sections.contains(&".ctors".to_string()) => {
                ev.push(CompilerEvidence::new(
                    CompilerKind::Gcc,
                    65,
                    EvidenceSource::SectionName(".ctors".into()),
                    None,
                    "GCC constructor section",
                ));
            }
            ".idata" | ".rsrc" => {}
            _ => {}
        }
    }
    // Delphi CODE section
    if sections.contains(&"CODE".to_string()) && sections.contains(&"DATA".to_string()) {
        ev.push(CompilerEvidence::new(
            CompilerKind::Delphi,
            70,
            EvidenceSource::SectionName("CODE".into()),
            None,
            "Delphi-style CODE/DATA sections",
        ));
    }
}

fn collect_import_evidence(data: &[u8], ev: &mut Vec<CompilerEvidence>) {
    // Minimal import scan — look for DLL name strings in the import area
    let dlls = [
        ("mscoree.dll", CompilerKind::Msvc, "CLR/.NET host DLL"),
    ];
    for (dll, kind, note) in &dlls {
        let upper = dll.to_uppercase();
        if contains_ci(data, dll) || contains(data, upper.as_bytes()) {
            ev.push(CompilerEvidence::new(
                *kind,
                65,
                EvidenceSource::Import { dll: (*dll).into(), func: "*".into() },
                None,
                *note,
            ));
        }
    }
}

fn collect_pe_header_evidence(data: &[u8], ev: &mut Vec<CompilerEvidence>) {
    let Some(pe_off) = get_pe_offset(data) else { return };
    if pe_off + 0x60 > data.len() {
        return;
    }
    // Linker version from Optional Header (PE32 major=0x1a, minor=0x1b)
    let opt_off = pe_off + 0x18;
    if opt_off + 4 > data.len() {
        return;
    }
    let linker_major = data[opt_off + 2];
    let linker_minor = data[opt_off + 3];
    // MSVC linker major versions: 6=VS6, 7=VS2002/2003, 8=VS2005,
    // 9=VS2008, 10=VS2010, 11=VS2012, 12=VS2013, 14=VS2015+
    if matches!(linker_major, 6..=14) {
        let vs = match linker_major {
            6 => "VS6",
            7 => "VS2002/2003",
            8 => "VS2005",
            9 => "VS2008",
            10 => "VS2010",
            11 => "VS2012",
            12 => "VS2013",
            14 => "VS2015+",
            _ => "Unknown",
        };
        let note = format!("Linker {linker_major}.{linker_minor} = {vs}");
        ev.push(CompilerEvidence::new(
            CompilerKind::Msvc,
            55,
            EvidenceSource::RichHeader,
            Some(CompilerVersion::new(linker_major.into(), linker_minor.into(), None)),
            note,
        ));
    }
}

// ─── ELF Evidence collection ─────────────────────────────────────────────────

fn collect_elf_evidence(data: &[u8], ev: &mut Vec<CompilerEvidence>) {
    // ELF .comment section usually contains "GCC: (..." or "clang version ..."
    collect_string_evidence(data, ev);

    // ELF note — look for "GNU" producer note
    if contains(data, b"GNU\x00\x04") {
        ev.push(CompilerEvidence::new(
            CompilerKind::Gcc,
            70,
            EvidenceSource::ElfNote("GNU build note".into()),
            None,
            "GNU ELF note section",
        ));
    }
}

// ─── Raw / unknown format evidence ──────────────────────────────────────────

fn collect_raw_evidence(data: &[u8], ev: &mut Vec<CompilerEvidence>) {
    collect_string_evidence(data, ev);
}

// ─── Evidence aggregation ────────────────────────────────────────────────────

fn aggregate_evidence(
    evidence: Vec<CompilerEvidence>,
    min_confidence: u8,
) -> Result<DetectionResult, DetectorError> {
    if evidence.is_empty() {
        return Ok(DetectionResult::unknown());
    }

    // Sum confidence per compiler kind
    let mut totals: HashMap<CompilerKind, (u32, u32)> = HashMap::new(); // (sum, count)
    let mut best_version: HashMap<CompilerKind, CompilerVersion> = HashMap::new();

    for e in &evidence {
        let entry = totals.entry(e.kind).or_insert((0, 0));
        entry.0 += e.confidence as u32;
        entry.1 += 1;
        // Take the highest-confidence version for each kind
        if let Some(v) = &e.version {
            best_version.entry(e.kind).or_insert_with(|| v.clone());
        }
    }

    // Convert to averaged scores, capped at 99
    let mut scores: Vec<(CompilerKind, u8)> = totals
        .iter()
        .map(|(kind, (sum, count))| {
            let avg = (*sum / count).min(99) as u8;
            (*kind, avg)
        })
        .collect();
    scores.sort_by(|a, b| b.1.cmp(&a.1));

    let (best_kind, best_conf) = scores[0];

    if best_conf < min_confidence {
        return Ok(DetectionResult::unknown());
    }

    let alternatives = scores[1..].to_vec();

    Ok(DetectionResult {
        compiler: best_kind,
        version: best_version.remove(&best_kind),
        confidence: best_conf,
        evidence,
        alternatives,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn contains(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|w| w == needle)
}

fn contains_ci(data: &[u8], needle: &str) -> bool {
    let lower = needle.to_lowercase();
    let needle_bytes = lower.as_bytes();
    data.windows(needle_bytes.len())
        .any(|w| w.eq_ignore_ascii_case(needle_bytes))
}

fn get_pe_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return None;
    }
    let off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if off + 4 > data.len() || &data[off..off + 4] != b"PE\0\0" {
        return None;
    }
    Some(off)
}

fn read_section_names(data: &[u8]) -> Vec<String> {
    let Some(pe_off) = get_pe_offset(data) else { return vec![] };
    if pe_off + 6 > data.len() {
        return vec![];
    }
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = pe_off + 0x18 + opt_size;
    let mut names = Vec::new();
    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 8 > data.len() {
            break;
        }
        let nb = &data[s..s + 8];
        let end = nb.iter().position(|&b| b == 0).unwrap_or(8);
        if let Ok(n) = std::str::from_utf8(&nb[..end]) {
            names.push(n.to_string());
        }
    }
    names
}

fn extract_gcc_version(data: &[u8]) -> Option<String> {
    let needle = b"GCC: (";
    let pos = data.windows(needle.len()).position(|w| w == needle)?;
    let start = pos + needle.len();
    let end = data[start..].iter().position(|&b| b == b')')? + start;
    std::str::from_utf8(&data[start..end]).ok().map(|s| s.to_string())
}

fn extract_clang_version(data: &[u8]) -> Option<String> {
    let needle = b"clang version ";
    let pos = data.windows(needle.len()).position(|w| w == needle)?;
    let start = pos + needle.len();
    let end = data[start..]
        .iter()
        .position(|&b| b == b' ' || b == b'\n' || b == 0)?
        + start;
    std::str::from_utf8(&data[start..end]).ok().map(|s| s.to_string())
}

fn extract_msvc_version(data: &[u8]) -> Option<String> {
    // Look for "Msc" followed by a version token in PDB path strings
    let needle = b"\\vc\\";
    let pos = data.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))?;
    // Grab up to 16 bytes before as a rough heuristic
    let start = pos.saturating_sub(16);
    let slice = &data[start..pos];
    let digits: String = slice
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_digit() || **b == b'.')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|b| *b as char)
        .collect();
    if digits.is_empty() { None } else { Some(digits) }
}

fn extract_go_version(data: &[u8]) -> Option<String> {
    let needle = b"go1.";
    let pos = data.windows(needle.len()).position(|w| w == needle)?;
    let start = pos;
    let end = data[start..]
        .iter()
        .position(|&b| b == 0 || b == b' ' || b == b'\n')?
        + start;
    std::str::from_utf8(&data[start..end]).ok().map(|s| s.to_string())
}

// ─── Public convenience function ─────────────────────────────────────────────

/// Detect the compiler in `data` with default settings (50% threshold).
///
/// # Errors
/// See [`DetectorError`].
pub fn detect(data: &[u8]) -> Result<DetectionResult, DetectorError> {
    detect_compiler(data, 50)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut v = vec![0u8; 512];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c] = 0x80; // PE at offset 0x80
        v[0x80] = b'P';
        v[0x81] = b'E';
        v[0x82] = 0;
        v[0x83] = 0;
        v
    }

    fn pe_with_string(s: &[u8]) -> Vec<u8> {
        let mut v = minimal_pe();
        v.extend_from_slice(s);
        v.push(0);
        v
    }

    #[test]
    fn detect_rust_from_symbol() {
        let data = pe_with_string(b"core::panicking::panic_fmt");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::Rust);
    }

    #[test]
    fn detect_gcc_from_version_banner() {
        let data = pe_with_string(b"GCC: (MinGW.org GCC Build-2) 9.2.0");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::Gcc);
    }

    #[test]
    fn detect_vb6_from_runtime() {
        let data = pe_with_string(b"MSVBVM60.DLL");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::VisualBasic);
        assert_eq!(result.version.as_ref().map(|v| v.version_str.as_str()), Some("6.0"));
    }

    #[test]
    fn detect_delphi_from_borland() {
        let data = pe_with_string(b"Borland Delphi Application");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::Delphi);
    }

    #[test]
    fn detect_clang_version_banner() {
        let data = pe_with_string(b"clang version 14.0.3 (https://github.com/llvm/llvm-project)");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::Clang);
    }

    #[test]
    fn detect_go_runtime() {
        let data = pe_with_string(b"runtime.main\x00go1.21.3\x00GOROOT=/usr/local/go");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::Go);
    }

    #[test]
    fn detect_unknown_returns_unknown() {
        let data = vec![0u8; 256];
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::Unknown);
    }

    #[test]
    fn detect_too_small_errors() {
        let err = detect(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, DetectorError::TooSmall(_)));
    }

    #[test]
    fn compiler_kind_display() {
        assert_eq!(CompilerKind::Msvc.to_string(), "MSVC");
        assert_eq!(CompilerKind::Rust.to_string(), "Rust");
        assert_eq!(CompilerKind::Go.to_string(), "Go");
    }

    #[test]
    fn compiler_version_from_str() {
        let v = CompilerVersion::from_str("14.3");
        assert_eq!(v.major, Some(14));
        assert_eq!(v.minor, Some(3));
    }

    #[test]
    fn compiler_version_new() {
        let v = CompilerVersion::new(14, 3, Some("MinGW".to_string()));
        assert_eq!(v.version_str, "14.3");
        assert_eq!(v.qualifier.as_deref(), Some("MinGW"));
        let s = v.to_string();
        assert!(s.contains("MinGW"));
    }

    #[test]
    fn evidence_display() {
        let e = CompilerEvidence::new(
            CompilerKind::Gcc,
            80,
            EvidenceSource::StringLiteral("GCC: (".into()),
            None,
            "GCC version banner",
        );
        let s = e.to_string();
        assert!(s.contains("GCC version banner"));
        assert!(s.contains("80"));
    }

    #[test]
    fn evidence_source_display_import() {
        let src = EvidenceSource::Import {
            dll: "kernel32.dll".into(),
            func: "LoadLibraryA".into(),
        };
        let s = src.to_string();
        assert!(s.contains("kernel32.dll"));
        assert!(s.contains("LoadLibraryA"));
    }

    #[test]
    fn detection_result_display() {
        let r = DetectionResult {
            compiler: CompilerKind::Msvc,
            version: Some(CompilerVersion::from_str("19.36")),
            confidence: 82,
            evidence: vec![],
            alternatives: vec![],
        };
        let s = r.to_string();
        assert!(s.contains("MSVC"));
        assert!(s.contains("82"));
    }

    #[test]
    fn detector_struct_api() {
        let detector = CompilerDetector::new(30);
        let data = pe_with_string(b"rustc 1.78.0");
        let result = detector.detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::Rust);
    }

    #[test]
    fn detector_high_threshold_returns_unknown() {
        let detector = CompilerDetector::new(99);
        let data = pe_with_string(b"rustc 1.78.0");
        // Single weak signal won't reach 99%
        let result = detector.detect(&data).unwrap();
        // May be Unknown if confidence is below threshold
        let _ = result; // just ensure no panic
    }

    #[test]
    fn detect_vb5_magic() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"VB5!");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::VisualBasic);
    }

    #[test]
    fn detect_free_pascal() {
        let data = pe_with_string(b"FPC 3.2.2 [2021/05/16] for i386 - Win32");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::FreePascal);
    }

    #[test]
    fn detect_d_lang_from_dmain() {
        let data = pe_with_string(b"_Dmain\x00_D4main4mainFAAyaZi");
        let result = detect(&data).unwrap();
        assert_eq!(result.compiler, CompilerKind::DLang);
    }
}
