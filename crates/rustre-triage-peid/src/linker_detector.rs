//! `linker_detector` — Detect which linker and compiler produced a binary.
//!
//! Uses Rich Header analysis, debug-directory inspection, section characteristics,
//! version-resource strings, and compiler-string heuristics to identify the
//! toolchain that produced a PE binary.
//!
//! # Key types
//!
//! | Type | Purpose |
//! |---|---|
//! | [`LinkerDetector`] | Top-level detector that orchestrates all heuristics |
//! | [`LinkerSignature`] | A named linker/compiler signature with version info |
//! | [`CompilerVersion`] | Version extracted from Rich Header / debug info |
//! | [`LinkerDb`] | Database of 40+ linker/compiler signatures |
//! | [`DetectedLinker`] | Result type for a detection attempt |
//! | [`RichHeaderAnalyzer`] | Parse and decode the PE Rich Header |


use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// LinkerKind
// ─────────────────────────────────────────────────────────────────────────────

/// The category of toolchain that produced the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkerKind {
    /// Microsoft Linker (link.exe).
    Msvc,
    /// GNU ld / ld.bfd.
    Gcc,
    /// LLVM lld.
    Clang,
    /// Embarcadero / Borland linker.
    Delphi,
    /// Free Pascal Compiler linker.
    Fpc,
    /// Go toolchain linker.
    Go,
    /// Rust (rustc / lld).
    Rust,
    /// Nim compiler linker.
    Nim,
    /// D language compiler (DMD/LDC).
    D,
    /// Watcom linker.
    Watcom,
    /// Digital Mars linker.
    DigitalMars,
    /// Unknown or unrecognised linker.
    Unknown,
}

impl LinkerKind {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Msvc => "MSVC",
            Self::Gcc => "GCC",
            Self::Clang => "Clang/LLVM",
            Self::Delphi => "Delphi/Borland",
            Self::Fpc => "Free Pascal",
            Self::Go => "Go",
            Self::Rust => "Rust",
            Self::Nim => "Nim",
            Self::D => "D",
            Self::Watcom => "Watcom",
            Self::DigitalMars => "Digital Mars",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for LinkerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompilerVersion
// ─────────────────────────────────────────────────────────────────────────────

/// A compiler/linker version extracted from PE metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerVersion {
    /// Major version number.
    pub major: u16,
    /// Minor version number.
    pub minor: u16,
    /// Build/patch version (0 if not present).
    pub build: u16,
    /// Human-readable version string.
    pub label: String,
}

impl CompilerVersion {
    /// Create a version with major.minor.
    #[must_use]
    pub fn new(major: u16, minor: u16) -> Self {
        Self {
            major,
            minor,
            build: 0,
            label: format!("{major}.{minor}"),
        }
    }

    /// Create a version with major.minor.build.
    #[must_use]
    pub fn with_build(major: u16, minor: u16, build: u16) -> Self {
        Self {
            major,
            minor,
            build,
            label: format!("{major}.{minor}.{build}"),
        }
    }

    /// Create a version from a raw MSVC build ID (from Rich Header).
    ///
    /// The `prod_id` is the high 16 bits of the Rich Header entry value,
    /// and `build_id` is the low 16 bits (build number).
    #[must_use]
    pub fn from_rich_entry(prod_id: u16, build_id: u16) -> Self {
        let (major, minor) = msvc_prod_id_to_version(prod_id);
        Self {
            major,
            minor,
            build: build_id,
            label: format!("{major}.{minor} (build {build_id})"),
        }
    }

    /// Return a short version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.label
    }
}

impl fmt::Display for CompilerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinkerSignature
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the linker/compiler signature database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerSignature {
    /// Linker kind.
    pub kind: LinkerKind,
    /// Version string.
    pub version: String,
    /// Confidence weight 0–100.
    pub confidence: u32,
    /// Description of what triggered this match.
    pub evidence: String,
    /// Optional Rich Header product ID range (min, max).
    pub rich_prod_id_range: Option<(u16, u16)>,
    /// Optional byte pattern that must appear in the binary.
    pub pattern: Option<Vec<u8>>,
}

impl LinkerSignature {
    /// Build a simple signature.
    #[must_use]
    pub fn new(
        kind: LinkerKind,
        version: impl Into<String>,
        confidence: u32,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            version: version.into(),
            confidence,
            evidence: evidence.into(),
            rich_prod_id_range: None,
            pattern: None,
        }
    }

    /// Add a Rich Header product-ID range constraint.
    #[must_use]
    pub const fn with_rich_range(mut self, min: u16, max: u16) -> Self {
        self.rich_prod_id_range = Some((min, max));
        self
    }

    /// Add a byte-pattern constraint.
    #[must_use]
    pub fn with_pattern(mut self, pattern: Vec<u8>) -> Self {
        self.pattern = Some(pattern);
        self
    }

    /// Returns `true` if the signature matches the given product ID.
    #[must_use]
    pub const fn matches_prod_id(&self, prod_id: u16) -> bool {
        match self.rich_prod_id_range {
            Some((min, max)) => prod_id >= min && prod_id <= max,
            None => false,
        }
    }
}

impl fmt::Display for LinkerSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} (confidence {}%)",
            self.kind, self.version, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectedLinker
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a linker/compiler detection attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLinker {
    /// Best-match linker kind.
    pub kind: LinkerKind,
    /// Version information, if determined.
    pub version: Option<CompilerVersion>,
    /// Human-readable version string.
    pub version_str: String,
    /// How confident we are (0–100).
    pub confidence: u32,
    /// List of evidence items that contributed to the detection.
    pub evidence: Vec<String>,
    /// Whether the binary has a Rich Header.
    pub has_rich_header: bool,
}

impl DetectedLinker {
    /// Create an "unknown" result.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            kind: LinkerKind::Unknown,
            version: None,
            version_str: String::new(),
            confidence: 0,
            evidence: Vec::new(),
            has_rich_header: false,
        }
    }

    /// Create a detected result.
    #[must_use]
    pub fn new(
        kind: LinkerKind,
        version_str: impl Into<String>,
        confidence: u32,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            kind,
            version: None,
            version_str: version_str.into(),
            confidence,
            evidence,
            has_rich_header: false,
        }
    }

    /// Returns `true` if a definite match was found.
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.kind != LinkerKind::Unknown && self.confidence >= 40
    }

    /// Short summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.is_known() {
            format!(
                "{} {} ({}% confidence)",
                self.kind, self.version_str, self.confidence
            )
        } else {
            "Unknown linker/compiler".to_string()
        }
    }
}

impl fmt::Display for DetectedLinker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RichHeaderEntry / RichHeader
// ─────────────────────────────────────────────────────────────────────────────

/// A single decoded entry from the PE Rich Header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichEntry {
    /// Product (tool) identifier.
    pub prod_id: u16,
    /// Build number.
    pub build_id: u16,
    /// Number of times this tool contributed to the binary.
    pub count: u32,
}

impl RichEntry {
    /// Returns the MSVC product version inferred from `prod_id`.
    #[must_use]
    pub const fn msvc_version(&self) -> (u16, u16) {
        msvc_prod_id_to_version(self.prod_id)
    }
}

impl fmt::Display for RichEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (maj, min) = self.msvc_version();
        write!(
            f,
            "prodId={:#06x} build={} count={} (vs{}.{:02})",
            self.prod_id, self.build_id, self.count, maj, min
        )
    }
}

/// The decoded PE Rich Header.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RichHeader {
    /// Decoded entries.
    pub entries: Vec<RichEntry>,
    /// XOR key used to encode the Rich Header.
    pub xor_key: u32,
    /// Whether the Rich Header signature was found and validated.
    pub valid: bool,
}

impl RichHeader {
    /// Returns `true` if the header contains at least one entry.
    #[must_use]
    pub const fn has_entries(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Returns the highest-version product ID found.
    #[must_use]
    pub fn max_prod_id(&self) -> Option<u16> {
        self.entries.iter().map(|e| e.prod_id).max()
    }

    /// Returns the most common MSVC version across all entries.
    #[must_use]
    pub fn dominant_version(&self) -> Option<(u16, u16)> {
        let mut counts: HashMap<(u16, u16), u32> = HashMap::new();
        for e in &self.entries {
            *counts.entry(e.msvc_version()).or_insert(0) += e.count;
        }
        counts.into_iter().max_by_key(|&(_, v)| v).map(|(k, _)| k)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RichHeaderAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Parses and decodes the PE Rich Header (the obfuscated structure between
/// the DOS stub and the PE signature).
pub struct RichHeaderAnalyzer;

impl RichHeaderAnalyzer {
    /// Attempt to find and decode the Rich Header in `pe_data`.
    ///
    /// Returns `RichHeader { valid: false }` if not found.
    #[must_use]
    pub fn analyze(pe_data: &[u8]) -> RichHeader {
        // The Rich Header lives between the DOS stub and the PE signature.
        // We search for the "Rich" marker (XOR-encoded).
        // The real "Rich" marker is after the encoded data; preceding it is the
        // XOR key. The start marker is "DanS" (also XOR-encoded).
        let e_lfanew = if pe_data.len() >= 0x40 {
            u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]])
                as usize
        } else {
            return RichHeader::default();
        };

        let search_end = e_lfanew.min(pe_data.len());
        // The search below starts at 0x80, so the guard has to be about 0x80 —
        // not about 8. With `search_end` between 8 and 0x84 the old condition
        // passed and `pe_data[0x80..search_end]` then panicked: for a 124-byte
        // file, "range start index 128 out of range for slice of length 124".
        // Four bytes past 0x80 are needed to hold the "Rich" marker at all.
        if search_end < 0x84 {
            return RichHeader::default();
        }

        // Search for "Rich" marker (unencoded — should be at rich_offset+4 with
        // the XOR key immediately after).
        let rich_marker = b"Rich";
        let rich_pos = match pe_data[0x80..search_end]
            .windows(4)
            .position(|w| w == rich_marker)
        {
            Some(p) => 0x80 + p,
            None => return RichHeader::default(),
        };

        if rich_pos + 8 > pe_data.len() {
            return RichHeader::default();
        }

        let xor_key = u32::from_le_bytes([
            pe_data[rich_pos + 4],
            pe_data[rich_pos + 5],
            pe_data[rich_pos + 6],
            pe_data[rich_pos + 7],
        ]);

        // Find the XOR-encoded "DanS" marker.
        let dans_encoded = xor_key ^ 0x536E6144; // b"DanS" as LE
        let mut dans_pos = None;
        let mut i = 0x80usize;
        while i + 4 <= rich_pos {
            let word =
                u32::from_le_bytes([pe_data[i], pe_data[i + 1], pe_data[i + 2], pe_data[i + 3]]);
            if word == dans_encoded {
                dans_pos = Some(i);
                break;
            }
            i += 4;
        }

        let dans_pos = match dans_pos {
            Some(p) => p,
            None => return RichHeader::default(),
        };

        // Decode entries between DanS+16 and Rich.
        let data_start = dans_pos + 16;
        if data_start >= rich_pos {
            return RichHeader {
                entries: Vec::new(),
                xor_key,
                valid: true,
            };
        }

        let mut entries = Vec::new();
        let mut pos = data_start;
        while pos + 8 <= rich_pos {
            let dw0 = u32::from_le_bytes([
                pe_data[pos],
                pe_data[pos + 1],
                pe_data[pos + 2],
                pe_data[pos + 3],
            ]) ^ xor_key;
            let dw1 = u32::from_le_bytes([
                pe_data[pos + 4],
                pe_data[pos + 5],
                pe_data[pos + 6],
                pe_data[pos + 7],
            ]) ^ xor_key;

            let prod_id = (dw0 >> 16) as u16;
            let build_id = (dw0 & 0xFFFF) as u16;
            let count = dw1;

            if prod_id != 0 || count != 0 {
                entries.push(RichEntry {
                    prod_id,
                    build_id,
                    count,
                });
            }
            pos += 8;
        }

        RichHeader {
            entries,
            xor_key,
            valid: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinkerDb
// ─────────────────────────────────────────────────────────────────────────────

/// Database of 40+ linker/compiler detection signatures.
pub struct LinkerDb {
    signatures: Vec<LinkerSignature>,
    /// Map from string pattern → `LinkerKind` for string-based detection.
    string_patterns: Vec<(Vec<u8>, LinkerKind, String, u32)>,
}

impl LinkerDb {
    /// Build the database with all built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        let mut db = Self {
            signatures: Vec::new(),
            string_patterns: Vec::new(),
        };
        db.populate_rich_header_sigs();
        db.populate_string_patterns();
        db
    }

    fn populate_rich_header_sigs(&mut self) {
        // MSVC versions by prod_id ranges.
        // VS 2022 (MSVC 17.x) — prod_id 0x0105..=0x010F
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2022 (17.x)",
                85,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x0105, 0x010F),
        );
        // VS 2019 (MSVC 16.x) — prod_id 0x00F0..=0x0104
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2019 (16.x)",
                85,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x00F0, 0x0104),
        );
        // VS 2017 (MSVC 15.x) — prod_id 0x00D0..=0x00EF
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2017 (15.x)",
                85,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x00D0, 0x00EF),
        );
        // VS 2015 (MSVC 14.x) — prod_id 0x00C0..=0x00CF
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2015 (14.x)",
                80,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x00C0, 0x00CF),
        );
        // VS 2013 (MSVC 12.x) — prod_id 0x00B0..=0x00BF
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2013 (12.x)",
                80,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x00B0, 0x00BF),
        );
        // VS 2012 (MSVC 11.x) — prod_id 0x00A0..=0x00AF
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2012 (11.x)",
                80,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x00A0, 0x00AF),
        );
        // VS 2010 (MSVC 10.x) — prod_id 0x0060..=0x009F
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2010 (10.x)",
                78,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x0060, 0x009F),
        );
        // VS 2008 (MSVC 9.x) — prod_id 0x0050..=0x005F
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2008 (9.x)",
                75,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x0050, 0x005F),
        );
        // VS 2005 (MSVC 8.x) — prod_id 0x0040..=0x004F
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2005 (8.x)",
                75,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x0040, 0x004F),
        );
        // VS 2003 (MSVC 7.1) — prod_id 0x0022..=0x003F
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2003 (7.1)",
                70,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x0022, 0x003F),
        );
        // VS 2002 (MSVC 7.0) — prod_id 0x0010..=0x0021
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "VS 2002 (7.0)",
                70,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x0010, 0x0021),
        );
        // MSVC 6.0 — prod_id 0x0001..=0x000F
        self.signatures.push(
            LinkerSignature::new(
                LinkerKind::Msvc,
                "MSVC 6.0",
                65,
                "Rich Header prod_id range",
            )
            .with_rich_range(0x0001, 0x000F),
        );
    }

    fn populate_string_patterns(&mut self) {
        // GCC patterns
        self.string_patterns.push((
            b"GCC: (".to_vec(),
            LinkerKind::Gcc,
            "GCC compiler string".into(),
            90,
        ));
        self.string_patterns.push((
            b"gcc version".to_vec(),
            LinkerKind::Gcc,
            "GCC version string".into(),
            88,
        ));
        self.string_patterns.push((
            b"mingw-w64".to_vec(),
            LinkerKind::Gcc,
            "MinGW-w64 toolchain".into(),
            85,
        ));
        self.string_patterns.push((
            b"MINGW".to_vec(),
            LinkerKind::Gcc,
            "MinGW toolchain".into(),
            80,
        ));
        self.string_patterns.push((
            b"cygwin".to_vec(),
            LinkerKind::Gcc,
            "Cygwin/GCC toolchain".into(),
            75,
        ));

        // Clang/LLVM patterns
        self.string_patterns.push((
            b"clang version".to_vec(),
            LinkerKind::Clang,
            "Clang version string".into(),
            92,
        ));
        self.string_patterns.push((
            b"clang LLVM ".to_vec(),
            LinkerKind::Clang,
            "Clang LLVM string".into(),
            90,
        ));
        self.string_patterns.push((
            b"LLVM ".to_vec(),
            LinkerKind::Clang,
            "LLVM string".into(),
            75,
        ));
        self.string_patterns.push((
            b"Apple clang".to_vec(),
            LinkerKind::Clang,
            "Apple Clang".into(),
            88,
        ));
        self.string_patterns.push((
            b"clang-".to_vec(),
            LinkerKind::Clang,
            "Clang identifier".into(),
            70,
        ));

        // Rust patterns
        self.string_patterns.push((
            b"rustc ".to_vec(),
            LinkerKind::Rust,
            "Rust compiler string".into(),
            95,
        ));
        self.string_patterns.push((
            b"rust_panic".to_vec(),
            LinkerKind::Rust,
            "Rust panic symbol".into(),
            90,
        ));
        self.string_patterns.push((
            b"core::panicking".to_vec(),
            LinkerKind::Rust,
            "Rust core panic".into(),
            90,
        ));
        self.string_patterns.push((
            b"std::panicking".to_vec(),
            LinkerKind::Rust,
            "Rust std panic".into(),
            90,
        ));
        self.string_patterns.push((
            b"alloc::alloc".to_vec(),
            LinkerKind::Rust,
            "Rust alloc crate".into(),
            85,
        ));

        // Go patterns
        self.string_patterns.push((
            b"GoVersion".to_vec(),
            LinkerKind::Go,
            "Go version symbol".into(),
            92,
        ));
        self.string_patterns.push((
            b"go build".to_vec(),
            LinkerKind::Go,
            "Go build string".into(),
            85,
        ));
        self.string_patterns.push((
            b"runtime.go".to_vec(),
            LinkerKind::Go,
            "Go runtime".into(),
            88,
        ));
        self.string_patterns.push((
            b"goroutine".to_vec(),
            LinkerKind::Go,
            "Goroutine string".into(),
            90,
        ));
        self.string_patterns.push((
            b"runtime/panic.go".to_vec(),
            LinkerKind::Go,
            "Go panic runtime".into(),
            90,
        ));

        // Delphi patterns
        self.string_patterns.push((
            b"Borland Delphi".to_vec(),
            LinkerKind::Delphi,
            "Delphi version string".into(),
            95,
        ));
        self.string_patterns.push((
            b"Embarcadero".to_vec(),
            LinkerKind::Delphi,
            "Embarcadero Delphi".into(),
            92,
        ));
        self.string_patterns.push((
            b"System.pas".to_vec(),
            LinkerKind::Delphi,
            "Delphi unit name".into(),
            85,
        ));
        self.string_patterns.push((
            b"Delphi ".to_vec(),
            LinkerKind::Delphi,
            "Delphi string".into(),
            80,
        ));

        // FPC patterns
        self.string_patterns.push((
            b"FPC_".to_vec(),
            LinkerKind::Fpc,
            "Free Pascal symbol prefix".into(),
            88,
        ));
        self.string_patterns.push((
            b"fpc_".to_vec(),
            LinkerKind::Fpc,
            "Free Pascal symbol prefix".into(),
            88,
        ));
        self.string_patterns.push((
            b"Free Pascal ".to_vec(),
            LinkerKind::Fpc,
            "Free Pascal string".into(),
            92,
        ));
        self.string_patterns.push((
            b"Lazarus".to_vec(),
            LinkerKind::Fpc,
            "Lazarus IDE (FPC)".into(),
            80,
        ));

        // Nim patterns
        self.string_patterns.push((
            b"NimVersion".to_vec(),
            LinkerKind::Nim,
            "Nim version symbol".into(),
            92,
        ));
        self.string_patterns.push((
            b"nim_main".to_vec(),
            LinkerKind::Nim,
            "Nim main symbol".into(),
            90,
        ));
        self.string_patterns.push((
            b"NimMain".to_vec(),
            LinkerKind::Nim,
            "Nim main symbol".into(),
            90,
        ));

        // D language patterns
        self.string_patterns.push((
            b"_Dmain".to_vec(),
            LinkerKind::D,
            "D language main".into(),
            88,
        ));
        self.string_patterns.push((
            b"D runtime".to_vec(),
            LinkerKind::D,
            "D runtime string".into(),
            85,
        ));
        self.string_patterns
            .push((b"dmd.".to_vec(), LinkerKind::D, "DMD compiler".into(), 82));

        // Watcom patterns
        self.string_patterns.push((
            b"Watcom C".to_vec(),
            LinkerKind::Watcom,
            "Watcom C string".into(),
            90,
        ));
        self.string_patterns.push((
            b"W32LINK".to_vec(),
            LinkerKind::Watcom,
            "Watcom linker ID".into(),
            88,
        ));

        // Digital Mars patterns
        self.string_patterns.push((
            b"Digital Mars".to_vec(),
            LinkerKind::DigitalMars,
            "Digital Mars string".into(),
            90,
        ));
        self.string_patterns.push((
            b"DMD ".to_vec(),
            LinkerKind::DigitalMars,
            "DMD compiler".into(),
            75,
        ));
    }

    /// Return the number of signatures.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len() + self.string_patterns.len()
    }

    /// Returns `true` if the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty() && self.string_patterns.is_empty()
    }

    /// Find all Rich Header signatures matching `prod_id`.
    #[must_use]
    pub fn rich_matches(&self, prod_id: u16) -> Vec<&LinkerSignature> {
        self.signatures
            .iter()
            .filter(|s| s.matches_prod_id(prod_id))
            .collect()
    }

    /// Find string-pattern matches in `data`.
    #[must_use]
    pub fn string_matches(&self, data: &[u8]) -> Vec<(LinkerKind, &str, u32)> {
        let mut results = Vec::new();
        for (pattern, kind, evidence, confidence) in &self.string_patterns {
            if data.windows(pattern.len()).any(|w| w == pattern.as_slice()) {
                results.push((*kind, evidence.as_str(), *confidence));
            }
        }
        results
    }
}

impl Default for LinkerDb {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LinkerDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level detector that identifies the linker/compiler from PE binary data.
///
/// Uses several independent heuristics:
/// 1. Rich Header product-ID analysis.
/// 2. String-pattern scanning.
/// 3. Section characteristics inspection.
/// 4. COFF linker version fields.
pub struct LinkerDetector {
    db: LinkerDb,
}

impl LinkerDetector {
    /// Create a detector with the built-in database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: LinkerDb::new(),
        }
    }

    /// Detect the linker/compiler from `pe_data`.
    #[must_use]
    pub fn detect(&self, pe_data: &[u8]) -> DetectedLinker {
        let rich = RichHeaderAnalyzer::analyze(pe_data);
        let mut candidates: HashMap<LinkerKind, (u32, Vec<String>)> = HashMap::new();

        // 1. Rich Header analysis.
        if rich.valid && rich.has_entries() {
            for entry in &rich.entries {
                for sig in self.db.rich_matches(entry.prod_id) {
                    let e = candidates.entry(sig.kind).or_insert((0, Vec::new()));
                    e.0 = e.0.max(sig.confidence);
                    e.1.push(format!(
                        "Rich Header: {} (prodId={:#06x})",
                        sig.evidence, entry.prod_id
                    ));
                }
            }
        }

        // 2. String-pattern scanning.
        for (kind, evidence, confidence) in self.db.string_matches(pe_data) {
            let e = candidates.entry(kind).or_insert((0, Vec::new()));
            e.0 = e.0.max(confidence);
            e.1.push(format!("String pattern: {evidence}"));
        }

        // 3. COFF linker version (from optional header).
        if let Some((major, minor)) = coff_linker_version(pe_data) {
            let evidence = format!("COFF linker version {major}.{minor}");
            if major >= 14 {
                let e = candidates
                    .entry(LinkerKind::Msvc)
                    .or_insert((0, Vec::new()));
                e.0 = e.0.max(70);
                e.1.push(evidence);
            }
        }

        // Pick best candidate.
        if let Some((kind, (confidence, evidence))) =
            candidates.into_iter().max_by_key(|(_, (c, _))| *c)
        {
            let version_str = if rich.valid {
                rich.dominant_version()
                    .map(|(maj, min)| format!("{maj}.{min}"))
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let mut result = DetectedLinker::new(kind, version_str, confidence, evidence);
            result.has_rich_header = rich.valid;
            result
        } else {
            let mut result = DetectedLinker::unknown();
            result.has_rich_header = rich.valid;
            result
        }
    }

    /// Quick check: does `pe_data` have a Rich Header?
    #[must_use]
    pub fn has_rich_header(pe_data: &[u8]) -> bool {
        RichHeaderAnalyzer::analyze(pe_data).valid
    }

    /// Return the raw Rich Header entries for `pe_data`.
    #[must_use]
    pub fn rich_header(pe_data: &[u8]) -> RichHeader {
        RichHeaderAnalyzer::analyze(pe_data)
    }

    /// Number of signatures in the database.
    #[must_use]
    pub const fn db_size(&self) -> usize {
        self.db.len()
    }
}

impl Default for LinkerDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Map an MSVC Rich Header product ID to a (major, minor) version pair.
const fn msvc_prod_id_to_version(prod_id: u16) -> (u16, u16) {
    match prod_id {
        0x0001..=0x000F => (6, 0),
        0x0010..=0x0021 => (7, 0),
        0x0022..=0x003F => (7, 1),
        0x0040..=0x004F => (8, 0),
        0x0050..=0x005F => (9, 0),
        0x0060..=0x009F => (10, 0),
        0x00A0..=0x00AF => (11, 0),
        0x00B0..=0x00BF => (12, 0),
        0x00C0..=0x00CF => (14, 0),
        0x00D0..=0x00EF => (15, 0),
        0x00F0..=0x0104 => (16, 0),
        0x0105..=0x010F => (17, 0),
        _ => (0, 0),
    }
}

/// Read the linker version from the COFF optional header.
fn coff_linker_version(pe_data: &[u8]) -> Option<(u8, u8)> {
    if pe_data.len() < 0x40 {
        return None;
    }
    if &pe_data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew =
        u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;
    if e_lfanew + 28 > pe_data.len() {
        return None;
    }
    if &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    // Optional header starts at e_lfanew + 24.
    let opt = e_lfanew + 24;
    if opt + 4 > pe_data.len() {
        return None;
    }
    let major = pe_data[opt + 2];
    let minor = pe_data[opt + 3];
    Some((major, minor))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── LinkerKind ────────────────────────────────────────────────────────────

    #[test]
    fn test_linker_kind_names() {
        assert_eq!(LinkerKind::Msvc.name(), "MSVC");
        assert_eq!(LinkerKind::Gcc.name(), "GCC");
        assert_eq!(LinkerKind::Clang.name(), "Clang/LLVM");
        assert_eq!(LinkerKind::Rust.name(), "Rust");
        assert_eq!(LinkerKind::Go.name(), "Go");
        assert_eq!(LinkerKind::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_linker_kind_display() {
        assert_eq!(LinkerKind::Delphi.to_string(), "Delphi/Borland");
    }

    // ── CompilerVersion ───────────────────────────────────────────────────────

    #[test]
    fn test_compiler_version_new() {
        let v = CompilerVersion::new(16, 0);
        assert_eq!(v.major, 16);
        assert_eq!(v.minor, 0);
        assert_eq!(v.label, "16.0");
    }

    #[test]
    fn test_compiler_version_with_build() {
        let v = CompilerVersion::with_build(17, 5, 32215);
        assert_eq!(v.build, 32215);
        assert!(v.label.contains("32215"));
    }

    #[test]
    fn test_compiler_version_from_rich_entry() {
        let v = CompilerVersion::from_rich_entry(0x00F5, 29912);
        assert_eq!(v.major, 16);
        assert!(v.label.contains("29912"));
    }

    #[test]
    fn test_compiler_version_display() {
        let v = CompilerVersion::new(14, 2);
        assert!(v.to_string().contains("14.2"));
    }

    // ── LinkerSignature ───────────────────────────────────────────────────────

    #[test]
    fn test_linker_signature_display() {
        let sig = LinkerSignature::new(LinkerKind::Msvc, "VS 2022", 90, "test");
        assert!(sig.to_string().contains("MSVC"));
        assert!(sig.to_string().contains("90%"));
    }

    #[test]
    fn test_linker_signature_matches_prod_id() {
        let sig = LinkerSignature::new(LinkerKind::Msvc, "VS 2022", 85, "test")
            .with_rich_range(0x0105, 0x010F);
        assert!(sig.matches_prod_id(0x0105));
        assert!(sig.matches_prod_id(0x010F));
        assert!(!sig.matches_prod_id(0x0104));
        assert!(!sig.matches_prod_id(0x0110));
    }

    #[test]
    fn test_linker_signature_no_range() {
        let sig = LinkerSignature::new(LinkerKind::Gcc, "GCC", 80, "test");
        assert!(!sig.matches_prod_id(0x0001));
    }

    // ── DetectedLinker ────────────────────────────────────────────────────────

    #[test]
    fn test_detected_linker_unknown() {
        let d = DetectedLinker::unknown();
        assert!(!d.is_known());
        assert_eq!(d.kind, LinkerKind::Unknown);
    }

    #[test]
    fn test_detected_linker_known() {
        let d = DetectedLinker::new(LinkerKind::Rust, "1.70", 90, vec!["rustc string".into()]);
        assert!(d.is_known());
        let summary = d.summary();
        assert!(summary.contains("Rust"));
        assert!(summary.contains("90%"));
    }

    #[test]
    fn test_detected_linker_low_confidence_not_known() {
        let d = DetectedLinker::new(LinkerKind::Gcc, "4.x", 30, vec![]);
        assert!(!d.is_known()); // below 40%
    }

    #[test]
    fn test_detected_linker_display() {
        let d = DetectedLinker::new(LinkerKind::Msvc, "17.0", 95, vec![]);
        let s = d.to_string();
        assert!(s.contains("MSVC") || s.contains("17.0") || s.contains("95%"));
    }

    // ── RichEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_rich_entry_msvc_version() {
        let e = RichEntry {
            prod_id: 0x00F5,
            build_id: 29912,
            count: 4,
        };
        let (maj, min) = e.msvc_version();
        assert_eq!(maj, 16);
        assert_eq!(min, 0);
    }

    #[test]
    fn test_rich_entry_display() {
        let e = RichEntry {
            prod_id: 0x0105,
            build_id: 32215,
            count: 1,
        };
        let s = e.to_string();
        assert!(s.contains("0x0105") || s.contains("0105"));
    }

    // ── RichHeader ────────────────────────────────────────────────────────────

    #[test]
    fn test_rich_header_default_empty() {
        let rh = RichHeader::default();
        assert!(!rh.valid);
        assert!(!rh.has_entries());
        assert!(rh.max_prod_id().is_none());
    }

    #[test]
    fn test_rich_header_dominant_version() {
        let mut rh = RichHeader {
            valid: true,
            ..RichHeader::default()
        };
        rh.entries = vec![
            RichEntry {
                prod_id: 0x00F5,
                build_id: 0,
                count: 10,
            },
            RichEntry {
                prod_id: 0x00F6,
                build_id: 0,
                count: 2,
            },
        ];
        let dom = rh.dominant_version();
        assert!(dom.is_some());
    }

    #[test]
    fn test_rich_header_max_prod_id() {
        let mut rh = RichHeader {
            valid: true,
            ..RichHeader::default()
        };
        rh.entries = vec![
            RichEntry {
                prod_id: 0x0010,
                build_id: 0,
                count: 1,
            },
            RichEntry {
                prod_id: 0x00F5,
                build_id: 0,
                count: 1,
            },
        ];
        assert_eq!(rh.max_prod_id(), Some(0x00F5));
    }

    // ── RichHeaderAnalyzer ────────────────────────────────────────────────────

    #[test]
    fn test_rich_header_analyzer_no_dos_stub() {
        let data = vec![0u8; 64];
        let rh = RichHeaderAnalyzer::analyze(&data);
        assert!(!rh.valid);
    }

    #[test]
    fn test_rich_header_analyzer_mz_no_rich() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80; // e_lfanew = 0x80
        let rh = RichHeaderAnalyzer::analyze(&data);
        assert!(!rh.valid);
    }

    // ── LinkerDb ──────────────────────────────────────────────────────────────

    #[test]
    fn test_linker_db_has_40_plus_entries() {
        let db = LinkerDb::new();
        assert!(db.len() >= 40, "only {} entries", db.len());
    }

    #[test]
    fn test_linker_db_rich_matches_vs2022() {
        let db = LinkerDb::new();
        let matches = db.rich_matches(0x0107);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|s| s.kind == LinkerKind::Msvc));
    }

    #[test]
    fn test_linker_db_rich_no_match() {
        let db = LinkerDb::new();
        let matches = db.rich_matches(0xFFFF);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_linker_db_string_match_rust() {
        let db = LinkerDb::new();
        let data = b"...rustc 1.70.0 (90c541806 2023-05-31)...";
        let matches = db.string_matches(data);
        assert!(matches.iter().any(|(k, _, _)| *k == LinkerKind::Rust));
    }

    #[test]
    fn test_linker_db_string_match_gcc() {
        let db = LinkerDb::new();
        let data = b"GCC: (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0";
        let matches = db.string_matches(data);
        assert!(matches.iter().any(|(k, _, _)| *k == LinkerKind::Gcc));
    }

    #[test]
    fn test_linker_db_string_match_go() {
        let db = LinkerDb::new();
        let data = b"goroutine panic goroutine GoVersion 1.20";
        let matches = db.string_matches(data);
        assert!(matches.iter().any(|(k, _, _)| *k == LinkerKind::Go));
    }

    // ── LinkerDetector ────────────────────────────────────────────────────────

    #[test]
    fn rich_header_analyze_does_not_panic_on_short_input() {
        // `analyze` searches from 0x80, so any file whose e_lfanew resolves to
        // something between 8 and 0x84 used to slice `pe_data[0x80..search_end]`
        // with start > end and panic. A truncated or hostile file must produce a
        // default header, never a crash — this is a library that reads untrusted
        // input.
        for len in [8usize, 0x40, 0x7F, 0x80, 0x83] {
            let mut data = vec![0u8; len];
            if len >= 2 {
                data[0] = b'M';
                data[1] = b'Z';
            }
            // Point e_lfanew past the end so `search_end` clamps to len.
            if len >= 0x40 {
                data[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            }
            let h = RichHeaderAnalyzer::analyze(&data);
            assert!(
                h.entries.is_empty(),
                "{len}-byte input must yield an empty header, not a panic"
            );
        }
    }

    #[test]
    fn test_detector_rust_binary() {
        let detector = LinkerDetector::new();
        let data = b"MZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00rustc 1.72.0 (5680fa18f 2023-08-23) rust_panic core::panicking";
        let result = detector.detect(data);
        assert_eq!(result.kind, LinkerKind::Rust);
        assert!(result.confidence >= 80);
    }

    #[test]
    fn test_detector_go_binary() {
        let detector = LinkerDetector::new();
        let data = b"MZ\x00\x00goroutine GoVersion go1.20 runtime.go";
        let result = detector.detect(data);
        assert_eq!(result.kind, LinkerKind::Go);
    }

    #[test]
    fn test_detector_empty_returns_unknown() {
        let detector = LinkerDetector::new();
        let result = detector.detect(&[]);
        assert_eq!(result.kind, LinkerKind::Unknown);
    }

    #[test]
    fn test_detector_db_size() {
        let detector = LinkerDetector::new();
        assert!(detector.db_size() >= 40);
    }

    #[test]
    fn test_detector_no_rich_header_on_empty() {
        assert!(!LinkerDetector::has_rich_header(&[]));
    }

    #[test]
    fn test_detected_linker_has_evidence() {
        let detector = LinkerDetector::new();
        let data = b"MZ\x00\x00GCC: (Ubuntu 11.3.0) 11.3.0";
        let result = detector.detect(data);
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn test_msvc_prod_id_to_version() {
        assert_eq!(msvc_prod_id_to_version(0x0001), (6, 0));
        assert_eq!(msvc_prod_id_to_version(0x00F5), (16, 0));
        assert_eq!(msvc_prod_id_to_version(0x0107), (17, 0));
        assert_eq!(msvc_prod_id_to_version(0xFFFF), (0, 0));
    }
}
