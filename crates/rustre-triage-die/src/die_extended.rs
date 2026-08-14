//! `die_extended` — Extended DIE (Detect-It-Easy) detection: compiler/linker
//! signatures for MSVC, GCC, Clang, Delphi, Nim, Go, Rust, build artifact
//! extraction, and a comprehensive `DieReport`.

use std::fmt;

pub use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CompilerSignature — strongly typed compiler identity
// ---------------------------------------------------------------------------

/// Identified compiler.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompilerKind {
    Msvc,
    Gcc,
    Clang,
    Delphi,
    Borland,
    FreePascal,
    Nim,
    Go,
    Rust,
    DotNet,
    Java,
    Python,
    AutoIt,
    Vb6,
    PowerBasic,
    Intel,
    TinyC,
    Zig,
    VLang,
    Unknown,
}

impl fmt::Display for CompilerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A compiler signature — name, version, evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerSignature {
    pub kind: CompilerKind,
    pub version: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<String>,
    pub is_debug_build: bool,
    pub bitness: Option<u8>,
}

impl CompilerSignature {
    /// Create a new signature.
    #[must_use]
    pub fn new(kind: CompilerKind, version: impl Into<Option<String>>, confidence: u8) -> Self {
        Self {
            kind,
            version: version.into(),
            confidence,
            evidence: Vec::new(),
            is_debug_build: false,
            bitness: None,
        }
    }

    /// Whether this signature identifies a known compiler.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self.kind, CompilerKind::Unknown)
    }
}

impl fmt::Display for CompilerSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.version.as_deref().unwrap_or("?");
        let bits = self.bitness.map(|b| format!(" {b}bit")).unwrap_or_default();
        write!(f, "{}{} v{} ({}%)", self.kind, bits, ver, self.confidence)
    }
}

// ---------------------------------------------------------------------------
// LinkerSignature
// ---------------------------------------------------------------------------

/// Identified linker.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkerKind {
    MsvcLink,
    Lld,
    Gold,
    Bfd,
    Mold,
    TurboLink,
    SmartLink,
    Unknown,
}

impl fmt::Display for LinkerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A linker identification record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerSignature {
    pub kind: LinkerKind,
    pub version: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

impl LinkerSignature {
    #[must_use]
    pub fn new(kind: LinkerKind, version: impl Into<Option<String>>, confidence: u8) -> Self {
        Self {
            kind,
            version: version.into(),
            confidence,
            evidence: Vec::new(),
        }
    }
}

impl fmt::Display for LinkerSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.version.as_deref().unwrap_or("?");
        write!(f, "{} v{} ({}%)", self.kind, ver, self.confidence)
    }
}

// ---------------------------------------------------------------------------
// VersionDetection — version string extraction
// ---------------------------------------------------------------------------

/// A version string found in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedVersion {
    pub component: String,
    pub version_string: String,
    pub offset: u64,
    pub source: VersionSource,
}

/// Where the version was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionSource {
    RichHeader,
    VersionResource,
    DebugDirectory,
    EmbeddedString,
    SectionName,
    ImportTable,
}

/// Extract version strings from a binary.
#[must_use]
pub fn detect_versions(data: &[u8]) -> Vec<DetectedVersion> {
    let mut versions = Vec::new();

    // Rust version string pattern: "rustc X.Y.Z"
    let rustc = b"rustc ";
    if let Some(pos) = data.windows(rustc.len()).position(|w| w == rustc) {
        let remaining = data.len() - pos;
        let end = data[pos..]
            .iter()
            .position(|&b| b == 0 || b == b'\n' || b == b'"')
            .unwrap_or(50)
            // Cap to both 50 and remaining bytes to avoid slicing past end of data.
            .min(50)
            .min(remaining);
        let ver = String::from_utf8_lossy(&data[pos..pos + end]).into_owned();
        versions.push(DetectedVersion {
            component: "Rust compiler".to_string(),
            version_string: ver,
            offset: pos as u64,
            source: VersionSource::EmbeddedString,
        });
    }

    // Go version: "go1."
    let go = b"go1.";
    for pos in 0..data.len().saturating_sub(go.len()) {
        if &data[pos..pos + go.len()] == go {
            let remaining = data.len() - pos;
            let end = data[pos..]
                .iter()
                .position(|&b| b == 0 || b == b' ' || b == b'"')
                .unwrap_or(20)
                // Cap to both 20 and remaining bytes to avoid slicing past end of data.
                .min(20)
                .min(remaining);
            let ver = String::from_utf8_lossy(&data[pos..pos + end]).into_owned();
            // After the "go1." prefix the next character must be the version
            // digit (e.g. "go1.21.3" — index 4 is '2').
            if ver.len() > 4
                && ver
                    .chars().nth(4)
                    .is_some_and(|c| c.is_ascii_digit())
            {
                versions.push(DetectedVersion {
                    component: "Go runtime".to_string(),
                    version_string: ver,
                    offset: pos as u64,
                    source: VersionSource::EmbeddedString,
                });
                break;
            }
        }
    }

    // .NET CLR version: "v4." or "v2."
    let clr_patterns: &[&[u8]] = &[b"v4.0.", b"v2.0.", b"v3.5.", b"v4.5.", b"v4.7.", b"v4.8."];
    for pat in clr_patterns {
        if let Some(pos) = data.windows(pat.len()).position(|w| w == *pat) {
            let remaining = data.len() - pos;
            let end = data[pos..]
                .iter()
                .position(|&b| b == 0 || b == b'\r' || b == b'\n')
                .unwrap_or(20)
                .min(20)
                .min(remaining);
            versions.push(DetectedVersion {
                component: "CLR Runtime".to_string(),
                version_string: String::from_utf8_lossy(&data[pos..pos + end]).into_owned(),
                offset: pos as u64,
                source: VersionSource::VersionResource,
            });
            break;
        }
    }

    versions
}

// ---------------------------------------------------------------------------
// BuildArtifacts — compiler-generated metadata
// ---------------------------------------------------------------------------

/// Build artifacts found in a binary.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildArtifacts {
    /// PDB / debug info path.
    pub pdb_path: Option<String>,
    /// Source file paths embedded in the binary.
    pub source_paths: Vec<String>,
    /// Build configuration (Debug / Release / etc.).
    pub build_config: Option<String>,
    /// Product name from version resource.
    pub product_name: Option<String>,
    /// Company name from version resource.
    pub company_name: Option<String>,
    /// File version string.
    pub file_version: Option<String>,
    /// Internal name.
    pub internal_name: Option<String>,
    /// Original filename.
    pub original_filename: Option<String>,
    /// Copyright string.
    pub copyright: Option<String>,
    /// Tool chain strings.
    pub toolchain: Vec<String>,
}

impl BuildArtifacts {
    /// Extract build artifacts from raw bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut artifacts = Self::default();

        // PDB path: a .pdb path usually follows a CV_INFO_PDB record GUID
        let pdb_sig = b".pdb";
        if let Some(pos) = data.windows(pdb_sig.len()).position(|w| w == pdb_sig) {
            // Walk back to find the start of the path
            let start = data[..pos]
                .iter()
                .rposition(|&b| b < 0x20 && b != b'\\' && b != b'/' && b != b':')
                .map_or(0, |p| p + 1);
            let end = pos
                + 4
                + data[pos + 4..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0)
                    .min(256);
            if end > start && end <= data.len() {
                let path = String::from_utf8_lossy(&data[start..end]).into_owned();
                if path.contains('\\') || path.contains('/') {
                    artifacts.pdb_path = Some(path);
                }
            }
        }

        // Source paths: look for common C drive path patterns
        for pattern in [
            b"C:\\Users\\" as &[u8],
            b"D:\\build\\",
            b"/home/",
            b"/usr/src/",
        ] {
            if let Some(pos) = data.windows(pattern.len()).position(|w| w == pattern) {
                let end = data[pos..]
                    .iter()
                    .position(|&b| b == 0 || b == b'"')
                    .unwrap_or(128)
                    .min(128);
                let path = String::from_utf8_lossy(&data[pos..pos + end]).into_owned();
                if !artifacts.source_paths.contains(&path) {
                    artifacts.source_paths.push(path);
                }
            }
        }

        // Build configuration hints
        if data.windows(7).any(|w| w == b"Release") {
            artifacts.build_config = Some("Release".to_string());
        } else if data.windows(5).any(|w| w == b"Debug") {
            artifacts.build_config = Some("Debug".to_string());
        }

        artifacts
    }
}

// ---------------------------------------------------------------------------
// DieExtended — main detection engine
// ---------------------------------------------------------------------------

/// The extended DIE detection engine.
pub struct DieExtended;

impl DieExtended {
    /// Detect compiler from raw bytes.
    #[must_use]
    pub fn detect_compiler(data: &[u8]) -> Option<CompilerSignature> {
        // .NET / CLR takes precedence
        if is_dotnet(data) {
            let mut sig = CompilerSignature::new(CompilerKind::DotNet, None::<String>, 90);
            sig.evidence.push("CLR data directory present".to_string());
            return Some(sig);
        }

        // Rust
        if data.windows(5).any(|w| w == b"rustc") {
            let mut sig = CompilerSignature::new(CompilerKind::Rust, None::<String>, 88);
            sig.evidence.push("rustc string found".to_string());
            return Some(sig);
        }

        // Go
        if data.windows(8).any(|w| w == b"GoBuiltI") || data.windows(4).any(|w| w == b"go1.") {
            let mut sig = CompilerSignature::new(CompilerKind::Go, None::<String>, 87);
            sig.evidence.push("Go build info found".to_string());
            return Some(sig);
        }

        // Nim
        if data.windows(6).any(|w| w == b"NimVer") {
            let mut sig = CompilerSignature::new(CompilerKind::Nim, None::<String>, 85);
            sig.evidence.push("NimVer string".to_string());
            return Some(sig);
        }

        // Zig
        if data.windows(6).any(|w| w == b"zig_bi") {
            let mut sig = CompilerSignature::new(CompilerKind::Zig, None::<String>, 82);
            sig.evidence.push("zig_bi string".to_string());
            return Some(sig);
        }

        // Delphi / Borland
        if data.windows(7).any(|w| w == b"Borland") {
            let mut sig = CompilerSignature::new(CompilerKind::Delphi, None::<String>, 85);
            sig.evidence.push("Borland string".to_string());
            return Some(sig);
        }

        // AutoIt
        if data.windows(6).any(|w| w == b"AU3!EA") {
            let mut sig = CompilerSignature::new(CompilerKind::AutoIt, Some("3.x".to_string()), 92);
            sig.evidence.push("AU3!EA magic".to_string());
            return Some(sig);
        }

        // VB6
        if data.windows(4).any(|w| w == b"VB5!") {
            let mut sig = CompilerSignature::new(CompilerKind::Vb6, Some("6.0".to_string()), 90);
            sig.evidence.push("VB5! magic".to_string());
            return Some(sig);
        }

        // Clang (before GCC to prefer clang)
        if data.windows(5).any(|w| w == b"clang") {
            let mut sig = CompilerSignature::new(CompilerKind::Clang, None::<String>, 78);
            sig.evidence.push("clang string".to_string());
            return Some(sig);
        }

        // GCC / MinGW
        //
        // `GCC: (` is the real marker: GCC writes its version string into the
        // `.comment` section as e.g. `GCC: (GNU) 12.2.0`. It is taken from this
        // crate's own sibling detector (`compiler_detector.rs`), which had the
        // right signature all along.
        //
        // The bare `b"gcc"` below is kept but demoted, because 3 bytes cannot
        // support a confident verdict: there are only 2^24 such sequences, so a
        // specific one appears somewhere in a 10 MB image with probability
        // above 60% in uniformly random data — never mind the ordinary paths
        // and messages that contain "gcc". It is now a corroborating hint at
        // low confidence, and it says so in its evidence string.
        if data.windows(6).any(|w| w == b"GCC: (") {
            let mut sig = CompilerSignature::new(CompilerKind::Gcc, None::<String>, 92);
            sig.evidence
                .push("GCC version string in .comment (\"GCC: (\")".to_string());
            return Some(sig);
        }
        if data.windows(5).any(|w| w == b"MinGW") {
            let mut sig = CompilerSignature::new(CompilerKind::Gcc, None::<String>, 80);
            sig.evidence.push("MinGW string".to_string());
            return Some(sig);
        }
        if data.windows(3).any(|w| w == b"gcc") {
            let mut sig = CompilerSignature::new(CompilerKind::Gcc, None::<String>, 30);
            sig.evidence.push(
                "weak: 3-byte \"gcc\" substring only — occurs by chance in large \
                 buffers and in any path or message naming gcc"
                    .to_string(),
            );
            return Some(sig);
        }

        // MSVC — Rich header
        if data.windows(4).any(|w| w == b"Rich") {
            let mut sig = CompilerSignature::new(CompilerKind::Msvc, None::<String>, 75);
            sig.evidence.push("Rich header present".to_string());
            return Some(sig);
        }

        None
    }

    /// Detect linker from raw bytes.
    #[must_use]
    pub fn detect_linker(data: &[u8]) -> Option<LinkerSignature> {
        if data.windows(4).any(|w| w == b"lld\0") || data.windows(7).any(|w| w == b"lld-lin") {
            let mut sig = LinkerSignature::new(LinkerKind::Lld, None::<String>, 85);
            sig.evidence.push("lld string found".to_string());
            return Some(sig);
        }
        if data.windows(4).any(|w| w == b"gold") {
            let mut sig = LinkerSignature::new(LinkerKind::Gold, None::<String>, 70);
            sig.evidence.push("gold string found".to_string());
            return Some(sig);
        }
        if data.windows(9).any(|w| w == b"Microsoft") {
            let mut sig = LinkerSignature::new(LinkerKind::MsvcLink, None::<String>, 70);
            sig.evidence.push("Microsoft string found".to_string());
            return Some(sig);
        }
        None
    }

    /// Full detection run producing a `DieReport`.
    #[must_use]
    pub fn detect(data: &[u8]) -> DieReport {
        let compiler = Self::detect_compiler(data);
        let linker = Self::detect_linker(data);
        let versions = detect_versions(data);
        let artifacts = BuildArtifacts::from_bytes(data);

        let packer_hits = detect_packers_detailed(data);
        let packers: Vec<String> =
            packer_hits.iter().map(|(n, _, _)| (*n).to_string()).collect();
        let strong_packers: Vec<String> = packer_hits
            .iter()
            .filter(|(_, strong, _)| *strong)
            .map(|(n, _, _)| (*n).to_string())
            .collect();
        let protector_hits = detect_protectors_detailed(data);
        let protectors: Vec<String> =
            protector_hits.iter().map(|(n, _, _)| (*n).to_string()).collect();
        let strong_protectors: Vec<String> = protector_hits
            .iter()
            .filter(|(_, strong, _)| *strong)
            .map(|(n, _, _)| (*n).to_string())
            .collect();

        DieReport {
            compiler,
            linker,
            versions,
            artifacts,
            packers,
            strong_packers,
            protectors,
            strong_protectors,
            file_size: data.len(),
            entropy: compute_entropy(data),
        }
    }
}

/// Detect known packer strings.
/// Packer signatures, tagged by how much a match is worth.
///
/// Same criterion as [`PROTECTOR_SIGS`]: `strong` entries are structural — PE
/// section names (`UPX0`, `.MPRESS1`, `.aspack`) or an installer marker no
/// ordinary text carries (`PECompact2`). The weak entries are names a human
/// writes: `Nullsoft` and `Inno Setup` appear in installer documentation,
/// licence text and any tool that merely *mentions* them.
///
/// Added 2026-07-29, completing the split already applied to the protector
/// table beside this one and to the packer table in `rustre-mcp-tools`.
const PACKER_SIGS: &[(&[u8], &str, bool)] = &[
    (b"UPX0", "UPX", true),
    (b".MPRESS1", "MPRESS", true),
    (b".aspack", "ASPack", true),
    (b"PECompact2", "PECompact", true),
    (b"Nullsoft", "NSIS", false),
    (b"Inno Setup", "InnoSetup", false),
];

/// Every packer match with the evidence behind it: `(name, strong, offset)`.
fn detect_packers_detailed(data: &[u8]) -> Vec<(&'static str, bool, usize)> {
    let mut found = Vec::new();
    for (pat, name, strong) in PACKER_SIGS {
        if pat.len() <= data.len()
            && let Some(off) = data.windows(pat.len()).position(|w| w == *pat)
        {
            found.push((*name, *strong, off));
        }
    }
    found
}

/// All packer names matched, strong or weak.
///
/// Kept unchanged for callers and tests that want everything that matched;
/// use [`detect_packers_detailed`] when the distinction matters.
fn detect_packers(data: &[u8]) -> Vec<String> {
    detect_packers_detailed(data)
        .into_iter()
        .map(|(name, _, _)| name.to_string())
        .collect()
}

/// Detect known protector strings.
/// Protector signatures, tagged by how much a match is worth.
///
/// `strong` entries are PE **section names** — `.themida`, `.vmp0`, `.enigma1`
/// — which ordinary text cannot contain. `strong == false` entries are the
/// product's name as a human writes it: they occur in help strings, error
/// messages and analysis reports that merely *mention* the protector, so a
/// match is worth REPORTING but must not on its own produce a verdict.
///
/// Added 2026-07-29. Same shape as the packer table split earlier the same day
/// (`7-Zip` / `WinRAR` were setting `detected: true` on any file containing
/// those words). Milder here, because `Obsidium` and `ExeCryptor` are rare in
/// ordinary prose — but `is_protected()` is a verdict, and a verdict needs
/// evidence.
const PROTECTOR_SIGS: &[(&[u8], &str, bool)] = &[
    (b".themida", "Themida/WinLicense", true),
    (b".vmp0", "VMProtect", true),
    (b".enigma1", "Enigma Protector", true),
    (b"Obsidium", "Obsidium", false),
    (b"ExeCryptor", "ExeCryptor", false),
];

/// Every protector match with the evidence behind it: `(name, strong, offset)`.
fn detect_protectors_detailed(data: &[u8]) -> Vec<(&'static str, bool, usize)> {
    let mut found = Vec::new();
    for (pat, name, strong) in PROTECTOR_SIGS {
        if pat.len() <= data.len()
            && let Some(off) = data.windows(pat.len()).position(|w| w == *pat)
        {
            found.push((*name, *strong, off));
        }
    }
    found
}

/// All protector names matched, strong or weak.
///
/// Kept unchanged: callers and tests use it to see everything that matched.
/// Use [`detect_protectors_detailed`] when the distinction matters.
fn detect_protectors(data: &[u8]) -> Vec<String> {
    detect_protectors_detailed(data)
        .into_iter()
        .map(|(name, _, _)| name.to_string())
        .collect()
}

fn is_dotnet(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    if &data[0..2] != b"MZ" {
        return false;
    }
    let pe_off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_off + 4 > data.len() {
        return false;
    }
    if &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return false;
    }
    let opt_off = pe_off + 24;
    if opt_off + 2 > data.len() {
        return false;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let dd_off = if magic == 0x020b {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };
    let clr_off = dd_off + 14 * 8;
    if clr_off + 8 > data.len() {
        return false;
    }
    let rva = u32::from_le_bytes([
        data[clr_off],
        data[clr_off + 1],
        data[clr_off + 2],
        data[clr_off + 3],
    ]);
    rva != 0
}

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &f in &freq {
        if f > 0 {
            let p = f64::from(f) / len;
            h -= p * p.log2();
        }
    }
    h
}

// ---------------------------------------------------------------------------
// DieReport
// ---------------------------------------------------------------------------

/// Complete DIE detection report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DieReport {
    pub compiler: Option<CompilerSignature>,
    pub linker: Option<LinkerSignature>,
    pub versions: Vec<DetectedVersion>,
    pub artifacts: BuildArtifacts,
    /// Every packer name matched, strong or weak.
    pub packers: Vec<String>,
    /// Only the packers backed by a STRUCTURAL marker. `is_packed()` is
    /// derived from this, so a file that merely mentions a packer by name
    /// is reported in `packers` without being declared packed.
    pub strong_packers: Vec<String>,
    /// Every protector name matched, strong or weak.
    pub protectors: Vec<String>,
    /// Only the protectors backed by a STRUCTURAL marker (a PE section
    /// name). `is_protected()` is derived from this, so a file that merely
    /// mentions a protector by name is reported in `protectors` without
    /// being declared protected. Added 2026-07-29.
    pub strong_protectors: Vec<String>,
    pub file_size: usize,
    pub entropy: f64,
}

impl DieReport {
    /// Whether a packer was detected **on structural evidence**.
    ///
    /// Derived from `strong_packers`: before 2026-07-29 any file
    /// containing the words `Nullsoft` or `Inno Setup` — installer
    /// documentation, licence text, a tool naming them — was declared
    /// packed. The full match list remains in `packers`.
    #[must_use]
    pub const fn is_packed(&self) -> bool {
        !self.strong_packers.is_empty()
    }

    /// Whether a protector was detected **on structural evidence**.
    ///
    /// Derived from `strong_protectors`, not `protectors`: before
    /// 2026-07-29 any file containing the word `Obsidium` or
    /// `ExeCryptor` — a help string, an error message, an analysis
    /// report naming the tool — was declared protected. The full match
    /// list is still available in `protectors`.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        !self.strong_protectors.is_empty()
    }

    /// The compiler name as a string (or "Unknown").
    #[must_use]
    pub fn compiler_name(&self) -> String {
        self.compiler
            .as_ref().map_or_else(|| "Unknown".to_string(), |c| c.kind.to_string())
    }

    /// The linker name as a string (or "Unknown").
    #[must_use]
    pub fn linker_name(&self) -> String {
        self.linker
            .as_ref().map_or_else(|| "Unknown".to_string(), |l| l.kind.to_string())
    }
}

impl fmt::Display for DieReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DieReport: compiler={} linker={} packed={} protected={} entropy={:.3}",
            self.compiler_name(),
            self.linker_name(),
            self.is_packed(),
            self.is_protected(),
            self.entropy
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_kind_display() {
        assert_eq!(CompilerKind::Msvc.to_string(), "Msvc");
        assert_eq!(CompilerKind::Rust.to_string(), "Rust");
    }

    #[test]
    fn test_compiler_signature_new() {
        let s = CompilerSignature::new(CompilerKind::Gcc, Some("10.x".to_string()), 80);
        assert_eq!(s.kind, CompilerKind::Gcc);
        assert_eq!(s.confidence, 80);
        assert!(s.is_known());
    }

    #[test]
    fn test_compiler_signature_unknown() {
        let s = CompilerSignature::new(CompilerKind::Unknown, None::<String>, 0);
        assert!(!s.is_known());
    }

    #[test]
    fn test_compiler_signature_display() {
        let s = CompilerSignature::new(CompilerKind::Clang, Some("12.x".to_string()), 78);
        let d = s.to_string();
        assert!(d.contains("Clang"));
        assert!(d.contains("12.x"));
    }

    #[test]
    fn test_linker_signature_new() {
        let s = LinkerSignature::new(LinkerKind::Lld, Some("14.x".to_string()), 85);
        assert_eq!(s.kind, LinkerKind::Lld);
    }

    #[test]
    fn test_linker_signature_display() {
        let s = LinkerSignature::new(LinkerKind::MsvcLink, None::<String>, 70);
        let d = s.to_string();
        assert!(d.contains("MsvcLink"));
    }

    #[test]
    fn test_detect_compiler_rust() {
        let data = b"embedded rustc 1.70 string in binary";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::Rust);
    }

    #[test]
    fn test_detect_compiler_go() {
        let data = b"go1.21 runtime GoBuiltIn";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::Go);
    }

    #[test]
    fn test_detect_compiler_nim() {
        let data = b"NimVersion 1.6.10";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::Nim);
    }

    #[test]
    fn test_detect_compiler_delphi() {
        let data = b"Borland C++ Builder";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::Delphi);
    }

    #[test]
    fn test_detect_compiler_clang() {
        let data = b"clang-12.0 compiled binary";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::Clang);
    }

    #[test]
    fn test_detect_compiler_autoit() {
        let data = b"AU3!EA compiled script";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::AutoIt);
    }

    #[test]
    fn test_detect_compiler_vb6() {
        let data = b"VB5! runtime stub";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::Vb6);
    }

    #[test]
    fn test_detect_compiler_msvc_rich() {
        let data = b"MZ\x00\x00\x00\x00Rich header present in binary stub";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, CompilerKind::Msvc);
    }

    #[test]
    fn test_detect_compiler_unknown() {
        let data = b"nothing identifiable here at all 0x1234";
        let s = DieExtended::detect_compiler(data);
        assert!(s.is_none());
    }

    /// The real GCC marker must win, at high confidence.
    ///
    /// Added 2026-07-29. `GCC: (` is the prefix of the version string GCC
    /// writes into `.comment` (`GCC: (GNU) 12.2.0`), and was taken from this
    /// crate's own `compiler_detector.rs`, which had it all along while
    /// `die_extended` matched a 3-byte `gcc`.
    #[test]
    fn test_detect_compiler_gcc_comment_string_is_strong() {
        let data = b"....GCC: (GNU) 12.2.0....";
        let s = DieExtended::detect_compiler(data).expect("GCC marker must be detected");
        assert_eq!(s.kind, CompilerKind::Gcc);
        assert!(
            s.confidence >= 90,
            "the real .comment marker deserves high confidence, got {}",
            s.confidence
        );
    }

    /// A SIZE-REALISTIC negative control.
    ///
    /// `test_detect_compiler_unknown` above feeds 39 bytes. A 3-byte signature
    /// is essentially never hit in 39 bytes, so that test passes without
    /// exercising the failure mode at all — the real input is a multi-megabyte
    /// image, where a specific 3-byte sequence appears by chance with
    /// probability n/2^24 (over 60% at 10 MB).
    ///
    /// This feeds 4 MB of seeded pseudo-random bytes. A chance `gcc` hit is
    /// allowed — refusing it would be a lie in the other direction — but it
    /// must be reported as WEAK. What must never happen is arbitrary data
    /// producing a confident compiler identification.
    #[test]
    fn test_detect_compiler_confidence_is_proportional_on_random_data() {
        let mut prng: u64 = 0x2026_07_29_C0FFEE;
        let data: Vec<u8> = (0..4 * 1024 * 1024)
            .map(|_| {
                prng = prng
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (prng >> 33) as u8
            })
            .collect();

        if let Some(sig) = DieExtended::detect_compiler(&data) {
            assert!(
                sig.confidence < 50,
                "random bytes produced a confident {:?} verdict ({}), evidence: {:?}",
                sig.kind,
                sig.confidence,
                sig.evidence
            );
        }
    }

    #[test]
    fn test_detect_linker_lld() {
        let data = b"binary linked with lld\0 toolchain";
        let s = DieExtended::detect_linker(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, LinkerKind::Lld);
    }

    #[test]
    fn test_detect_linker_msvc() {
        let data = b"Microsoft Visual C++ Runtime";
        let s = DieExtended::detect_linker(data);
        assert!(s.is_some());
        assert_eq!(s.unwrap().kind, LinkerKind::MsvcLink);
    }

    #[test]
    fn test_detect_linker_unknown() {
        let data = b"nothing here";
        let s = DieExtended::detect_linker(data);
        assert!(s.is_none());
    }

    #[test]
    fn test_detect_versions_rust() {
        let data = b"binary rustc 1.70.0-nightly metadata";
        let versions = detect_versions(data);
        assert!(!versions.is_empty());
        assert!(versions[0].component.contains("Rust"));
    }

    #[test]
    fn test_detect_versions_go() {
        let data = b"program go1.21.3 runtime info";
        let versions = detect_versions(data);
        let go_ver = versions.iter().find(|v| v.component.contains("Go"));
        assert!(go_ver.is_some());
    }

    #[test]
    fn test_detect_versions_clr() {
        let data = b"assembly compiled for v4.0.30319 clr";
        let versions = detect_versions(data);
        let clr_ver = versions.iter().find(|v| v.component.contains("CLR"));
        assert!(clr_ver.is_some());
    }

    #[test]
    fn test_detect_versions_empty() {
        let versions = detect_versions(b"nothing here");
        assert!(versions.is_empty());
    }

    #[test]
    fn test_build_artifacts_release() {
        let data = b"Release build configuration string";
        let a = BuildArtifacts::from_bytes(data);
        assert_eq!(a.build_config.as_deref(), Some("Release"));
    }

    #[test]
    fn test_build_artifacts_debug() {
        let data = b"Debug symbols present in binary";
        let a = BuildArtifacts::from_bytes(data);
        assert_eq!(a.build_config.as_deref(), Some("Debug"));
    }

    #[test]
    fn test_build_artifacts_pdb() {
        let data = b"C:\\Users\\user\\project\\debug\\app.pdb\0trailing";
        let a = BuildArtifacts::from_bytes(data);
        // pdb detection is heuristic — just check no panic
        let _ = a.pdb_path;
    }

    #[test]
    fn test_detect_packers_upx() {
        let data = b"UPX0 section header data";
        let p = detect_packers(data);
        assert!(p.contains(&"UPX".to_string()));
    }

    #[test]
    fn test_detect_packers_nsis() {
        let data = b"Nullsoft Install System banner";
        let p = detect_packers(data);
        assert!(p.contains(&"NSIS".to_string()));
    }

    #[test]
    fn test_detect_protectors_themida() {
        let data = b".themida section name in PE";
        let p = detect_protectors(data);
        assert!(p.iter().any(|x| x.contains("Themida")));
    }

    /// Prose that merely NAMES a protector must not be declared protected.
    ///
    /// Added 2026-07-29. `is_protected()` derived from `!protectors.is_empty()`,
    /// and two table entries are bare product names, so any file containing the
    /// word `Obsidium` or `ExeCryptor` — a help string, an error message, an
    /// analysis report naming the tool — was reported as protected.
    /// The mention is still reported in `protectors`; what changed is that it
    /// no longer produces a verdict on its own.
    #[test]
    fn report_does_not_call_prose_protected() {
        let report = DieExtended::detect(b"see the Obsidium and ExeCryptor sections of the manual");

        assert!(
            !report.is_protected(),
            "a document naming protectors is not a protected binary"
        );
        assert!(
            report.strong_protectors.is_empty(),
            "no structural marker is present"
        );
        // Nothing is lost: the weak matches are still visible.
        assert_eq!(
            report.protectors.len(),
            2,
            "both mentions must still be reported: {:?}",
            report.protectors
        );
    }

    /// Positive control: a structural marker still yields a verdict.
    #[test]
    fn report_is_protected_on_a_section_name() {
        let report = DieExtended::detect(b"....vmp0....");
        assert!(
            report.is_protected(),
            "the .vmp0 section name is structural evidence"
        );
        assert!(
            report.strong_protectors.iter().any(|p| p.contains("VMProtect")),
            "got {:?}",
            report.strong_protectors
        );
    }

    /// Documentation that NAMES an installer is not a packed binary.
    ///
    /// Companion to `report_does_not_call_prose_protected`, for the packer
    /// table. `is_packed()` derived from `!packers.is_empty()`, and `Nullsoft`
    /// / `Inno Setup` are words that appear in installer documentation and
    /// licence text.
    #[test]
    fn report_does_not_call_prose_packed() {
        let report =
            DieExtended::detect(b"built with Inno Setup; see the Nullsoft installer docs");

        assert!(
            !report.is_packed(),
            "documentation naming installers is not a packed binary"
        );
        assert!(report.strong_packers.is_empty());
        assert_eq!(
            report.packers.len(),
            2,
            "both mentions must still be reported: {:?}",
            report.packers
        );
    }

    /// Positive control: a section name still yields the packed verdict.
    #[test]
    fn report_is_packed_on_a_section_name() {
        let report = DieExtended::detect(b"....UPX0....");
        assert!(report.is_packed(), "UPX0 is a PE section name");
        assert!(
            report.strong_packers.iter().any(|p| p == "UPX"),
            "got {:?}",
            report.strong_packers
        );
    }

    /// Every detection carries the offset that justifies it.
    #[test]
    fn protector_matches_carry_their_offset() {
        let hits = detect_protectors_detailed(b"xxxx.themida");
        assert_eq!(hits.len(), 1);
        let (name, strong, off) = hits[0];
        assert!(name.contains("Themida"));
        assert!(strong, "a section name is strong evidence");
        assert_eq!(off, 4, "the offset must locate the match");
    }

    #[test]
    fn test_detect_protectors_vmprotect() {
        let data = b".vmp0 section for protected code";
        let p = detect_protectors(data);
        assert!(p.iter().any(|x| x.contains("VMProtect")));
    }

    #[test]
    fn test_die_report_compiler_name() {
        let r = DieExtended::detect(b"rustc 1.70 embedded");
        assert_eq!(r.compiler_name(), "Rust");
    }

    #[test]
    fn test_die_report_is_packed() {
        let r = DieExtended::detect(b"UPX0 packer section");
        assert!(r.is_packed());
    }

    #[test]
    fn test_die_report_is_not_packed() {
        let r = DieExtended::detect(b"clean binary no packer");
        assert!(!r.is_packed());
    }

    #[test]
    fn test_die_report_entropy() {
        let data: Vec<u8> = (0u8..=255).collect();
        let r = DieExtended::detect(&data);
        assert!(r.entropy > 7.9);
    }

    #[test]
    fn test_die_report_display() {
        let r = DieExtended::detect(b"test binary data");
        let s = r.to_string();
        assert!(s.contains("DieReport"));
    }

    #[test]
    fn test_compute_entropy_all_same() {
        let data = vec![0xABu8; 1024];
        let e = compute_entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_compute_entropy_max() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        let e = compute_entropy(&data);
        assert!(e > 7.9);
    }
}
