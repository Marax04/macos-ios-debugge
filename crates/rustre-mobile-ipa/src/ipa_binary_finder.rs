//! IPA binary finder — locates and classifies all Mach-O executables inside an
//! IPA ZIP archive without a full ZIP parser dependency.
//!
//! An IPA file follows the layout:
//! ```text
//! Payload/
//!   MyApp.app/
//!     MyApp              ← main executable (MH_EXECUTE)
//!     Frameworks/
//!       Foo.framework/Foo  ← dynamic library (MH_DYLIB)
//!     PlugIns/
//!       Bar.appex/Bar    ← app extension (MH_EXECUTE)
//! ```
//!
//! This module scans the ZIP central directory for entries whose name ends with
//! a known Mach-O path suffix (no extension inside a `.app/` or `.framework/`
//! directory), reads the first 8 bytes of each candidate to verify the magic
//! number, and returns a list of [`AppBinary`] records.

use std::collections::HashMap;

// ── Mach-O magic constants ────────────────────────────────────────────────────

const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_CIGAM: u32 = 0xCEFA_EDFE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_CIGAM: u32 = 0xBEBA_FECA;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by [`IpaBinaryFinder`].
#[derive(Debug)]
pub enum BinaryFinderError {
    /// The supplied bytes are not a valid ZIP / IPA archive.
    NotAZip,
    /// An entry in the central directory could not be parsed.
    CdParse(String),
    /// A requested binary entry could not be located.
    EntryNotFound(String),
    /// I/O-style error (slice out of bounds, etc.).
    Io(String),
}

impl std::fmt::Display for BinaryFinderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAZip => write!(f, "not a valid ZIP archive"),
            Self::CdParse(s) => write!(f, "central directory parse error: {s}"),
            Self::EntryNotFound(s) => write!(f, "entry not found: {s}"),
            Self::Io(s) => write!(f, "I/O error: {s}"),
        }
    }
}

impl std::error::Error for BinaryFinderError {}

// ── Architecture ──────────────────────────────────────────────────────────────

/// CPU architecture of a Mach-O binary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CpuArch {
    /// ARM 64-bit (Apple Silicon / modern iOS).
    Arm64,
    /// ARM 32-bit (legacy iOS).
    Arm32,
    /// x86-64 (simulator).
    X86_64,
    /// x86 32-bit (old simulator).
    X86,
    /// A FAT binary containing multiple architectures.
    Fat(Vec<Self>),
    /// Unrecognised CPU type code.
    Unknown(u32),
}

impl std::fmt::Display for CpuArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arm64 => write!(f, "arm64"),
            Self::Arm32 => write!(f, "armv7"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::X86 => write!(f, "x86"),
            Self::Fat(arches) => {
                write!(f, "fat(")?;
                for (i, a) in arches.iter().enumerate() {
                    if i > 0 { write!(f, "+")?; }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Self::Unknown(n) => write!(f, "unknown(0x{n:08x})"),
        }
    }
}

// ── Mach-O file type ──────────────────────────────────────────────────────────

/// Mach-O file type (`mh_filetype`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MachOType {
    /// Main executable (`MH_EXECUTE = 2`).
    Execute,
    /// Dynamic library (`MH_DYLIB = 6`).
    Dylib,
    /// Dynamic linker (`MH_DYLINKER = 7`).
    Dylinker,
    /// Bundle (`MH_BUNDLE = 8`).
    Bundle,
    /// Core dump (`MH_CORE = 4`).
    Core,
    /// Object file (`MH_OBJECT = 1`).
    Object,
    /// Unknown filetype.
    Unknown(u32),
}

impl MachOType {
    const fn from_u32(n: u32) -> Self {
        match n {
            1 => Self::Object,
            2 => Self::Execute,
            4 => Self::Core,
            6 => Self::Dylib,
            7 => Self::Dylinker,
            8 => Self::Bundle,
            other => Self::Unknown(other),
        }
    }
}

// ── BinaryPath ────────────────────────────────────────────────────────────────

/// The zip-internal path of a binary and its classification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryPath {
    /// Full zip-entry path (e.g. `Payload/MyApp.app/MyApp`).
    pub zip_path: String,
    /// The final path component (filename).
    pub name: String,
    /// Relative path inside the `.app` bundle.
    pub bundle_relative: String,
    /// Whether this path is the main executable (matches `CFBundleExecutable`).
    pub is_main_executable: bool,
    /// Whether this binary lives under a `Frameworks/` subtree.
    pub is_framework: bool,
    /// Whether this binary lives under a `PlugIns/` subtree.
    pub is_plugin: bool,
    /// Uncompressed size in bytes as reported by the central directory.
    pub uncompressed_size: u64,
    /// Offset of the local file header in the ZIP data.
    pub local_offset: u64,
}

// ── AppBinary ─────────────────────────────────────────────────────────────────

/// A confirmed Mach-O binary found inside an IPA.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppBinary {
    /// Path information.
    pub path: BinaryPath,
    /// Mach-O magic that was observed.
    pub magic: u32,
    /// Whether this is a 64-bit binary.
    pub is_64bit: bool,
    /// Whether the magic is byte-swapped relative to the host.
    pub is_byte_swapped: bool,
    /// Whether this is a FAT universal binary.
    pub is_fat: bool,
    /// CPU architecture(s).
    pub arch: CpuArch,
    /// Mach-O file type (from the header's `filetype` field).
    pub mach_type: MachOType,
    /// Size of the binary data in bytes.
    pub size: u64,
}

impl AppBinary {
    /// Return `true` when this binary is the application's main executable.
    #[must_use]
    pub const fn is_main(&self) -> bool {
        self.path.is_main_executable
    }

    /// Return `true` when this is a dynamic library embedded in Frameworks/.
    #[must_use]
    pub const fn is_framework(&self) -> bool {
        self.path.is_framework
    }

    /// Return `true` when this is an app extension binary from `PlugIns`/.
    #[must_use]
    pub const fn is_extension(&self) -> bool {
        self.path.is_plugin
    }
}

// ── FinderConfig ─────────────────────────────────────────────────────────────

/// Configuration for [`IpaBinaryFinder`].
#[derive(Debug, Clone)]
pub struct FinderConfig {
    /// Only return binaries whose Mach-O magic verifies (default: `true`).
    pub verify_magic: bool,
    /// Also scan `PlugIns/` for app extension binaries (default: `true`).
    pub include_extensions: bool,
    /// Also scan `Frameworks/` for embedded dynamic libraries (default: `true`).
    pub include_frameworks: bool,
    /// Name of the main executable (from `CFBundleExecutable`), used to mark
    /// the primary binary.  When `None`, heuristics are used.
    pub main_executable_name: Option<String>,
}

impl Default for FinderConfig {
    fn default() -> Self {
        Self {
            verify_magic: true,
            include_extensions: true,
            include_frameworks: true,
            main_executable_name: None,
        }
    }
}

// ── IpaBinaryFinder ───────────────────────────────────────────────────────────

/// Finds and classifies Mach-O binaries inside a raw IPA byte slice.
pub struct IpaBinaryFinder {
    config: FinderConfig,
}

impl IpaBinaryFinder {
    /// Create a new finder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { config: FinderConfig::default() }
    }

    /// Create a finder with a custom configuration.
    #[must_use]
    pub const fn with_config(config: FinderConfig) -> Self {
        Self { config }
    }

    /// Set the name of the main executable so it can be flagged correctly.
    pub fn set_main_executable(&mut self, name: impl Into<String>) {
        self.config.main_executable_name = Some(name.into());
    }

    /// Scan `ipa_data` (raw IPA/ZIP bytes) and return all Mach-O binaries
    /// found inside.
    ///
    /// # Errors
    /// Returns an error if the ZIP central directory cannot be parsed.
    pub fn find_binaries(
        &self,
        ipa_data: &[u8],
    ) -> Result<Vec<AppBinary>, BinaryFinderError> {
        let cd_entries = parse_central_directory(ipa_data)?;
        let mut binaries = Vec::new();

        for entry in &cd_entries {
            if !Self::is_candidate_path(&entry.name) {
                continue;
            }

            let bin_path = classify_path(entry, &self.config);

            if !self.config.include_frameworks && bin_path.is_framework {
                continue;
            }
            if !self.config.include_extensions && bin_path.is_plugin {
                continue;
            }

            // Read enough bytes to parse the Mach-O header.
            let data = read_entry_data(ipa_data, entry)?;
            if data.len() < 8 {
                continue;
            }

            let magic = read_u32_le(data, 0);
            if self.config.verify_magic && !is_macho_magic(magic) {
                continue;
            }
            if !is_macho_magic(magic) {
                continue;
            }

            let (arch, mach_type, is_fat, is_64bit, is_byte_swapped) =
                parse_macho_header(data, magic);

            binaries.push(AppBinary {
                path: bin_path,
                magic,
                is_64bit,
                is_byte_swapped,
                is_fat,
                arch,
                mach_type,
                size: entry.uncompressed_size,
            });
        }

        Ok(binaries)
    }

    /// Return `true` if `path` is a plausible Mach-O candidate inside an IPA.
    fn is_candidate_path(path: &str) -> bool {
        // Must be inside Payload/
        if !path.starts_with("Payload/") {
            return false;
        }
        // Skip directory entries and resource files with known extensions.
        if path.ends_with('/') {
            return false;
        }
        let skip_extensions = [
            ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".car", ".strings",
            ".nib", ".plist", ".js", ".html", ".css", ".json", ".ttf",
            ".otf", ".mp3", ".mp4", ".m4a", ".mov", ".wav", ".mobileprovision",
            ".dylib", ".a", ".swift", ".h", ".m", ".c",
        ];
        let lower = path.to_lowercase();
        for ext in skip_extensions {
            if lower.ends_with(ext) {
                return false;
            }
        }
        true
    }
}

impl Default for IpaBinaryFinder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Path classifier ───────────────────────────────────────────────────────────

fn classify_path(entry: &CdEntry, config: &FinderConfig) -> BinaryPath {
    let zip_path = entry.name.clone();
    let name = zip_path.split('/').next_back().unwrap_or("").to_string();

    // Strip "Payload/AppName.app/" prefix for bundle_relative.
    let bundle_relative = strip_payload_prefix(&zip_path).map_or_else(|| zip_path.clone(), std::string::ToString::to_string);

    let is_framework = zip_path.contains("/Frameworks/");
    let is_plugin = zip_path.contains("/PlugIns/");

    let is_main_executable = config.main_executable_name.as_ref().map_or_else(
        // Heuristic: the main executable is the sole non-framework,
        // non-plugin, non-extension binary directly in the .app folder.
        || !is_framework && !is_plugin && bundle_relative.chars().filter(|c| *c == '/').count() == 0,
        |exe_name| &name == exe_name && !is_framework && !is_plugin,
    );

    BinaryPath {
        zip_path,
        name,
        bundle_relative,
        is_main_executable,
        is_framework,
        is_plugin,
        uncompressed_size: entry.uncompressed_size,
        local_offset: entry.local_offset,
    }
}

fn strip_payload_prefix(path: &str) -> Option<&str> {
    // "Payload/App.app/..." → "..."
    let rest = path.strip_prefix("Payload/")?;
    let slash = rest.find('/')?;
    Some(&rest[slash + 1..])
}

// ── Mach-O header parsing ─────────────────────────────────────────────────────

const fn is_macho_magic(magic: u32) -> bool {
    matches!(
        magic,
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 | FAT_MAGIC | FAT_CIGAM
    )
}

fn parse_macho_header(
    data: &[u8],
    magic: u32,
) -> (CpuArch, MachOType, bool, bool, bool) {
    let is_fat = matches!(magic, FAT_MAGIC | FAT_CIGAM);
    let is_byte_swapped = matches!(magic, MH_CIGAM | MH_CIGAM_64 | FAT_CIGAM);
    let is_64bit = matches!(magic, MH_MAGIC_64 | MH_CIGAM_64);

    if is_fat {
        let arches = parse_fat_arches(data, is_byte_swapped);
        return (CpuArch::Fat(arches), MachOType::Unknown(0), true, false, is_byte_swapped);
    }

    if data.len() < 16 {
        return (CpuArch::Unknown(0), MachOType::Unknown(0), false, is_64bit, is_byte_swapped);
    }

    let cpu_type = if is_byte_swapped {
        read_u32_be(data, 4)
    } else {
        read_u32_le(data, 4)
    };
    let file_type = if is_byte_swapped {
        read_u32_be(data, 12)
    } else {
        read_u32_le(data, 12)
    };

    let arch = cpu_type_to_arch(cpu_type);
    let mach_type = MachOType::from_u32(file_type);
    (arch, mach_type, false, is_64bit, is_byte_swapped)
}

const fn cpu_type_to_arch(cpu_type: u32) -> CpuArch {
    // cpu_type constants (masked to 24 bits to ignore CPU_ARCH_ABI64 flag 0x01000000)
    const CPU_TYPE_X86: u32 = 7;
    const CPU_TYPE_X86_64: u32 = 7 | 0x0100_0000;
    const CPU_TYPE_ARM: u32 = 12;
    const CPU_TYPE_ARM64: u32 = 12 | 0x0100_0000;
    match cpu_type {
        CPU_TYPE_X86 => CpuArch::X86,
        CPU_TYPE_X86_64 => CpuArch::X86_64,
        CPU_TYPE_ARM => CpuArch::Arm32,
        CPU_TYPE_ARM64 => CpuArch::Arm64,
        other => CpuArch::Unknown(other),
    }
}

fn parse_fat_arches(data: &[u8], _byte_swapped: bool) -> Vec<CpuArch> {
    // FAT header: magic(4) + nfat_arch(4), then fat_arch structs (5×u32 = 20 bytes each).
    if data.len() < 8 {
        return Vec::new();
    }
    let nfat = read_u32_be(data, 4) as usize;
    let mut arches = Vec::with_capacity(nfat.min(16));
    for i in 0..nfat.min(16) {
        let off = 8 + i * 20;
        if off + 4 > data.len() {
            break;
        }
        let cpu_type = read_u32_be(data, off);
        arches.push(cpu_type_to_arch(cpu_type));
    }
    arches
}

// ── ZIP central directory parser ──────────────────────────────────────────────

#[derive(Debug)]
struct CdEntry {
    name: String,
    uncompressed_size: u64,
    local_offset: u64,
    compressed_size: u64,
    compression: u16,
}

fn parse_central_directory(data: &[u8]) -> Result<Vec<CdEntry>, BinaryFinderError> {
    let eocd_off = find_eocd(data).ok_or(BinaryFinderError::NotAZip)?;
    // EOCD layout (ignoring disk fields):
    // +0  sig (4)
    // +4  disk num (2)
    // +6  cd start disk (2)
    // +8  entries this disk (2)
    // +10 total entries (2)
    // +12 cd size (4)
    // +16 cd offset (4)
    // +20 comment len (2)
    if eocd_off + 22 > data.len() {
        return Err(BinaryFinderError::NotAZip);
    }
    let cd_offset = read_u32_le(data, eocd_off + 16) as usize;
    let cd_size = read_u32_le(data, eocd_off + 12) as usize;
    let total_entries = read_u16_le(data, eocd_off + 10) as usize;

    if cd_offset + cd_size > data.len() {
        return Err(BinaryFinderError::NotAZip);
    }

    let cd = &data[cd_offset..cd_offset + cd_size];
    let mut entries = Vec::with_capacity(total_entries.min(4096));
    let mut pos = 0usize;

    while pos + 46 <= cd.len() {
        let sig = read_u32_le(cd, pos);
        if sig != 0x0201_4B50 {
            break;
        }
        let compression = read_u16_le(cd, pos + 10);
        let compressed_size = u64::from(read_u32_le(cd, pos + 20));
        let uncompressed_size = u64::from(read_u32_le(cd, pos + 24));
        let name_len = read_u16_le(cd, pos + 28) as usize;
        let extra_len = read_u16_le(cd, pos + 30) as usize;
        let comment_len = read_u16_le(cd, pos + 32) as usize;
        let local_offset = u64::from(read_u32_le(cd, pos + 42));

        if pos + 46 + name_len > cd.len() {
            break;
        }
        let name = std::str::from_utf8(&cd[pos + 46..pos + 46 + name_len]).map_or_else(|_| format!("<invalid utf8 at {pos}>"), str::to_string);

        entries.push(CdEntry {
            name,
            uncompressed_size,
            local_offset,
            compressed_size,
            compression,
        });

        pos += 46 + name_len + extra_len + comment_len;
    }

    Ok(entries)
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    const EOCD_SIG: u32 = 0x0606_4B50; // ZIP64
    const EOCD32_SIG: u32 = 0x0605_4B50; // not used below; standard EOCD:
    // 0x06054B50
    const SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
    // Search backwards from the end.
    let max_comment = 65535usize;
    let start = data.len().saturating_sub(max_comment + 22);
    for i in (start..data.len().saturating_sub(3)).rev() {
        if data[i..].starts_with(&SIG) {
            return Some(i);
        }
    }
    let _ = EOCD_SIG;
    let _ = EOCD32_SIG;
    None
}

fn read_entry_data<'a>(
    ipa: &'a [u8],
    entry: &CdEntry,
) -> Result<&'a [u8], BinaryFinderError> {
    let loff = usize::try_from(entry.local_offset).map_err(|_| BinaryFinderError::Io("local_offset overflow".into()))?;
    if loff + 30 > ipa.len() {
        return Err(BinaryFinderError::Io(format!(
            "local header at {loff} out of bounds"
        )));
    }
    let name_len = read_u16_le(ipa, loff + 26) as usize;
    let extra_len = read_u16_le(ipa, loff + 28) as usize;
    let data_start = loff + 30 + name_len + extra_len;
    let data_end = data_start + usize::try_from(entry.compressed_size).map_err(|_| BinaryFinderError::Io("compressed_size overflow".into()))?;
    if data_end > ipa.len() {
        return Err(BinaryFinderError::Io("entry data out of bounds".into()));
    }
    // Only stored (compression method 0) entries can be read directly.
    if entry.compression != 0 {
        // Return a small slice sufficient for magic-number inspection from the
        // compressed stream (the first 4 bytes of a deflate stream cannot
        // coincidentally look like a Mach-O magic, so returning compressed
        // data is safe for magic-checking purposes).
        let end = (data_start + 16).min(ipa.len());
        return Ok(&ipa[data_start..end]);
    }
    Ok(&ipa[data_start..data_end])
}

// ── Byte helpers ──────────────────────────────────────────────────────────────

fn read_u32_le(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u32_be(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u16_le(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

// ── Summary helpers ───────────────────────────────────────────────────────────

/// A concise summary of binaries found in an IPA.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinarySummary {
    /// Total number of Mach-O binaries found.
    pub total: usize,
    /// Number of framework dylibs.
    pub framework_count: usize,
    /// Number of app extensions.
    pub extension_count: usize,
    /// Whether the main executable was found.
    pub main_found: bool,
    /// Architectures present (deduplicated, stringified).
    pub architectures: Vec<String>,
    /// Map of binary name → size in bytes.
    pub sizes: HashMap<String, u64>,
}

/// Build a [`BinarySummary`] from a list of [`AppBinary`] items.
#[must_use]
pub fn summarise_binaries(binaries: &[AppBinary]) -> BinarySummary {
    let mut arch_set: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut sizes = HashMap::new();

    for b in binaries {
        arch_set.insert(b.arch.to_string());
        sizes.insert(b.path.name.clone(), b.size);
    }

    BinarySummary {
        total: binaries.len(),
        framework_count: binaries.iter().filter(|b| b.is_framework()).count(),
        extension_count: binaries.iter().filter(|b| b.is_extension()).count(),
        main_found: binaries.iter().any(AppBinary::is_main),
        architectures: {
            let mut v: Vec<String> = arch_set.into_iter().collect();
            v.sort();
            v
        },
        sizes,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_macho_header(magic: u32, cpu_type: u32, filetype: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&magic.to_le_bytes());
        v.extend_from_slice(&cpu_type.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // cpu_subtype
        v.extend_from_slice(&filetype.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // ncmds
        v.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v
    }

    #[test]
    fn test_is_macho_magic() {
        assert!(is_macho_magic(MH_MAGIC));
        assert!(is_macho_magic(MH_MAGIC_64));
        assert!(is_macho_magic(FAT_MAGIC));
        assert!(!is_macho_magic(0x0000_0000));
        assert!(!is_macho_magic(0xDEAD_BEEF));
    }

    #[test]
    fn test_cpu_type_to_arch_arm64() {
        let arch = cpu_type_to_arch(12 | 0x0100_0000);
        assert!(matches!(arch, CpuArch::Arm64));
    }

    #[test]
    fn test_cpu_type_to_arch_x86_64() {
        let arch = cpu_type_to_arch(7 | 0x0100_0000);
        assert!(matches!(arch, CpuArch::X86_64));
    }

    #[test]
    fn test_macho_header_arm64() {
        let data = make_macho_header(MH_MAGIC_64, 12 | 0x0100_0000, 2);
        let (arch, mach_type, is_fat, is_64, _) = parse_macho_header(&data, MH_MAGIC_64);
        assert!(matches!(arch, CpuArch::Arm64));
        assert!(matches!(mach_type, MachOType::Execute));
        assert!(!is_fat);
        assert!(is_64);
    }

    #[test]
    fn test_strip_payload_prefix() {
        let result = strip_payload_prefix("Payload/MyApp.app/Frameworks/Foo.framework/Foo");
        assert_eq!(result, Some("Frameworks/Foo.framework/Foo"));
    }

    #[test]
    fn test_candidate_path_filter() {
        assert!(IpaBinaryFinder::is_candidate_path("Payload/App.app/App"));
        assert!(!IpaBinaryFinder::is_candidate_path("Payload/App.app/Assets.car"));
        assert!(!IpaBinaryFinder::is_candidate_path("Payload/App.app/Info.plist"));
        assert!(!IpaBinaryFinder::is_candidate_path("Payload/App.app/"));
        assert!(!IpaBinaryFinder::is_candidate_path("META-INF/manifest.xml"));
    }

    #[test]
    fn test_arch_display() {
        assert_eq!(CpuArch::Arm64.to_string(), "arm64");
        assert_eq!(CpuArch::X86_64.to_string(), "x86_64");
        let fat = CpuArch::Fat(vec![CpuArch::Arm64, CpuArch::X86_64]);
        assert_eq!(fat.to_string(), "fat(arm64+x86_64)");
    }

    #[test]
    fn test_macho_type_from_u32() {
        assert!(matches!(MachOType::from_u32(2), MachOType::Execute));
        assert!(matches!(MachOType::from_u32(6), MachOType::Dylib));
        assert!(matches!(MachOType::from_u32(8), MachOType::Bundle));
        assert!(matches!(MachOType::from_u32(99), MachOType::Unknown(99)));
    }

    #[test]
    fn test_summarise_empty() {
        let summary = summarise_binaries(&[]);
        assert_eq!(summary.total, 0);
        assert!(!summary.main_found);
    }

    #[test]
    fn test_binary_is_main_heuristic() {
        let path = BinaryPath {
            zip_path: "Payload/App.app/App".into(),
            name: "App".into(),
            bundle_relative: "App".into(),
            is_main_executable: true,
            is_framework: false,
            is_plugin: false,
            uncompressed_size: 1024,
            local_offset: 0,
        };
        let bin = AppBinary {
            path,
            magic: MH_MAGIC_64,
            is_64bit: true,
            is_byte_swapped: false,
            is_fat: false,
            arch: CpuArch::Arm64,
            mach_type: MachOType::Execute,
            size: 1024,
        };
        assert!(bin.is_main());
        assert!(!bin.is_framework());
        assert!(!bin.is_extension());
    }

    #[test]
    fn test_serde_roundtrip() {
        let b = BinarySummary {
            total: 3,
            framework_count: 2,
            extension_count: 0,
            main_found: true,
            architectures: vec!["arm64".into()],
            sizes: HashMap::from([("App".into(), 1_000_000)]),
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: BinarySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total, 3);
        assert_eq!(back.framework_count, 2);
    }
}
