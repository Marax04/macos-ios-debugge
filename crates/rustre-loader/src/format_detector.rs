//! Binary format auto-detection with 50+ magic-byte signatures.
//!
//! [`FormatDetector`] inspects raw bytes and returns a [`DetectionResult`]
//! carrying the detected [`BinaryFormatKind`], a confidence score, and optional
//! architecture / OS hints.  The `detect_from_bytes` path is O(n) in the number
//! of registered signatures and performs no I/O.

use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// BinaryFormatKind
// ─────────────────────────────────────────────────────────────────────────────

/// All binary formats that [`FormatDetector`] can identify.
///
/// Variants are grouped loosely by origin (OS, VM, embedded, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BinaryFormatKind {
    // ── Native executables ───────────────────────────────────────────────────
    /// ELF 32-bit little-endian.
    Elf32Le,
    /// ELF 32-bit big-endian.
    Elf32Be,
    /// ELF 64-bit little-endian.
    Elf64Le,
    /// ELF 64-bit big-endian.
    Elf64Be,
    /// Portable Executable (Windows) — PE32 or PE32+.
    Pe,
    /// Mach-O 32-bit little-endian.
    MachoLe32,
    /// Mach-O 64-bit little-endian.
    MachoLe64,
    /// Mach-O 32-bit big-endian.
    MachoBe32,
    /// Mach-O 64-bit big-endian.
    MachoBe64,
    /// Mach-O fat / universal binary.
    FatMacho,

    // ── Mobile / embedded ───────────────────────────────────────────────────
    /// Android Dalvik Executable.
    AndroidDex,
    /// Android Package (ZIP containing `classes.dex`).
    Apk,
    /// Nintendo Switch NRO (homebrew).
    Nro,
    /// Nintendo Switch NSO (official).
    Nso,
    /// Xbox 360 / Xbox One executable.
    Xex,
    /// `PlayStation` `SELF` / `EBOOT.BIN`.
    Self_,

    // ── JVM / managed ────────────────────────────────────────────────────────
    /// Java `.class` file.
    JavaClass,
    /// JAR archive (ZIP + `META-INF/MANIFEST.MF`).
    Jar,
    /// .NET / CIL PE image.
    DotNet,

    // ── WebAssembly ──────────────────────────────────────────────────────────
    /// WebAssembly binary module.
    Wasm,

    // ── Bytecode / scripting ─────────────────────────────────────────────────
    /// Standard Lua bytecode.
    LuaBytecode,
    /// `LuaJIT` bytecode.
    LuaJit,
    /// `CPython` bytecode (`.pyc`).
    PythonPyc,

    // ── Archives / containers ────────────────────────────────────────────────
    /// ZIP archive (also APK / JAR / DOCX / …).
    Zip,
    /// 7-Zip archive.
    SevenZip,
    /// RAR archive.
    Rar,
    /// GZIP-compressed data.
    Gzip,
    /// BZIP2-compressed data.
    Bzip2,
    /// XZ/LZMA-compressed data.
    Xz,
    /// Zstd-compressed data.
    Zstd,
    /// LZ4 frame format.
    Lz4,
    /// TAR archive.
    Tar,
    /// Cabinet (Windows `.cab`) archive.
    MsCab,

    // ── Firmware / raw formats ────────────────────────────────────────────────
    /// Intel HEX text records.
    IntelHex,
    /// Motorola S-Record text format.
    MotorolaSrec,
    /// Flat / raw binary (no identifying magic).
    FlatBinary,

    // ── Documents / media (common false-positive vectors) ────────────────────
    /// PDF document.
    Pdf,
    /// OLE Compound Document (DOC, XLS, PPT …).
    OleCompoundDoc,
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// GIF image.
    Gif,
    /// RIFF-based container (WAV, AVI, …).
    Riff,

    // ── Misc ─────────────────────────────────────────────────────────────────
    /// ARM `IMage` (U-Boot legacy image).
    UBootImage,
    /// `SquashFS` filesystem image.
    Squashfs,
    /// Ext2/3/4 filesystem image.
    Ext2Fs,
    /// ISO 9660 CD-ROM image (checked at offset 32 768).
    Iso9660,
    /// LLVM bitcode.
    LlvmBitcode,
    /// PCAP packet capture.
    Pcap,
    /// PCAP-NG packet capture.
    PcapNg,

    /// Unrecognised format.
    Unknown,
}

impl std::fmt::Display for BinaryFormatKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Elf32Le => "ELF-32LE",
            Self::Elf32Be => "ELF-32BE",
            Self::Elf64Le => "ELF-64LE",
            Self::Elf64Be => "ELF-64BE",
            Self::Pe => "PE",
            Self::MachoLe32 => "Mach-O LE32",
            Self::MachoLe64 => "Mach-O LE64",
            Self::MachoBe32 => "Mach-O BE32",
            Self::MachoBe64 => "Mach-O BE64",
            Self::FatMacho => "Mach-O Fat",
            Self::AndroidDex => "Android DEX",
            Self::Apk => "Android APK",
            Self::Nro => "Nintendo NRO",
            Self::Nso => "Nintendo NSO",
            Self::Xex => "Xbox XEX",
            Self::Self_ => "PlayStation SELF",
            Self::JavaClass => "Java Class",
            Self::Jar => "JAR",
            Self::DotNet => ".NET/CIL",
            Self::Wasm => "WebAssembly",
            Self::LuaBytecode => "Lua Bytecode",
            Self::LuaJit => "LuaJIT Bytecode",
            Self::PythonPyc => "Python Bytecode",
            Self::Zip => "ZIP",
            Self::SevenZip => "7-Zip",
            Self::Rar => "RAR",
            Self::Gzip => "GZIP",
            Self::Bzip2 => "BZIP2",
            Self::Xz => "XZ",
            Self::Zstd => "Zstd",
            Self::Lz4 => "LZ4",
            Self::Tar => "TAR",
            Self::MsCab => "Cabinet",
            Self::IntelHex => "Intel HEX",
            Self::MotorolaSrec => "Motorola S-Record",
            Self::FlatBinary => "Flat Binary",
            Self::Pdf => "PDF",
            Self::OleCompoundDoc => "OLE Compound Doc",
            Self::Png => "PNG",
            Self::Jpeg => "JPEG",
            Self::Gif => "GIF",
            Self::Riff => "RIFF",
            Self::UBootImage => "U-Boot Image",
            Self::Squashfs => "SquashFS",
            Self::Ext2Fs => "ext2/3/4 FS",
            Self::Iso9660 => "ISO 9660",
            Self::LlvmBitcode => "LLVM Bitcode",
            Self::Pcap => "PCAP",
            Self::PcapNg => "PCAP-NG",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DetectionResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a format-detection operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    /// Identified format.
    pub format: BinaryFormatKind,
    /// Confidence score: 255 = certain magic match, 128 = heuristic, 0 = none.
    pub confidence: u8,
    /// Optional architecture hint, e.g. `"x86_64"`, `"arm64"`.
    pub architecture_hint: Option<String>,
    /// Optional OS hint, e.g. `"linux"`, `"windows"`, `"darwin"`.
    pub os_hint: Option<String>,
    /// Human-readable reason string (for debugging).
    pub reason: String,
}

impl DetectionResult {
    /// Construct a certain detection (confidence 255).
    fn certain(format: BinaryFormatKind, reason: impl Into<String>) -> Self {
        Self {
            format,
            confidence: 255,
            architecture_hint: None,
            os_hint: None,
            reason: reason.into(),
        }
    }

    /// Set the architecture hint on the result.
    fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.architecture_hint = Some(arch.into());
        self
    }

    /// Set the OS hint on the result.
    fn with_os(mut self, os: impl Into<String>) -> Self {
        self.os_hint = Some(os.into());
        self
    }

    /// Set a lower confidence.
    const fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }

    /// Unknown-format result.
    fn unknown() -> Self {
        Self {
            format: BinaryFormatKind::Unknown,
            confidence: 0,
            architecture_hint: None,
            os_hint: None,
            reason: "no matching signature".into(),
        }
    }

    /// Return `true` when the format is known (not [`BinaryFormatKind::Unknown`]).
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.format != BinaryFormatKind::Unknown
    }

    /// Return `true` when confidence is at or above `threshold`.
    #[must_use]
    pub const fn is_confident(&self, threshold: u8) -> bool {
        self.confidence >= threshold
    }
}

impl std::fmt::Display for DetectionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (confidence={})", self.format, self.confidence)?;
        if let Some(arch) = &self.architecture_hint {
            write!(f, " arch={arch}")?;
        }
        if let Some(os) = &self.os_hint {
            write!(f, " os={os}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FormatDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Stateless binary format detector with 50+ magic-byte signatures.
///
/// All detection is allocation-free when the input slice is already in memory.
/// Call [`detect_from_bytes`](Self::detect_from_bytes) for the fast path or
/// [`detect_from_path`](Self::detect_from_path) to read a file automatically.
#[derive(Debug, Default, Clone, Copy)]
pub struct FormatDetector;

impl FormatDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Inspect `bytes` and return the best [`DetectionResult`].
    ///
    /// Returns [`BinaryFormatKind::Unknown`] when no signature matches.
    #[must_use]
    pub fn detect_from_bytes(&self, bytes: &[u8]) -> DetectionResult {
        if bytes.is_empty() {
            return DetectionResult::unknown();
        }
        Self::detect_executable_format(bytes)
            .or_else(|| Self::detect_archive_format(bytes))
            .or_else(|| Self::detect_media_format(bytes))
            .or_else(|| Self::detect_misc_format(bytes))
            .or_else(|| Self::detect_embedded_format(bytes))
            .unwrap_or_else(DetectionResult::unknown)
    }

    fn detect_executable_format(bytes: &[u8]) -> Option<DetectionResult> {
        // ── ELF ──────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
            return Some(Self::classify_elf(bytes));
        }
        // ── PE / MZ ──────────────────────────────────────────────────────────
        if bytes.starts_with(b"MZ") {
            return Some(DetectionResult::certain(BinaryFormatKind::Pe, "MZ magic").with_os("windows"));
        }
        // ── Mach-O ──────────────────────────────────────────────────────────
        if bytes.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
            return Some(DetectionResult::certain(BinaryFormatKind::MachoLe64, "Mach-O LE64 magic").with_os("darwin"));
        }
        if bytes.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
            return Some(DetectionResult::certain(BinaryFormatKind::MachoLe32, "Mach-O LE32 magic").with_os("darwin"));
        }
        if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) {
            return Some(DetectionResult::certain(BinaryFormatKind::MachoBe64, "Mach-O BE64 magic").with_os("darwin"));
        }
        if bytes.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) {
            return Some(DetectionResult::certain(BinaryFormatKind::MachoBe32, "Mach-O BE32 magic").with_os("darwin"));
        }
        // ── CAFEBABE — Fat Mach-O or Java Class ──────────────────────────────
        if bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
            return Some(Self::classify_cafebabe(bytes));
        }
        // ── WebAssembly ──────────────────────────────────────────────────────
        if bytes.starts_with(&[0x00, 0x61, 0x73, 0x6D]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Wasm, "Wasm magic \\0asm").with_arch("wasm32"));
        }
        // ── Android DEX ──────────────────────────────────────────────────────
        if bytes.starts_with(b"dex\n") {
            return Some(DetectionResult::certain(BinaryFormatKind::AndroidDex, "DEX magic").with_os("android").with_arch("dex"));
        }
        None
    }

    fn detect_archive_format(bytes: &[u8]) -> Option<DetectionResult> {
        // ── ZIP / JAR / APK ─────────────────────────────────────────────────
        if bytes.starts_with(&[b'P', b'K', 0x03, 0x04])
            || bytes.starts_with(&[b'P', b'K', 0x05, 0x06])
            || bytes.starts_with(&[b'P', b'K', 0x07, 0x08])
        {
            return Some(DetectionResult::certain(BinaryFormatKind::Zip, "PK ZIP magic"));
        }
        // ── 7-Zip ────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
            return Some(DetectionResult::certain(BinaryFormatKind::SevenZip, "7z magic"));
        }
        // ── RAR ──────────────────────────────────────────────────────────────
        if bytes.starts_with(b"Rar!") {
            return Some(DetectionResult::certain(BinaryFormatKind::Rar, "RAR magic"));
        }
        // ── GZIP ─────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x1F, 0x8B]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Gzip, "GZIP magic"));
        }
        // ── BZIP2 ────────────────────────────────────────────────────────────
        if bytes.starts_with(b"BZh") {
            return Some(DetectionResult::certain(BinaryFormatKind::Bzip2, "BZIP2 magic"));
        }
        // ── XZ ───────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Xz, "XZ stream magic"));
        }
        // ── Zstd ─────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Zstd, "Zstd frame magic"));
        }
        // ── LZ4 ──────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Lz4, "LZ4 frame magic"));
        }
        // ── Microsoft Cabinet ────────────────────────────────────────────────
        if bytes.starts_with(b"MSCF") {
            return Some(DetectionResult::certain(BinaryFormatKind::MsCab, "MSCF Cabinet magic").with_os("windows"));
        }
        // ── TAR ─────────────────────────────────────────────────────────────
        if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
            return Some(DetectionResult::certain(BinaryFormatKind::Tar, "ustar magic").with_confidence(200));
        }
        None
    }

    fn detect_media_format(bytes: &[u8]) -> Option<DetectionResult> {
        // ── PNG ──────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Png, "PNG magic"));
        }
        // ── JPEG ─────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Jpeg, "JPEG SOI marker"));
        }
        // ── GIF ──────────────────────────────────────────────────────────────
        if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            return Some(DetectionResult::certain(BinaryFormatKind::Gif, "GIF magic"));
        }
        // ── RIFF (WAV, AVI, …) ───────────────────────────────────────────────
        if bytes.starts_with(b"RIFF") && bytes.len() >= 12 {
            return Some(DetectionResult::certain(BinaryFormatKind::Riff, "RIFF magic"));
        }
        None
    }

    fn detect_misc_format(bytes: &[u8]) -> Option<DetectionResult> {
        // ── Lua ──────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x1B, b'L', b'u', b'a']) {
            return Some(DetectionResult::certain(BinaryFormatKind::LuaBytecode, "Lua magic"));
        }
        if bytes.starts_with(&[0x1B, b'L', b'J']) {
            return Some(DetectionResult::certain(BinaryFormatKind::LuaJit, "LuaJIT magic"));
        }
        // ── Python ──────────────────────────────────────────────────────────
        if bytes.len() >= 4 && bytes[2] == 0x0D && bytes[3] == 0x0A {
            let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
            if matches!(
                magic,
                62211 | 62213 | 62215 | 62218 | 62221 | 62231 | 62234 | 62235
                    | 62243 | 62252 | 62261 | 62271 | 62281 | 62291 | 62301
                    | 62311 | 62321 | 62331
                    | 3390 | 3391 | 3392 | 3393 | 3394 | 3400 | 3401
                    | 3410 | 3411 | 3412 | 3413 | 3420 | 3421 | 3422 | 3423
                    | 3430 | 3431 | 3432 | 3433 | 3440 | 3450 | 3451
                    | 3460 | 3461 | 3462 | 3470 | 3480 | 3490 | 3491 | 3492
                    | 3493 | 3494 | 3495
            ) {
                return Some(DetectionResult::certain(BinaryFormatKind::PythonPyc, "Python .pyc magic").with_arch("cpython"));
            }
        }
        // ── PDF ──────────────────────────────────────────────────────────────
        if bytes.starts_with(b"%PDF") {
            return Some(DetectionResult::certain(BinaryFormatKind::Pdf, "%PDF magic"));
        }
        // ── OLE Compound Document ────────────────────────────────────────────
        if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
            return Some(DetectionResult::certain(BinaryFormatKind::OleCompoundDoc, "OLE Compound Document magic").with_os("windows"));
        }
        // ── LLVM Bitcode ─────────────────────────────────────────────────────
        if bytes.starts_with(&[0x42, 0x43, 0xC0, 0xDE]) {
            return Some(DetectionResult::certain(BinaryFormatKind::LlvmBitcode, "LLVM bitcode magic"));
        }
        // ── PCAP ─────────────────────────────────────────────────────────────
        if bytes.starts_with(&[0xD4, 0xC3, 0xB2, 0xA1]) || bytes.starts_with(&[0xA1, 0xB2, 0xC3, 0xD4]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Pcap, "PCAP magic"));
        }
        // ── PCAP-NG ──────────────────────────────────────────────────────────
        if bytes.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]) {
            return Some(DetectionResult::certain(BinaryFormatKind::PcapNg, "PCAP-NG magic"));
        }
        None
    }

    fn detect_embedded_format(bytes: &[u8]) -> Option<DetectionResult> {
        // ── U-Boot legacy image ──────────────────────────────────────────────
        if bytes.starts_with(&[0x27, 0x05, 0x19, 0x56]) {
            return Some(DetectionResult::certain(BinaryFormatKind::UBootImage, "U-Boot magic").with_os("embedded"));
        }
        // ── SquashFS ─────────────────────────────────────────────────────────
        if bytes.starts_with(b"sqsh") || bytes.starts_with(b"hsqs") {
            return Some(DetectionResult::certain(BinaryFormatKind::Squashfs, "SquashFS magic"));
        }
        // ── ext2/3/4 ─────────────────────────────────────────────────────────
        if bytes.len() >= 1082 && bytes[1080] == 0x53 && bytes[1081] == 0xEF {
            return Some(DetectionResult::certain(BinaryFormatKind::Ext2Fs, "ext2/3/4 superblock magic").with_os("linux"));
        }
        // ── ISO 9660 (magic at offset 32 768) ────────────────────────────────
        if bytes.len() >= 32_773 && &bytes[32_769..32_774] == b"CD001" {
            return Some(DetectionResult::certain(BinaryFormatKind::Iso9660, "ISO 9660 CD001 magic"));
        }
        // ── Nintendo Switch NRO ──────────────────────────────────────────────
        if bytes.len() >= 16 && &bytes[0x10..0x14] == b"NRO0" {
            return Some(DetectionResult::certain(BinaryFormatKind::Nro, "NRO0 magic").with_os("horizon").with_arch("arm64"));
        }
        // ── Nintendo Switch NSO ──────────────────────────────────────────────
        if bytes.starts_with(b"NSO0") {
            return Some(DetectionResult::certain(BinaryFormatKind::Nso, "NSO0 magic").with_os("horizon").with_arch("arm64"));
        }
        // ── Xbox XEX ─────────────────────────────────────────────────────────
        if bytes.starts_with(b"XEX2") || bytes.starts_with(b"XEX1") {
            return Some(DetectionResult::certain(BinaryFormatKind::Xex, "XEX magic").with_os("xbox"));
        }
        // ── PlayStation SELF ─────────────────────────────────────────────────
        if bytes.starts_with(&[0x4F, 0x15, 0x3D, 0x1D]) {
            return Some(DetectionResult::certain(BinaryFormatKind::Self_, "PS SELF magic").with_os("orbis"));
        }
        // ── Intel HEX ────────────────────────────────────────────────────────
        if bytes.first() == Some(&b':') && bytes.get(1).is_some_and(u8::is_ascii_hexdigit) {
            return Some(DetectionResult {
                format: BinaryFormatKind::IntelHex,
                confidence: 180,
                architecture_hint: None,
                os_hint: Some("embedded".into()),
                reason: "Intel HEX ':' leader".into(),
            });
        }
        // ── Motorola S-Record ────────────────────────────────────────────────
        if bytes.len() >= 2 && bytes[0] == b'S' && bytes[1].is_ascii_digit() {
            return Some(DetectionResult {
                format: BinaryFormatKind::MotorolaSrec,
                confidence: 180,
                architecture_hint: None,
                os_hint: Some("embedded".into()),
                reason: "S-record 'S[0-9]' leader".into(),
            });
        }
        None
    }

    /// Read up to 64 KiB from `path` and call [`detect_from_bytes`](Self::detect_from_bytes).
    ///
    /// For formats whose signature lives deep in the file (ISO 9660, ext2/3/4),
    /// the function reads more bytes as needed.
    ///
    /// # Errors
    /// Returns an [`std::io::Error`] if the file cannot be opened or read.
    pub fn detect_from_path(&self, path: impl AsRef<Path>) -> std::io::Result<DetectionResult> {
        // ISO 9660 needs at least 32 773 bytes; ext2/3/4 needs 1082.
        // Read 64 KiB to cover both.
        const READ_SIZE: usize = 65_536;
        use std::io::Read as _;
        let path = path.as_ref();
        let mut f = std::fs::File::open(path)?;
        let mut buf = Vec::with_capacity(READ_SIZE);
        f.by_ref().take(u64::try_from(READ_SIZE).unwrap_or(u64::MAX)).read_to_end(&mut buf)?;

        let mut result = self.detect_from_bytes(&buf);

        // Supplement with extension-based hints when confidence is low.
        if result.confidence < 180
            && let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                result = Self::refine_with_extension(result, ext);
            }

        Ok(result)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn classify_elf(bytes: &[u8]) -> DetectionResult {
        if bytes.len() < 6 {
            return DetectionResult::unknown();
        }
        let class = bytes[4]; // 1 = 32-bit, 2 = 64-bit
        let endian = bytes[5]; // 1 = LE, 2 = BE

        let (format, arch_hint) = match (class, endian) {
            (1, 1) => (BinaryFormatKind::Elf32Le, Self::elf_arch_hint(bytes)),
            (1, 2) => (BinaryFormatKind::Elf32Be, Self::elf_arch_hint(bytes)),
            (2, 1) => (BinaryFormatKind::Elf64Le, Self::elf_arch_hint(bytes)),
            (2, 2) => (BinaryFormatKind::Elf64Be, Self::elf_arch_hint(bytes)),
            _ => return DetectionResult::unknown(),
        };

        let mut r = DetectionResult::certain(format, "ELF magic").with_os("linux");
        r.architecture_hint = arch_hint;
        r
    }

    fn elf_arch_hint(bytes: &[u8]) -> Option<String> {
        if bytes.len() < 20 {
            return None;
        }
        // e_machine at offset 18 (LE) / 19 (BE, but still 16-bit LE field in the struct).
        let endian = bytes[5];
        let e_machine = if endian == 1 {
            u16::from_le_bytes([bytes[18], bytes[19]])
        } else {
            u16::from_be_bytes([bytes[18], bytes[19]])
        };
        let hint = match e_machine {
            0x0003 => "x86",
            0x003E => "x86_64",
            0x0028 => "arm",
            0x00B7 if bytes.len() >= 20 && bytes[4] == 2 => "arm64",
            // Fallback when EI_CLASS is missing/32-bit: still identify AArch64 by machine code.
            0x00B7 => "arm64",
            0x0008 => "mips",
            0x0014 => "powerpc",
            0x0015 => "powerpc64",
            0x00F3 => "riscv",
            _ => return None,
        };
        Some(hint.into())
    }

    fn classify_cafebabe(bytes: &[u8]) -> DetectionResult {
        if bytes.len() >= 8 {
            let major = u16::from_be_bytes([bytes[6], bytes[7]]);
            if (44..=80).contains(&major) {
                return DetectionResult::certain(
                    BinaryFormatKind::JavaClass,
                    "CAFEBABE + Java major version",
                )
                .with_arch("jvm")
                .with_os("jvm");
            }
        }
        DetectionResult::certain(BinaryFormatKind::FatMacho, "CAFEBABE Mach-O fat")
            .with_os("darwin")
    }

    fn refine_with_extension(mut result: DetectionResult, ext: &str) -> DetectionResult {
        let lower = ext.to_ascii_lowercase();
        match lower.as_str() {
            "dex" if result.format == BinaryFormatKind::Unknown => {
                result.format = BinaryFormatKind::AndroidDex;
                result.confidence = 100;
            }
            "apk" if result.format == BinaryFormatKind::Zip => {
                result.format = BinaryFormatKind::Apk;
            }
            "jar" if result.format == BinaryFormatKind::Zip => {
                result.format = BinaryFormatKind::Jar;
            }
            "wasm" if result.format == BinaryFormatKind::Unknown => {
                result.format = BinaryFormatKind::Wasm;
                result.confidence = 90;
            }
            "hex" if result.format == BinaryFormatKind::Unknown => {
                result.format = BinaryFormatKind::IntelHex;
                result.confidence = 90;
            }
            "bin" | "raw" if result.format == BinaryFormatKind::Unknown => {
                result.format = BinaryFormatKind::FlatBinary;
                result.confidence = 50;
            }
            _ => {}
        }
        result
    }

    // ── Convenience predicates ────────────────────────────────────────────────

    /// Return `true` if `bytes` is any ELF variant.
    #[must_use]
    pub fn is_elf(&self, bytes: &[u8]) -> bool {
        matches!(
            self.detect_from_bytes(bytes).format,
            BinaryFormatKind::Elf32Le
                | BinaryFormatKind::Elf32Be
                | BinaryFormatKind::Elf64Le
                | BinaryFormatKind::Elf64Be
        )
    }

    /// Return `true` if `bytes` is a PE image.
    #[must_use]
    pub fn is_pe(&self, bytes: &[u8]) -> bool {
        self.detect_from_bytes(bytes).format == BinaryFormatKind::Pe
    }

    /// Return `true` if `bytes` is any Mach-O variant.
    #[must_use]
    pub fn is_macho(&self, bytes: &[u8]) -> bool {
        matches!(
            self.detect_from_bytes(bytes).format,
            BinaryFormatKind::MachoLe32
                | BinaryFormatKind::MachoLe64
                | BinaryFormatKind::MachoBe32
                | BinaryFormatKind::MachoBe64
                | BinaryFormatKind::FatMacho
        )
    }

    /// Return `true` if `bytes` is a WebAssembly module.
    #[must_use]
    pub fn is_wasm(&self, bytes: &[u8]) -> bool {
        self.detect_from_bytes(bytes).format == BinaryFormatKind::Wasm
    }

    /// Return `true` if `bytes` looks like an archive or compressed container.
    #[must_use]
    pub fn is_archive(&self, bytes: &[u8]) -> bool {
        matches!(
            self.detect_from_bytes(bytes).format,
            BinaryFormatKind::Zip
                | BinaryFormatKind::SevenZip
                | BinaryFormatKind::Rar
                | BinaryFormatKind::Gzip
                | BinaryFormatKind::Bzip2
                | BinaryFormatKind::Xz
                | BinaryFormatKind::Zstd
                | BinaryFormatKind::Lz4
                | BinaryFormatKind::Tar
                | BinaryFormatKind::MsCab
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn det(bytes: &[u8]) -> DetectionResult {
        FormatDetector::new().detect_from_bytes(bytes)
    }

    // ── ELF ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_elf64le() {
        let r = det(&[
            0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3E, 0,
        ]);
        assert_eq!(r.format, BinaryFormatKind::Elf64Le);
        assert_eq!(r.confidence, 255);
        assert_eq!(r.os_hint.as_deref(), Some("linux"));
        assert_eq!(r.architecture_hint.as_deref(), Some("x86_64"));
    }

    #[test]
    fn test_elf32be() {
        let mut bytes = vec![0u8; 20];
        bytes[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        bytes[4] = 1; // 32-bit
        bytes[5] = 2; // BE
        let r = det(&bytes);
        assert_eq!(r.format, BinaryFormatKind::Elf32Be);
    }

    #[test]
    fn test_elf_is_known() {
        let r = det(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(r.is_known());
    }

    // ── PE ────────────────────────────────────────────────────────────────────

    #[test]
    fn test_pe() {
        let r = det(b"MZ\x90\x00");
        assert_eq!(r.format, BinaryFormatKind::Pe);
        assert_eq!(r.os_hint.as_deref(), Some("windows"));
    }

    // ── Mach-O ────────────────────────────────────────────────────────────────

    #[test]
    fn test_macho_le64() {
        let r = det(&[0xCF, 0xFA, 0xED, 0xFE]);
        assert_eq!(r.format, BinaryFormatKind::MachoLe64);
    }

    #[test]
    fn test_macho_le32() {
        let r = det(&[0xCE, 0xFA, 0xED, 0xFE]);
        assert_eq!(r.format, BinaryFormatKind::MachoLe32);
    }

    #[test]
    fn test_macho_be32() {
        let r = det(&[0xFE, 0xED, 0xFA, 0xCE]);
        assert_eq!(r.format, BinaryFormatKind::MachoBe32);
    }

    #[test]
    fn test_macho_be64() {
        let r = det(&[0xFE, 0xED, 0xFA, 0xCF]);
        assert_eq!(r.format, BinaryFormatKind::MachoBe64);
    }

    #[test]
    fn test_fat_macho() {
        // CAFEBABE with major version 0 (not Java)
        let r = det(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 1]);
        assert_eq!(r.format, BinaryFormatKind::FatMacho);
    }

    #[test]
    fn test_java_class() {
        // Java 11 class: major = 55 = 0x0037
        let r = det(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 55]);
        assert_eq!(r.format, BinaryFormatKind::JavaClass);
    }

    // ── Wasm ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_wasm() {
        let r = det(&[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(r.format, BinaryFormatKind::Wasm);
        assert_eq!(r.architecture_hint.as_deref(), Some("wasm32"));
    }

    // ── Android DEX ──────────────────────────────────────────────────────────

    #[test]
    fn test_dex() {
        let r = det(b"dex\n035\0");
        assert_eq!(r.format, BinaryFormatKind::AndroidDex);
    }

    // ── Archives ─────────────────────────────────────────────────────────────

    #[test]
    fn test_zip() {
        let r = det(&[b'P', b'K', 0x03, 0x04, 0x00]);
        assert_eq!(r.format, BinaryFormatKind::Zip);
    }

    #[test]
    fn test_gzip() {
        let r = det(&[0x1F, 0x8B, 0x08]);
        assert_eq!(r.format, BinaryFormatKind::Gzip);
    }

    #[test]
    fn test_bzip2() {
        let r = det(b"BZh91");
        assert_eq!(r.format, BinaryFormatKind::Bzip2);
    }

    #[test]
    fn test_xz() {
        let r = det(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
        assert_eq!(r.format, BinaryFormatKind::Xz);
    }

    #[test]
    fn test_zstd() {
        let r = det(&[0x28, 0xB5, 0x2F, 0xFD, 0x04]);
        assert_eq!(r.format, BinaryFormatKind::Zstd);
    }

    #[test]
    fn test_lz4() {
        let r = det(&[0x04, 0x22, 0x4D, 0x18]);
        assert_eq!(r.format, BinaryFormatKind::Lz4);
    }

    #[test]
    fn test_rar() {
        let r = det(b"Rar!\x1A\x07\x00");
        assert_eq!(r.format, BinaryFormatKind::Rar);
    }

    #[test]
    fn test_7z() {
        let r = det(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
        assert_eq!(r.format, BinaryFormatKind::SevenZip);
    }

    // ── Images / documents ────────────────────────────────────────────────────

    #[test]
    fn test_png() {
        let r = det(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(r.format, BinaryFormatKind::Png);
    }

    #[test]
    fn test_jpeg() {
        let r = det(&[0xFF, 0xD8, 0xFF, 0xE0]);
        assert_eq!(r.format, BinaryFormatKind::Jpeg);
    }

    #[test]
    fn test_gif() {
        let r = det(b"GIF89a");
        assert_eq!(r.format, BinaryFormatKind::Gif);
    }

    #[test]
    fn test_pdf() {
        let r = det(b"%PDF-1.7\n");
        assert_eq!(r.format, BinaryFormatKind::Pdf);
    }

    #[test]
    fn test_ole() {
        let r = det(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        assert_eq!(r.format, BinaryFormatKind::OleCompoundDoc);
    }

    // ── Scripting ─────────────────────────────────────────────────────────────

    #[test]
    fn test_lua() {
        let r = det(&[0x1B, b'L', b'u', b'a', 0x53]);
        assert_eq!(r.format, BinaryFormatKind::LuaBytecode);
    }

    #[test]
    fn test_luajit() {
        let r = det(&[0x1B, b'L', b'J', 0x02]);
        assert_eq!(r.format, BinaryFormatKind::LuaJit);
    }

    // ── Firmware / hex ────────────────────────────────────────────────────────

    #[test]
    fn test_intel_hex() {
        let r = det(b":10000000....");
        assert_eq!(r.format, BinaryFormatKind::IntelHex);
    }

    #[test]
    fn test_srec() {
        let r = det(b"S0...");
        assert_eq!(r.format, BinaryFormatKind::MotorolaSrec);
    }

    #[test]
    fn test_uboot() {
        let r = det(&[0x27, 0x05, 0x19, 0x56]);
        assert_eq!(r.format, BinaryFormatKind::UBootImage);
    }

    #[test]
    fn test_squashfs() {
        let r = det(b"sqsh");
        assert_eq!(r.format, BinaryFormatKind::Squashfs);
    }

    // ── LLVM / capture ────────────────────────────────────────────────────────

    #[test]
    fn test_llvm_bitcode() {
        let r = det(&[0x42, 0x43, 0xC0, 0xDE]);
        assert_eq!(r.format, BinaryFormatKind::LlvmBitcode);
    }

    #[test]
    fn test_pcap() {
        let r = det(&[0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(r.format, BinaryFormatKind::Pcap);
    }

    #[test]
    fn test_pcapng() {
        let r = det(&[0x0A, 0x0D, 0x0D, 0x0A]);
        assert_eq!(r.format, BinaryFormatKind::PcapNg);
    }

    // ── Nintendo / Xbox / PlayStation ─────────────────────────────────────────

    #[test]
    fn test_nso() {
        let r = det(b"NSO0\x00\x00\x00\x00");
        assert_eq!(r.format, BinaryFormatKind::Nso);
    }

    #[test]
    fn test_xex2() {
        let r = det(b"XEX2\x00\x00\x00\x00");
        assert_eq!(r.format, BinaryFormatKind::Xex);
    }

    // ── Cabinet ───────────────────────────────────────────────────────────────

    #[test]
    fn test_mscab() {
        let r = det(b"MSCF\x00\x00\x00\x00");
        assert_eq!(r.format, BinaryFormatKind::MsCab);
    }

    // ── Unknown / empty ───────────────────────────────────────────────────────

    #[test]
    fn test_empty_returns_unknown() {
        let r = det(&[]);
        assert_eq!(r.format, BinaryFormatKind::Unknown);
        assert!(!r.is_known());
    }

    #[test]
    fn test_random_bytes_unknown() {
        let r = det(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(r.format, BinaryFormatKind::Unknown);
    }

    // ── Predicates ────────────────────────────────────────────────────────────

    #[test]
    fn test_is_elf() {
        let d = FormatDetector::new();
        assert!(d.is_elf(&[0x7F, b'E', b'L', b'F', 2, 1]));
        assert!(!d.is_elf(b"MZ"));
    }

    #[test]
    fn test_is_pe() {
        let d = FormatDetector::new();
        assert!(d.is_pe(b"MZ\x90\x00"));
        assert!(!d.is_pe(&[0x7F, b'E', b'L', b'F', 2, 1]));
    }

    #[test]
    fn test_is_macho() {
        let d = FormatDetector::new();
        assert!(d.is_macho(&[0xCF, 0xFA, 0xED, 0xFE]));
        assert!(!d.is_macho(b"MZ"));
    }

    #[test]
    fn test_is_wasm() {
        let d = FormatDetector::new();
        assert!(d.is_wasm(&[0x00, 0x61, 0x73, 0x6D, 0x01]));
        assert!(!d.is_wasm(b"MZ"));
    }

    #[test]
    fn test_is_archive_zip() {
        let d = FormatDetector::new();
        assert!(d.is_archive(&[b'P', b'K', 0x03, 0x04]));
        assert!(!d.is_archive(&[0x7F, b'E', b'L', b'F']));
    }

    // ── DetectionResult helpers ───────────────────────────────────────────────

    #[test]
    fn test_detection_result_is_confident() {
        let r = det(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
        assert!(r.is_confident(200));
        assert!(r.is_confident(255));
    }

    #[test]
    fn test_detection_result_display() {
        let r = det(&[
            0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3E, 0,
        ]);
        let s = r.to_string();
        assert!(s.contains("ELF"));
        assert!(s.contains("confidence"));
    }
}
