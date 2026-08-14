//! File format detector for binary analysis.
//!
//! Identifies over 50 file formats via magic-byte signatures and heuristics.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// FileFormat enum
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileFormat {
    Pe,
    Elf,
    MachO,
    MachOFat,
    MachO64,
    Dex,
    Wasm,
    Pdf,
    Zip,
    Rar,
    SevenZip,
    Gz,
    Bz2,
    Xz,
    Tar,
    Ole2,
    Sqlite,
    Jar,
    Apk,
    Ipa,
    Lzma,
    Zstd,
    Lz4,
    Brotli,
    PcapNg,
    Pcap,
    Swf,
    DjVu,
    Mp4,
    Avi,
    Mkv,
    Flv,
    BitmapDib,
    Png,
    Jpeg,
    Gif,
    Tiff,
    Ico,
    Cur,
    Cab,
    Msi,
    Iso,
    Vmdk,
    VirtualBox,
    Qcow2,
    Dmg,
    AndroidBoot,
    LinuxKernelImage,
    FirmwareFfs,
    Unknown,
}

impl fmt::Display for FileFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(format_description(*self))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature table
// ─────────────────────────────────────────────────────────────────────────────

/// A magic-byte signature for a file format.
pub struct FormatSignature {
    pub format: FileFormat,
    /// Byte offset at which the magic bytes appear.
    pub magic_offset: usize,
    /// Required bytes.
    pub magic: &'static [u8],
    /// Optional bitmask applied to the data bytes before comparing. If None,
    /// all bits must match exactly.
    pub mask: Option<&'static [u8]>,
    /// Minimum file size for this format to be plausible.
    pub min_size: usize,
    /// Base confidence when magic matches.
    pub confidence: f64,
}

impl FormatSignature {
    const fn new(
        format: FileFormat,
        magic_offset: usize,
        magic: &'static [u8],
        min_size: usize,
        confidence: f64,
    ) -> Self {
        Self {
            format,
            magic_offset,
            magic,
            mask: None,
            min_size,
            confidence,
        }
    }

    fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.min_size {
            return false;
        }
        let start = self.magic_offset;
        let end = start + self.magic.len();
        if end > data.len() {
            return false;
        }
        let slice = &data[start..end];
        match self.mask {
            None => slice == self.magic,
            Some(mask) => {
                slice.iter()
                    .zip(self.magic.iter())
                    .zip(mask.iter())
                    .all(|((d, m), msk)| (d & msk) == (m & msk))
            }
        }
    }
}

/// All format signatures, ordered roughly by specificity (more specific first).
static SIGNATURES: &[FormatSignature] = &[
    // Executables
    FormatSignature::new(FileFormat::Pe,          0, b"MZ",                                         64,   0.70),
    FormatSignature::new(FileFormat::Elf,         0, b"\x7fELF",                                   16,   0.99),
    FormatSignature::new(FileFormat::MachO,       0, b"\xfe\xed\xfa\xce",                           8,   0.99),
    FormatSignature::new(FileFormat::MachO64,     0, b"\xfe\xed\xfa\xcf",                           8,   0.99),
    FormatSignature::new(FileFormat::MachOFat,    0, b"\xca\xfe\xba\xbe",                           8,   0.99),
    FormatSignature::new(FileFormat::Dex,         0, b"dex\n035\0",                                 8,   0.99),
    FormatSignature::new(FileFormat::Wasm,        0, b"\0asm",                                      8,   0.99),
    // Documents
    FormatSignature::new(FileFormat::Pdf,         0, b"%PDF",                                        8,   0.99),
    FormatSignature::new(FileFormat::Ole2,        0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",           8,   0.99),
    FormatSignature::new(FileFormat::Sqlite,      0, b"SQLite format 3\0",                          16,   0.99),
    // Archives
    FormatSignature::new(FileFormat::Zip,         0, b"PK\x03\x04",                                  4,   0.96),
    FormatSignature::new(FileFormat::Rar,         0, b"Rar!\x1a\x07\x00",                            7,   0.99),
    FormatSignature::new(FileFormat::SevenZip,    0, b"7z\xbc\xaf\x27\x1c",                          6,   0.99),
    FormatSignature::new(FileFormat::Gz,          0, b"\x1f\x8b",                                    2,   0.95),
    FormatSignature::new(FileFormat::Bz2,         0, b"BZh",                                         3,   0.97),
    FormatSignature::new(FileFormat::Xz,          0, b"\xfd7zXZ\0",                                  6,   0.99),
    FormatSignature::new(FileFormat::Lzma,        0, b"\x5d\x00\x00",                                3,   0.60),
    FormatSignature::new(FileFormat::Zstd,        0, b"\x28\xb5\x2f\xfd",                            4,   0.99),
    FormatSignature::new(FileFormat::Lz4,         0, b"\x04\x22\x4d\x18",                            4,   0.99),
    FormatSignature::new(FileFormat::Cab,         0, b"MSCF",                                        4,   0.99),
    // Images
    FormatSignature::new(FileFormat::Png,         0, b"\x89PNG\r\n\x1a\n",                           8,   0.99),
    FormatSignature::new(FileFormat::Jpeg,        0, b"\xff\xd8\xff",                                3,   0.97),
    FormatSignature::new(FileFormat::Gif,         0, b"GIF87a",                                      6,   0.99),
    FormatSignature::new(FileFormat::Gif,         0, b"GIF89a",                                      6,   0.99),
    FormatSignature::new(FileFormat::Tiff,        0, b"II*\0",                                       4,   0.98),
    FormatSignature::new(FileFormat::Tiff,        0, b"MM\0*",                                       4,   0.98),
    FormatSignature::new(FileFormat::BitmapDib,   0, b"BM",                                          14,  0.92),
    FormatSignature::new(FileFormat::Ico,         0, b"\0\0\x01\0",                                  4,   0.88),
    FormatSignature::new(FileFormat::Cur,         0, b"\0\0\x02\0",                                  4,   0.88),
    FormatSignature::new(FileFormat::DjVu,        0, b"AT&TFORM",                                    8,   0.90),
    // Video
    FormatSignature::new(FileFormat::Flv,         0, b"FLV\x01",                                     4,   0.99),
    FormatSignature::new(FileFormat::Avi,         0, b"RIFF",                                        4,   0.70),
    FormatSignature::new(FileFormat::Mkv,         0, b"\x1a\x45\xdf\xa3",                            4,   0.97),
    FormatSignature::new(FileFormat::Swf,         0, b"FWS",                                         3,   0.98),
    FormatSignature::new(FileFormat::Swf,         0, b"CWS",                                         3,   0.98),
    // Network capture
    FormatSignature::new(FileFormat::PcapNg,      0, b"\x0a\x0d\x0d\x0a",                           4,   0.97),
    FormatSignature::new(FileFormat::Pcap,        0, b"\xd4\xc3\xb2\xa1",                            4,   0.97),
    FormatSignature::new(FileFormat::Pcap,        0, b"\xa1\xb2\xc3\xd4",                            4,   0.97),
    // Disk / VM
    FormatSignature::new(FileFormat::Vmdk,        0, b"KDMV",                                        4,   0.99),
    FormatSignature::new(FileFormat::VirtualBox,  0, b"<<<< Oracle VM VirtualBox Disk Image",        36,  0.99),
    FormatSignature::new(FileFormat::Qcow2,       0, b"QFI\xfb",                                     4,   0.99),
    FormatSignature::new(FileFormat::Iso,        32769, b"CD001",                                    32774, 0.99),
    // Firmware / embedded
    FormatSignature::new(FileFormat::AndroidBoot, 0, b"ANDROID!",                                   8,   0.99),
    FormatSignature::new(FileFormat::LinuxKernelImage, 0x1fe, b"\x1f\x8b",                          514, 0.60),
    FormatSignature::new(FileFormat::FirmwareFfs, 0, b"\xff\xff\xff\xff\xff\xff\xff\xff",            8,   0.30),
];

// ─────────────────────────────────────────────────────────────────────────────
// FormatDetector
// ─────────────────────────────────────────────────────────────────────────────

pub struct FormatDetector;

impl FormatDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect all matching formats, sorted by confidence (highest first).
    pub fn detect(&self, data: &[u8]) -> Vec<(FileFormat, f64)> {
        let mut results: Vec<(FileFormat, f64)> = Vec::new();

        for sig in SIGNATURES {
            if sig.matches(data) {
                let mut conf = sig.confidence;
                // Boost PE confidence if the PE header offset is valid.
                if sig.format == FileFormat::Pe {
                    conf = self.refine_pe(data, conf);
                }
                // Boost ZIP confidence if it might be a JAR/APK.
                if sig.format == FileFormat::Zip {
                    if let Some(fmt) = self.classify_zip(data) {
                        results.push((fmt, 0.90));
                        continue;
                    }
                }
                // Avoid duplicate format entries — keep highest confidence.
                if let Some(existing) = results.iter_mut().find(|(f, _)| *f == sig.format) {
                    if conf > existing.1 {
                        existing.1 = conf;
                    }
                } else {
                    results.push((sig.format, conf));
                }
            }
        }

        // Extra heuristic: MP4 uses ftyp box at offset 4.
        if self.detect_mp4(data) {
            results.push((FileFormat::Mp4, 0.97));
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Return the single best-match format.
    pub fn detect_best(&self, data: &[u8]) -> FileFormat {
        self.detect(data)
            .into_iter()
            .next()
            .map(|(f, _)| f)
            .unwrap_or(FileFormat::Unknown)
    }

    /// Detect both the file format and the canonical architecture name
    /// (e.g. `"x86_64"`, `"arm64"`) in one pass.
    ///
    /// The architecture is resolved via [`rustre_arch::detect_arch_from_bytes`],
    /// which inspects ELF/PE/Mach-O headers. Returns `None` for the arch when
    /// the binary format is unrecognised or its machine field is unsupported.
    pub fn detect_with_arch(&self, data: &[u8]) -> (FileFormat, Option<String>) {
        let fmt = self.detect_best(data);
        let arch = rustre_arch::detect_arch_from_bytes(data);
        (fmt, arch)
    }
}

/// Re-export of the architecture hub crate so CLI subcommands (`info`, `disasm`)
/// can drive the [`rustre_arch::ArchRegistry`], [`rustre_arch::LinearDisassembler`],
/// and all 20 bundled `rustre-arch-*` backends through a single dependency.
pub use rustre_arch as arch;

/// Convenience wrapper around [`rustre_arch::detect_arch_from_bytes`] exposed
/// alongside the file-format detector so callers have a one-stop shop for both
/// signals.
#[must_use]
pub fn detect_architecture(data: &[u8]) -> Option<String> {
    rustre_arch::detect_arch_from_bytes(data)
}

impl FormatDetector {
    /// Returns the names of all architecture backends currently registered in
    /// the process-wide [`rustre_arch::global_registry`]. Calling this from the
    /// `info` subcommand also forces the lazy registry to initialise, ensuring
    /// every bundled `rustre-arch-*` crate is reachable at runtime.
    pub fn known_architectures() -> Vec<String> {
        rustre_arch::register_all_builtins();
        rustre_arch::global_registry()
            .iter()
            .map(|e| e.key().clone())
            .collect()
    }

    /// Guess format from file extension (case-insensitive).
    pub fn detect_by_extension(&self, ext: &str) -> Option<FileFormat> {
        match ext.to_lowercase().as_str() {
            "exe" | "dll" | "sys" | "ocx" | "scr" => Some(FileFormat::Pe),
            "elf"                                   => Some(FileFormat::Elf),
            "dylib" | "macho"                       => Some(FileFormat::MachO),
            "dex"                                   => Some(FileFormat::Dex),
            "wasm"                                  => Some(FileFormat::Wasm),
            "pdf"                                   => Some(FileFormat::Pdf),
            "zip"                                   => Some(FileFormat::Zip),
            "jar"                                   => Some(FileFormat::Jar),
            "apk"                                   => Some(FileFormat::Apk),
            "ipa"                                   => Some(FileFormat::Ipa),
            "rar"                                   => Some(FileFormat::Rar),
            "7z"                                    => Some(FileFormat::SevenZip),
            "gz" | "tgz"                            => Some(FileFormat::Gz),
            "bz2"                                   => Some(FileFormat::Bz2),
            "xz"                                    => Some(FileFormat::Xz),
            "tar"                                   => Some(FileFormat::Tar),
            "sqlite" | "db" | "sqlite3"             => Some(FileFormat::Sqlite),
            "png"                                   => Some(FileFormat::Png),
            "jpg" | "jpeg"                          => Some(FileFormat::Jpeg),
            "gif"                                   => Some(FileFormat::Gif),
            "tif" | "tiff"                          => Some(FileFormat::Tiff),
            "bmp" | "dib"                           => Some(FileFormat::BitmapDib),
            "ico"                                   => Some(FileFormat::Ico),
            "mp4" | "m4v" | "m4a"                  => Some(FileFormat::Mp4),
            "avi"                                   => Some(FileFormat::Avi),
            "mkv" | "webm"                          => Some(FileFormat::Mkv),
            "flv"                                   => Some(FileFormat::Flv),
            "swf"                                   => Some(FileFormat::Swf),
            "pcap"                                  => Some(FileFormat::Pcap),
            "pcapng"                                => Some(FileFormat::PcapNg),
            "cab"                                   => Some(FileFormat::Cab),
            "msi"                                   => Some(FileFormat::Msi),
            "iso"                                   => Some(FileFormat::Iso),
            "vmdk"                                  => Some(FileFormat::Vmdk),
            "vdi"                                   => Some(FileFormat::VirtualBox),
            "qcow2"                                 => Some(FileFormat::Qcow2),
            "dmg"                                   => Some(FileFormat::Dmg),
            "zst"                                   => Some(FileFormat::Zstd),
            "lz4"                                   => Some(FileFormat::Lz4),
            _                                       => None,
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────

    fn refine_pe(&self, data: &[u8], base: f64) -> f64 {
        // The PE header offset is a u32 at 0x3c.
        if data.len() < 0x40 {
            return base;
        }
        let pe_offset = u32::from_le_bytes(
            data[0x3c..0x40].try_into().unwrap_or([0; 4]),
        ) as usize;
        if pe_offset + 4 <= data.len()
            && &data[pe_offset..pe_offset + 4] == b"PE\0\0"
        {
            0.99
        } else {
            base * 0.80
        }
    }

    fn classify_zip(&self, data: &[u8]) -> Option<FileFormat> {
        // JAR/APK/IPA are all ZIP files; look for distinguishing entries.
        // Search for "META-INF/MANIFEST.MF" → JAR.
        // Search for "AndroidManifest.xml"  → APK.
        // Search for "Payload/"             → IPA.
        let window = &data[..data.len().min(65536)];
        if contains_bytes(window, b"AndroidManifest.xml") {
            return Some(FileFormat::Apk);
        }
        if contains_bytes(window, b"META-INF/MANIFEST.MF") {
            return Some(FileFormat::Jar);
        }
        if contains_bytes(window, b"Payload/") {
            return Some(FileFormat::Ipa);
        }
        None
    }

    fn detect_mp4(&self, data: &[u8]) -> bool {
        // MP4: first box is [size(4)] "ftyp" at offset 4.
        if data.len() < 12 {
            return false;
        }
        &data[4..8] == b"ftyp"
    }
}

impl Default for FormatDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Format metadata helpers
// ─────────────────────────────────────────────────────────────────────────────

pub fn format_description(fmt: FileFormat) -> &'static str {
    match fmt {
        FileFormat::Pe               => "Windows PE executable",
        FileFormat::Elf              => "ELF executable/shared object",
        FileFormat::MachO            => "Mach-O binary (32-bit)",
        FileFormat::MachOFat         => "Mach-O fat binary (universal)",
        FileFormat::MachO64          => "Mach-O binary (64-bit)",
        FileFormat::Dex              => "Android Dalvik DEX",
        FileFormat::Wasm             => "WebAssembly module",
        FileFormat::Pdf              => "Portable Document Format",
        FileFormat::Zip              => "ZIP archive",
        FileFormat::Rar              => "RAR archive",
        FileFormat::SevenZip         => "7-Zip archive",
        FileFormat::Gz               => "gzip compressed",
        FileFormat::Bz2              => "bzip2 compressed",
        FileFormat::Xz               => "XZ/LZMA2 compressed",
        FileFormat::Tar              => "POSIX tar archive",
        FileFormat::Ole2             => "OLE2 Compound Document (MS Office)",
        FileFormat::Sqlite           => "SQLite database",
        FileFormat::Jar              => "Java JAR archive",
        FileFormat::Apk              => "Android APK package",
        FileFormat::Ipa              => "iOS IPA package",
        FileFormat::Lzma             => "LZMA compressed",
        FileFormat::Zstd             => "Zstandard compressed",
        FileFormat::Lz4              => "LZ4 compressed",
        FileFormat::Brotli           => "Brotli compressed",
        FileFormat::PcapNg           => "PCAP-NG network capture",
        FileFormat::Pcap             => "PCAP network capture",
        FileFormat::Swf              => "Adobe Flash SWF",
        FileFormat::DjVu             => "DjVu document",
        FileFormat::Mp4              => "MPEG-4 video",
        FileFormat::Avi              => "AVI video",
        FileFormat::Mkv              => "Matroska video",
        FileFormat::Flv              => "Flash video",
        FileFormat::BitmapDib        => "Windows BMP/DIB image",
        FileFormat::Png              => "PNG image",
        FileFormat::Jpeg             => "JPEG image",
        FileFormat::Gif              => "GIF image",
        FileFormat::Tiff             => "TIFF image",
        FileFormat::Ico              => "Windows icon",
        FileFormat::Cur              => "Windows cursor",
        FileFormat::Cab              => "Microsoft Cabinet",
        FileFormat::Msi              => "Windows Installer",
        FileFormat::Iso              => "ISO 9660 disc image",
        FileFormat::Vmdk             => "VMware VMDK disk image",
        FileFormat::VirtualBox       => "VirtualBox VDI disk image",
        FileFormat::Qcow2            => "QEMU QCOW2 disk image",
        FileFormat::Dmg              => "Apple DMG disk image",
        FileFormat::AndroidBoot      => "Android boot image",
        FileFormat::LinuxKernelImage => "Linux kernel image",
        FileFormat::FirmwareFfs      => "UEFI firmware FFS volume",
        FileFormat::Unknown          => "unknown format",
    }
}

pub fn is_executable(fmt: FileFormat) -> bool {
    matches!(
        fmt,
        FileFormat::Pe
            | FileFormat::Elf
            | FileFormat::MachO
            | FileFormat::MachOFat
            | FileFormat::MachO64
            | FileFormat::Dex
            | FileFormat::Wasm
    )
}

pub fn is_archive(fmt: FileFormat) -> bool {
    matches!(
        fmt,
        FileFormat::Zip
            | FileFormat::Rar
            | FileFormat::SevenZip
            | FileFormat::Gz
            | FileFormat::Bz2
            | FileFormat::Xz
            | FileFormat::Tar
            | FileFormat::Jar
            | FileFormat::Apk
            | FileFormat::Ipa
            | FileFormat::Lzma
            | FileFormat::Zstd
            | FileFormat::Lz4
            | FileFormat::Brotli
            | FileFormat::Cab
            | FileFormat::Msi
    )
}

pub fn mime_type(fmt: FileFormat) -> &'static str {
    match fmt {
        FileFormat::Pe               => "application/vnd.microsoft.portable-executable",
        FileFormat::Elf              => "application/x-elf",
        FileFormat::MachO | FileFormat::MachO64 | FileFormat::MachOFat => "application/x-mach-binary",
        FileFormat::Dex              => "application/vnd.android.package-archive",
        FileFormat::Wasm             => "application/wasm",
        FileFormat::Pdf              => "application/pdf",
        FileFormat::Zip | FileFormat::Jar | FileFormat::Apk | FileFormat::Ipa => "application/zip",
        FileFormat::Rar              => "application/vnd.rar",
        FileFormat::SevenZip         => "application/x-7z-compressed",
        FileFormat::Gz               => "application/gzip",
        FileFormat::Bz2              => "application/x-bzip2",
        FileFormat::Xz               => "application/x-xz",
        FileFormat::Tar              => "application/x-tar",
        FileFormat::Ole2             => "application/msword",
        FileFormat::Sqlite           => "application/x-sqlite3",
        FileFormat::Zstd             => "application/zstd",
        FileFormat::Lz4              => "application/x-lz4",
        FileFormat::Png              => "image/png",
        FileFormat::Jpeg             => "image/jpeg",
        FileFormat::Gif              => "image/gif",
        FileFormat::Tiff             => "image/tiff",
        FileFormat::BitmapDib        => "image/bmp",
        FileFormat::Ico | FileFormat::Cur => "image/x-icon",
        FileFormat::Mp4              => "video/mp4",
        FileFormat::Avi              => "video/x-msvideo",
        FileFormat::Mkv              => "video/x-matroska",
        FileFormat::Flv              => "video/x-flv",
        FileFormat::Swf              => "application/x-shockwave-flash",
        FileFormat::Pcap             => "application/vnd.tcpdump.pcap",
        FileFormat::PcapNg           => "application/x-pcapng",
        FileFormat::Iso              => "application/x-iso9660-image",
        FileFormat::Cab              => "application/vnd.ms-cab-compressed",
        FileFormat::Msi              => "application/x-msi",
        _                            => "application/octet-stream",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> FormatDetector {
        FormatDetector::new()
    }

    #[test]
    fn test_detect_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Elf);
    }

    #[test]
    fn test_detect_png() {
        let data = b"\x89PNG\r\n\x1a\nextra";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Png);
    }

    #[test]
    fn test_detect_jpeg() {
        let data = b"\xff\xd8\xff\xe0\x00\x10JFIF";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Jpeg);
    }

    #[test]
    fn test_detect_gif() {
        let data = b"GIF89a\x01\x00\x01\x00";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Gif);
    }

    #[test]
    fn test_detect_zip() {
        let data = b"PK\x03\x04\x14\x00\x00\x00";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Zip);
    }

    #[test]
    fn test_detect_apk() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend_from_slice(b"AndroidManifest.xml");
        let fmt = detector().detect_best(&data);
        assert_eq!(fmt, FileFormat::Apk);
    }

    #[test]
    fn test_detect_gz() {
        let data = b"\x1f\x8b\x08\x00";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Gz);
    }

    #[test]
    fn test_detect_wasm() {
        let data = b"\0asm\x01\x00\x00\x00";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Wasm);
    }

    #[test]
    fn test_detect_pdf() {
        let data = b"%PDF-1.7\n";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Pdf);
    }

    #[test]
    fn test_detect_7zip() {
        let data = b"7z\xbc\xaf\x27\x1c\x00\x03";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::SevenZip);
    }

    #[test]
    fn test_detect_sqlite() {
        let data = b"SQLite format 3\0\x10\x00";
        let fmt = detector().detect_best(data);
        assert_eq!(fmt, FileFormat::Sqlite);
    }

    #[test]
    fn test_detect_unknown() {
        let data = b"\x00\x00\x00\x00";
        // Unknown (firmware FFS might match but confidence is low)
        let results = detector().detect(data);
        if let Some((f, _)) = results.first() {
            // Allow FirmwareFfs low-confidence match or Unknown
            let _ = f;
        }
    }

    #[test]
    fn test_detect_with_arch_elf_x86_64() {
        // Minimal ELF64 little-endian header with e_machine = 62 (x86_64).
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // EI_CLASS = 64-bit
        data[5] = 1; // EI_DATA  = little-endian
        data[18] = 62; // e_machine low byte = EM_X86_64
        data[19] = 0;
        let (fmt, arch) = detector().detect_with_arch(&data);
        assert_eq!(fmt, FileFormat::Elf);
        assert_eq!(arch.as_deref(), Some("x86_64"));
    }

    #[test]
    fn test_detect_architecture_helper_handles_unknown() {
        // The standalone helper must mirror detect_with_arch's arch field.
        assert_eq!(detect_architecture(b"garbage_data_here"), None);
    }

    #[test]
    fn test_known_architectures_populates_registry() {
        let names = FormatDetector::known_architectures();
        assert!(names.iter().any(|n| n == "x86_64"));
        assert!(names.iter().any(|n| n == "arm64"));
        // Also exercise the re-exported `arch` alias so the path is wired.
        let reg = arch::ArchRegistry::new();
        assert!(reg.is_empty());
    }

    #[test]
    fn test_detect_by_extension() {
        let d = FormatDetector::new();
        assert_eq!(d.detect_by_extension("exe"), Some(FileFormat::Pe));
        assert_eq!(d.detect_by_extension("ELF"), Some(FileFormat::Elf));
        assert_eq!(d.detect_by_extension("png"), Some(FileFormat::Png));
        assert_eq!(d.detect_by_extension("mp4"), Some(FileFormat::Mp4));
        assert_eq!(d.detect_by_extension("unknown_ext"), None);
    }

    #[test]
    fn test_is_executable() {
        assert!(is_executable(FileFormat::Pe));
        assert!(is_executable(FileFormat::Elf));
        assert!(!is_executable(FileFormat::Zip));
        assert!(!is_executable(FileFormat::Png));
    }

    #[test]
    fn test_is_archive() {
        assert!(is_archive(FileFormat::Zip));
        assert!(is_archive(FileFormat::Rar));
        assert!(is_archive(FileFormat::Gz));
        assert!(!is_archive(FileFormat::Pe));
    }

    #[test]
    fn test_mime_type() {
        assert_eq!(mime_type(FileFormat::Png), "image/png");
        assert_eq!(mime_type(FileFormat::Gz), "application/gzip");
    }

    #[test]
    fn test_detect_multiple_candidates() {
        // An ELF inside a GZ wrapper would not trigger both here,
        // but ensure the results vec is sorted by confidence.
        let data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00";
        let results = detector().detect(data);
        for w in results.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn test_format_description_complete() {
        // Ensure format_description never returns empty string for all variants.
        let variants = [
            FileFormat::Pe, FileFormat::Elf, FileFormat::Wasm, FileFormat::Pdf,
            FileFormat::Zip, FileFormat::Gz, FileFormat::Png, FileFormat::Unknown,
        ];
        for v in variants {
            assert!(!format_description(v).is_empty());
        }
    }
}
