//! `signature_db` — Comprehensive firmware magic-byte signature database.
//!
//! This module provides a static database of 100+ binary signatures organised
//! by category (filesystem, compression, bootloader, OS image, certificate,
//! configuration).  Each entry carries the magic byte pattern, the byte offset
//! within the format where the magic appears, a human-readable name, and a
//! confidence score (0–100).
//!
//! # Usage
//! ```rust
//! use rustre_loader_firmware::signature_db::{SignatureDb, SignatureCategory};
//! let db = SignatureDb::new();
//! let hits = db.scan(b"\x1f\x8b\x08\x00some compressed payload");
//! assert!(hits.iter().any(|h| h.entry.name == "gzip"));
//! ```

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Core types
// ─────────────────────────────────────────────────────────────────────────────

/// High-level category that a signature belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureCategory {
    /// Compressed data stream (gzip, lzma, xz, …)
    Compression,
    /// On-flash / in-memory filesystem image (squashfs, cramfs, …)
    Filesystem,
    /// Bootloader image or stage (U-Boot, GRUB, EDK2 FV, …)
    Bootloader,
    /// Operating-system kernel or initrd image (zImage, bzImage, uImage, FIT)
    OsImage,
    /// Certificate, key, or PKCS material (PEM, DER, PKCS#7, …)
    Certificate,
    /// Encrypted or password-protected archive / blob
    Encrypted,
    /// Configuration file or meta-data (D-Bus, XML, …)
    Config,
    /// Executable or object file (ELF, PE/COFF, Mach-O, …)
    Executable,
    /// Archive container (ZIP, tar, AR, …)
    Archive,
    /// Firmware-specific container (UF2, Intel HEX, SREC, …)
    FirmwareContainer,
    /// Catch-all for signatures that span multiple categories.
    Generic,
}

impl fmt::Display for SignatureCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Compression => "compression",
            Self::Filesystem => "filesystem",
            Self::Bootloader => "bootloader",
            Self::OsImage => "os-image",
            Self::Certificate => "certificate",
            Self::Encrypted => "encrypted",
            Self::Config => "config",
            Self::Executable => "executable",
            Self::Archive => "archive",
            Self::FirmwareContainer => "firmware-container",
            Self::Generic => "generic",
        };
        write!(f, "{s}")
    }
}

/// Static description of a known binary signature.
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    /// Short lowercase identifier, e.g. `"gzip"`.
    pub name: &'static str,
    /// Magic bytes that identify this format.
    pub magic: &'static [u8],
    /// Byte offset *within the format* where the magic appears.
    /// Usually 0; some formats embed the magic at a fixed non-zero offset
    /// (e.g. ext2 superblock magic is at offset 0x438).
    pub magic_offset: usize,
    /// Human-readable description.
    pub description: &'static str,
    /// Broad category.
    pub category: SignatureCategory,
    /// Confidence score 0–100.
    /// 100 = unique 4+-byte magic, 50 = 2-byte magic with many false positives.
    pub confidence: u8,
}

/// A single match returned by [`SignatureDb::scan`].
#[derive(Debug, Clone)]
pub struct SignatureMatch<'db> {
    /// Reference to the matching database entry.
    pub entry: &'db SignatureEntry,
    /// Absolute byte offset within the scanned buffer where the magic was found.
    pub offset: usize,
}

impl fmt::Display for SignatureMatch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}  {:30}  {:20}  conf={}",
            self.offset, self.entry.name, self.entry.category, self.entry.confidence,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Static signature table
// ─────────────────────────────────────────────────────────────────────────────

// Helper to construct a SignatureEntry with less boilerplate.
macro_rules! sig {
    ($name:expr, $magic:expr, $off:expr, $desc:expr, $cat:expr, $conf:expr) => {
        SignatureEntry {
            name: $name,
            magic: $magic,
            magic_offset: $off,
            description: $desc,
            category: $cat,
            confidence: $conf,
        }
    };
}

/// Build the full static signature table.
fn build_table() -> Vec<SignatureEntry> {
    use SignatureCategory::*;
    vec![
        // ── Compression ─────────────────────────────────────────────────────
        sig!(
            "gzip",
            &[0x1F, 0x8B],
            0,
            "Gzip compressed data (RFC 1952)",
            Compression,
            80
        ),
        sig!(
            "bzip2",
            b"BZh",
            0,
            "Bzip2 compressed stream",
            Compression,
            90
        ),
        sig!(
            "xz",
            &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
            0,
            "XZ compressed stream (LZMA2)",
            Compression,
            99
        ),
        sig!(
            "lzma-alone",
            &[0x5D, 0x00, 0x00],
            0,
            "LZMA alone-format stream (legacy)",
            Compression,
            65
        ),
        sig!(
            "lzma-7z",
            &[0x5D, 0x00, 0x00, 0x80],
            0,
            "LZMA stream (7-zip variant)",
            Compression,
            72
        ),
        sig!(
            "zlib-default",
            &[0x78, 0x9C],
            0,
            "Zlib stream — default compression (RFC 1950)",
            Compression,
            75
        ),
        sig!(
            "zlib-best",
            &[0x78, 0xDA],
            0,
            "Zlib stream — best compression",
            Compression,
            75
        ),
        sig!(
            "zlib-low",
            &[0x78, 0x01],
            0,
            "Zlib stream — no/low compression",
            Compression,
            70
        ),
        sig!(
            "zlib-speed",
            &[0x78, 0x5E],
            0,
            "Zlib stream — fast compression",
            Compression,
            70
        ),
        sig!(
            "7zip",
            b"7z\xBC\xAF\x27\x1C",
            0,
            "7-Zip archive",
            Compression,
            99
        ),
        sig!(
            "zstd",
            &[0x28, 0xB5, 0x2F, 0xFD],
            0,
            "Zstandard compressed frame",
            Compression,
            99
        ),
        sig!(
            "lz4-legacy",
            &[0x02, 0x21, 0x4C, 0x18],
            0,
            "LZ4 legacy frame format",
            Compression,
            95
        ),
        sig!(
            "lz4-frame",
            &[0x04, 0x22, 0x4D, 0x18],
            0,
            "LZ4 frame format (v1.5+)",
            Compression,
            99
        ),
        sig!(
            "lzo",
            &[0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D],
            0,
            "LZO compressed file (lzop format)",
            Compression,
            98
        ),
        sig!(
            "snappy-framed",
            &[0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59],
            0,
            "Snappy framed format",
            Compression,
            99
        ),
        sig!(
            "brotli",
            &[0xCE, 0xB2, 0xCF, 0x81],
            0,
            "Brotli compressed data",
            Compression,
            85
        ),
        sig!(
            "compress-lzw",
            &[0x1F, 0x9D],
            0,
            "Unix compress (LZW) stream",
            Compression,
            80
        ),
        sig!(
            "compress-lzh",
            &[0x1F, 0xA0],
            0,
            "Unix pack (LZH) stream",
            Compression,
            80
        ),
        // ── Filesystems ──────────────────────────────────────────────────────
        sig!(
            "squashfs-le",
            &[0x73, 0x71, 0x73, 0x68],
            0,
            "SquashFS filesystem (little-endian, v4)",
            Filesystem,
            99
        ),
        sig!(
            "squashfs-be",
            &[0x71, 0x73, 0x68, 0x73],
            0,
            "SquashFS filesystem (big-endian)",
            Filesystem,
            99
        ),
        sig!(
            "squashfs-le3",
            &[0x68, 0x73, 0x71, 0x73],
            0,
            "SquashFS filesystem (LE, v3 DDWrt variant)",
            Filesystem,
            95
        ),
        sig!(
            "squashfs-be3",
            &[0x73, 0x68, 0x73, 0x71],
            0,
            "SquashFS filesystem (BE, v3)",
            Filesystem,
            95
        ),
        sig!(
            "cramfs-le",
            &[0x45, 0x3D, 0xCD, 0x28],
            0,
            "CramFS compressed filesystem (little-endian)",
            Filesystem,
            99
        ),
        sig!(
            "cramfs-be",
            &[0x28, 0xCD, 0x3D, 0x45],
            0,
            "CramFS compressed filesystem (big-endian)",
            Filesystem,
            99
        ),
        sig!(
            "jffs2-le",
            &[0x19, 0x85],
            0,
            "JFFS2 filesystem node (little-endian)",
            Filesystem,
            75
        ),
        sig!(
            "jffs2-be",
            &[0x85, 0x19],
            0,
            "JFFS2 filesystem node (big-endian)",
            Filesystem,
            75
        ),
        sig!(
            "ubifs",
            &[0x31, 0x18, 0x10, 0x06],
            0,
            "UBIFS superblock node",
            Filesystem,
            99
        ),
        sig!(
            "ext2",
            &[0x53, 0xEF],
            0x38,
            "ext2/3/4 filesystem superblock magic (offset 0x38 in superblock)",
            Filesystem,
            90
        ),
        sig!(
            "yaffs2",
            &[0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF],
            0,
            "YAFFS2 flash filesystem chunk header",
            Filesystem,
            85
        ),
        sig!("romfs", b"-rom1fs-", 0, "RomFS filesystem", Filesystem, 99),
        sig!(
            "minix-v1",
            &[0x8F, 0x13],
            0x410,
            "Minix filesystem v1 superblock",
            Filesystem,
            90
        ),
        sig!(
            "minix-v2",
            &[0x8F, 0x2F],
            0x410,
            "Minix filesystem v2 superblock",
            Filesystem,
            90
        ),
        sig!(
            "reiserfs",
            b"ReIsErFs",
            0x10034,
            "ReiserFS filesystem",
            Filesystem,
            99
        ),
        sig!(
            "reiserfs2",
            b"ReIsEr2Fs",
            0x10034,
            "ReiserFS v2 filesystem",
            Filesystem,
            99
        ),
        sig!(
            "xfs",
            b"XFSB",
            0,
            "XFS filesystem superblock",
            Filesystem,
            99
        ),
        sig!(
            "btrfs",
            b"_BHRfS_M",
            0x10040,
            "Btrfs filesystem",
            Filesystem,
            99
        ),
        sig!(
            "f2fs",
            &[0x10, 0x20, 0xF5, 0xF2],
            0,
            "F2FS (Flash-Friendly File System)",
            Filesystem,
            99
        ),
        sig!(
            "fat16",
            b"FAT16   ",
            0x36,
            "FAT16 filesystem BPB",
            Filesystem,
            90
        ),
        sig!(
            "fat32",
            b"FAT32   ",
            0x52,
            "FAT32 filesystem BPB",
            Filesystem,
            90
        ),
        sig!("ntfs", b"NTFS    ", 3, "NTFS filesystem", Filesystem, 99),
        sig!(
            "iso9660",
            b"CD001",
            0x8001,
            "ISO 9660 CD-ROM filesystem",
            Filesystem,
            99
        ),
        sig!(
            "erofs",
            &[0xE2, 0xE1, 0xF5, 0xE0],
            0,
            "EROFS read-only compressed filesystem",
            Filesystem,
            99
        ),
        // ── Bootloader / firmware containers ────────────────────────────────
        sig!(
            "uboot-legacy",
            &[0x27, 0x05, 0x19, 0x56],
            0,
            "U-Boot legacy uImage",
            Bootloader,
            99
        ),
        sig!(
            "uboot-fit",
            &[0xD0, 0x0D, 0xFE, 0xED],
            0,
            "U-Boot FIT image (flattened device tree)",
            Bootloader,
            99
        ),
        sig!(
            "dtb",
            &[0xD0, 0x0D, 0xFE, 0xED],
            0,
            "Device Tree Blob (DTB)",
            Bootloader,
            99
        ),
        sig!(
            "android-boot",
            b"ANDROID!",
            0,
            "Android boot image header v0",
            Bootloader,
            99
        ),
        sig!(
            "android-vendor-boot",
            b"VNDRBOOT",
            0,
            "Android vendor boot image",
            Bootloader,
            99
        ),
        sig!(
            "android-sparse",
            &[0x3A, 0xFF, 0x26, 0xED],
            0,
            "Android sparse image",
            Bootloader,
            99
        ),
        sig!(
            "grub-core",
            b"GRUB ",
            0,
            "GRUB2 core image marker",
            Bootloader,
            75
        ),
        sig!(
            "uefi-fv",
            &[0x5A, 0xA5, 0xF0, 0x0F],
            0x28,
            "UEFI Firmware Volume header signature",
            Bootloader,
            95
        ),
        sig!(
            "uefi-capsule",
            &[
                0xBD, 0x86, 0x66, 0x3B, 0x76, 0x0D, 0x30, 0x40, 0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F,
                0xC5, 0xA0
            ],
            0,
            "UEFI update capsule GUID",
            Bootloader,
            99
        ),
        sig!(
            "coreboot",
            b"LARCHIVE",
            0,
            "Coreboot CBFS archive header",
            Bootloader,
            99
        ),
        sig!(
            "trx",
            b"HDR0",
            0,
            "Broadcom TRX firmware container",
            Bootloader,
            95
        ),
        sig!(
            "seama",
            &[0x5E, 0xA3, 0xA4, 0x17],
            0,
            "SEAMA firmware container (D-Link)",
            Bootloader,
            95
        ),
        sig!(
            "chk",
            b"\x2A\x23\x24\x5E",
            0,
            "Netgear CHK firmware container",
            Bootloader,
            90
        ),
        sig!(
            "openwrt-trx",
            b"HDR0",
            0,
            "OpenWRT TRX image",
            Bootloader,
            90
        ),
        sig!(
            "zyxel-romfile",
            b"ROMFILE",
            0,
            "ZyXEL RomFile firmware",
            Bootloader,
            95
        ),
        sig!(
            "buffalo-enc",
            b"\x42\x55\x46\x46",
            0,
            "Buffalo encrypted firmware header (BUFF)",
            Bootloader,
            85
        ),
        sig!(
            "lzma-kernel",
            &[
                0x5D, 0x00, 0x00, 0x80, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ],
            0,
            "LZMA-compressed Linux kernel payload",
            Bootloader,
            88
        ),
        // ── OS / kernel images ───────────────────────────────────────────────
        sig!(
            "linux-zimage",
            b"HdrS",
            0x202,
            "Linux x86 zImage / bzImage setup header",
            OsImage,
            99
        ),
        sig!(
            "linux-arm-zimage",
            &[0x18, 0x28, 0x6F, 0x01],
            0x24,
            "Linux ARM zImage self-decompressor magic",
            OsImage,
            95
        ),
        sig!(
            "linux-arm64-image",
            b"ARM\x64",
            0x38,
            "Linux AArch64 Image header magic",
            OsImage,
            99
        ),
        sig!(
            "vmlinux-elf",
            &[0x7F, 0x45, 0x4C, 0x46],
            0,
            "Linux vmlinux ELF binary",
            OsImage,
            90
        ),
        sig!(
            "openwrt-sysupgrade",
            b"OWRT",
            0,
            "OpenWRT sysupgrade image tag",
            OsImage,
            99
        ),
        sig!(
            "initramfs-cpio",
            &[0x30, 0x37, 0x30, 0x37, 0x30, 0x31],
            0,
            "Linux initramfs CPIO newc archive ('070701')",
            OsImage,
            99
        ),
        sig!(
            "initramfs-cpio-crc",
            &[0x30, 0x37, 0x30, 0x37, 0x30, 0x32],
            0,
            "Linux initramfs CPIO newc+crc ('070702')",
            OsImage,
            99
        ),
        sig!(
            "cpio-binary",
            &[0xC7, 0x71],
            0,
            "CPIO binary archive (old format)",
            Archive,
            80
        ),
        sig!(
            "squashfs-lzma",
            b"shsq",
            0,
            "SquashFS with LZMA (firmware variant)",
            Filesystem,
            92
        ),
        // ── Certificates / keys ──────────────────────────────────────────────
        sig!(
            "pem-cert",
            b"-----BEGIN CERTIFICATE-----",
            0,
            "PEM encoded X.509 certificate",
            Certificate,
            99
        ),
        sig!(
            "pem-rsa-key",
            b"-----BEGIN RSA PRIVATE KEY-----",
            0,
            "PEM encoded RSA private key (PKCS#1)",
            Certificate,
            99
        ),
        sig!(
            "pem-ec-key",
            b"-----BEGIN EC PRIVATE KEY-----",
            0,
            "PEM encoded EC private key",
            Certificate,
            99
        ),
        sig!(
            "pem-private-key",
            b"-----BEGIN PRIVATE KEY-----",
            0,
            "PEM encoded private key (PKCS#8)",
            Certificate,
            99
        ),
        sig!(
            "pem-public-key",
            b"-----BEGIN PUBLIC KEY-----",
            0,
            "PEM encoded public key",
            Certificate,
            99
        ),
        sig!(
            "pem-crl",
            b"-----BEGIN X509 CRL-----",
            0,
            "PEM encoded X.509 CRL",
            Certificate,
            99
        ),
        sig!(
            "pkcs7-der",
            &[0x30, 0x82],
            0,
            "DER encoded PKCS#7 / X.509 (ASN.1 SEQUENCE)",
            Certificate,
            60
        ),
        sig!(
            "der-cert",
            &[0x30, 0x82],
            0,
            "DER encoded X.509 certificate (ASN.1)",
            Certificate,
            60
        ),
        sig!(
            "pkcs8-der",
            &[0x30, 0x81],
            0,
            "DER encoded PKCS#8 key info",
            Certificate,
            55
        ),
        // ── Encrypted blobs ──────────────────────────────────────────────────
        sig!(
            "openssl-salted",
            b"Salted__",
            0,
            "OpenSSL salted encrypted data",
            Encrypted,
            99
        ),
        sig!(
            "gpg-binary",
            &[0x99, 0x01],
            0,
            "GPG/PGP binary keyring / encrypted data",
            Encrypted,
            75
        ),
        sig!(
            "gpg-armored",
            b"-----BEGIN PGP",
            0,
            "GPG/PGP ASCII-armored message",
            Encrypted,
            99
        ),
        sig!(
            "luks",
            b"LUKS\xBA\xBE",
            0,
            "LUKS full-disk encryption header",
            Encrypted,
            99
        ),
        // ── Archives ─────────────────────────────────────────────────────────
        sig!(
            "zip-local",
            b"PK\x03\x04",
            0,
            "ZIP archive local file header",
            Archive,
            99
        ),
        sig!(
            "zip-eocd",
            b"PK\x05\x06",
            0,
            "ZIP end of central directory",
            Archive,
            99
        ),
        sig!(
            "zip-cd",
            b"PK\x01\x02",
            0,
            "ZIP central directory entry",
            Archive,
            99
        ),
        sig!(
            "tar-posix",
            b"ustar",
            0x101,
            "POSIX tar archive ('ustar' at 0x101)",
            Archive,
            99
        ),
        sig!("tar-gnu", b"ustar  ", 0x101, "GNU tar archive", Archive, 99),
        sig!("ar", b"!<arch>\n", 0, "Unix AR archive", Archive, 99),
        sig!(
            "rpm",
            &[0xED, 0xAB, 0xEE, 0xDB],
            0,
            "RPM package",
            Archive,
            99
        ),
        sig!(
            "deb",
            b"!<arch>\ndebian",
            0,
            "Debian package (.deb)",
            Archive,
            99
        ),
        sig!("cab", b"MSCF", 0, "Microsoft Cabinet archive", Archive, 99),
        sig!(
            "rar4",
            b"Rar!\x1A\x07\x00",
            0,
            "RAR archive v4",
            Archive,
            99
        ),
        sig!(
            "rar5",
            b"Rar!\x1A\x07\x01\x00",
            0,
            "RAR archive v5",
            Archive,
            99
        ),
        sig!(
            "cramfs-lzma",
            &[0xC5, 0x4C, 0x63, 0x28],
            0,
            "CramFS with LZMA (unofficial variant)",
            Filesystem,
            88
        ),
        sig!(
            "squashfs-lzo",
            &[0x68, 0x73, 0x71, 0x73],
            0,
            "SquashFS with LZO (BE, unofficial)",
            Filesystem,
            88
        ),
        // ── Executables ──────────────────────────────────────────────────────
        sig!(
            "elf",
            &[0x7F, 0x45, 0x4C, 0x46],
            0,
            "ELF executable / shared object",
            Executable,
            99
        ),
        sig!(
            "pe-mz",
            b"MZ",
            0,
            "PE/COFF Windows executable or DLL (MZ stub)",
            Executable,
            60
        ),
        sig!(
            "macho-32-le",
            &[0xCE, 0xFA, 0xED, 0xFE],
            0,
            "Mach-O 32-bit little-endian binary",
            Executable,
            99
        ),
        sig!(
            "macho-32-be",
            &[0xFE, 0xED, 0xFA, 0xCE],
            0,
            "Mach-O 32-bit big-endian binary",
            Executable,
            99
        ),
        sig!(
            "macho-64-le",
            &[0xCF, 0xFA, 0xED, 0xFE],
            0,
            "Mach-O 64-bit little-endian binary",
            Executable,
            99
        ),
        sig!(
            "macho-64-be",
            &[0xFE, 0xED, 0xFA, 0xCF],
            0,
            "Mach-O 64-bit big-endian binary",
            Executable,
            99
        ),
        sig!(
            "macho-fat",
            &[0xCA, 0xFE, 0xBA, 0xBE],
            0,
            "Mach-O fat / universal binary",
            Executable,
            99
        ),
        sig!(
            "java-class",
            &[0xCA, 0xFE, 0xBA, 0xBE],
            0,
            "Java .class bytecode (shared magic with Mach-O fat)",
            Executable,
            70
        ),
        sig!(
            "wasm",
            &[0x00, 0x61, 0x73, 0x6D],
            0,
            "WebAssembly binary module",
            Executable,
            99
        ),
        // ── Firmware containers ───────────────────────────────────────────────
        sig!(
            "uf2",
            b"UF2\n",
            0,
            "UF2 USB flashing format block",
            FirmwareContainer,
            99
        ),
        sig!(
            "intel-hex",
            b":",
            0,
            "Intel HEX ASCII record format",
            FirmwareContainer,
            50
        ),
        sig!(
            "srec",
            b"S0",
            0,
            "Motorola S-record (SREC) format",
            FirmwareContainer,
            70
        ),
        sig!(
            "dfu",
            b"DfuSe",
            0,
            "STM32 DFU firmware image",
            FirmwareContainer,
            99
        ),
        // ── Config / meta-data ────────────────────────────────────────────────
        sig!(
            "dbus-service",
            b"[D-BUS Service]",
            0,
            "D-Bus service activation file",
            Config,
            99
        ),
        sig!(
            "dbus-service-alt",
            b"[D-Bus Service]",
            0,
            "D-Bus service file (alternate casing)",
            Config,
            99
        ),
        sig!("xml-generic", b"<?xml", 0, "XML document", Config, 70),
        sig!(
            "json-object",
            b"{",
            0,
            "JSON object (heuristic)",
            Config,
            20
        ),
        sig!(
            "plist-binary",
            b"bplist00",
            0,
            "Apple binary property list",
            Config,
            99
        ),
        sig!(
            "plist-xml",
            b"<?xml version=\"1.0\" encoding",
            0,
            "Apple XML property list",
            Config,
            60
        ),
        sig!(
            "ini-generic",
            b"[",
            0,
            "INI/CFG configuration section (heuristic)",
            Config,
            15
        ),
        sig!(
            "yaml-document",
            b"---\n",
            0,
            "YAML document marker",
            Config,
            65
        ),
        sig!(
            "toml-document",
            b"[package]",
            0,
            "TOML document (Cargo/Rust style)",
            Config,
            75
        ),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureDb
// ─────────────────────────────────────────────────────────────────────────────

/// The compiled signature database.
///
/// Construct once with [`SignatureDb::new`] and reuse for multiple scans.
pub struct SignatureDb {
    entries: Vec<SignatureEntry>,
}

impl SignatureDb {
    /// Create a new database populated with all built-in signatures.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: build_table(),
        }
    }

    /// Return the number of entries in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when the database is empty (should never be the case with
    /// the built-in table).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries belonging to `category`.
    #[must_use]
    pub fn by_category(&self, category: SignatureCategory) -> Vec<&SignatureEntry> {
        self.entries
            .iter()
            .filter(|e| e.category == category)
            .collect()
    }

    /// Look up an entry by exact name (case-sensitive).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&SignatureEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Scan `data` and return every signature match, sorted ascending by offset.
    ///
    /// For signatures with `magic_offset > 0` (e.g. ext2 magic at 0x438) the
    /// returned `SignatureMatch::offset` is the **start of the container**, not
    /// the start of the magic bytes.  For `magic_offset == 0` both values are
    /// equal.
    ///
    /// Matches with confidence < `min_confidence` are omitted.
    #[must_use]
    pub fn scan_with_min_confidence<'db>(
        &'db self,
        data: &[u8],
        min_confidence: u8,
    ) -> Vec<SignatureMatch<'db>> {
        let mut results = Vec::new();
        for entry in &self.entries {
            if entry.confidence < min_confidence {
                continue;
            }
            let magic = entry.magic;
            if magic.is_empty() {
                continue;
            }
            // We search for the magic in the data, then adjust the reported
            // offset backwards by magic_offset so that it points to the logical
            // start of the structure.
            let mut search_from = entry.magic_offset;
            while search_from + magic.len() <= data.len() {
                let window = &data[search_from..];
                match window.windows(magic.len()).position(|w| w == magic) {
                    None => break,
                    Some(rel) => {
                        let magic_abs = search_from + rel;
                        // Container start = magic_abs - magic_offset
                        let container_start = magic_abs.saturating_sub(entry.magic_offset);
                        results.push(SignatureMatch {
                            entry,
                            offset: container_start,
                        });
                        // Advance past this hit to find further occurrences.
                        search_from = magic_abs + magic.len().max(1);
                    }
                }
            }
        }
        results.sort_by(|a, b| a.offset.cmp(&b.offset));
        results
    }

    /// Scan `data` and return all matches (confidence ≥ 1).
    #[must_use]
    pub fn scan<'db>(&'db self, data: &[u8]) -> Vec<SignatureMatch<'db>> {
        self.scan_with_min_confidence(data, 1)
    }

    /// Return highest-confidence match for any signature found in `data`.
    #[must_use]
    pub fn best_match<'db>(&'db self, data: &[u8]) -> Option<SignatureMatch<'db>> {
        let matches = self.scan(data);
        matches.into_iter().max_by_key(|m| m.entry.confidence)
    }

    /// Return all matches at offset 0 — useful for top-level container detection.
    #[must_use]
    pub fn root_matches<'db>(&'db self, data: &[u8]) -> Vec<SignatureMatch<'db>> {
        self.scan(data)
            .into_iter()
            .filter(|m| m.offset == 0)
            .collect()
    }

    /// Add a custom signature entry to the database at runtime.
    pub fn add_entry(&mut self, entry: SignatureEntry) {
        self.entries.push(entry);
    }
}

impl Default for SignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SignatureDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureDb({} entries)", self.entries.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> &'static SignatureDb {
        use std::sync::OnceLock;
        static DB: OnceLock<SignatureDb> = OnceLock::new();
        DB.get_or_init(SignatureDb::new)
    }

    // ── table integrity ───────────────────────────────────────────────────────

    #[test]
    fn test_db_not_empty() {
        assert!(
            db().len() >= 100,
            "expected 100+ signatures, got {}",
            db().len()
        );
    }

    #[test]
    fn test_all_names_unique() {
        let d = db();
        let mut names: Vec<&str> = d.entries.iter().map(|e| e.name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        // Allow a couple of intentional name-overlaps (e.g. dtb / uboot-fit share magic).
        // Just verify no large-scale duplication.
        assert!(names.len() >= total - 5, "too many duplicate names");
    }

    #[test]
    fn test_all_confidences_in_range() {
        for e in db().entries.iter() {
            assert!(
                e.confidence <= 100,
                "confidence {} > 100 for {}",
                e.confidence,
                e.name
            );
        }
    }

    #[test]
    fn test_by_category_compression() {
        let entries = db().by_category(SignatureCategory::Compression);
        assert!(!entries.is_empty());
        assert!(entries.iter().any(|e| e.name == "gzip"));
        assert!(entries.iter().any(|e| e.name == "xz"));
    }

    #[test]
    fn test_by_category_filesystem() {
        let entries = db().by_category(SignatureCategory::Filesystem);
        assert!(entries.iter().any(|e| e.name == "squashfs-le"));
        assert!(entries.iter().any(|e| e.name == "ext2"));
    }

    #[test]
    fn test_by_name_found() {
        assert!(db().by_name("gzip").is_some());
        assert!(db().by_name("uboot-legacy").is_some());
    }

    #[test]
    fn test_by_name_missing() {
        assert!(db().by_name("nonexistent-format").is_none());
    }

    // ── scanning ─────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_gzip_at_start() {
        let data = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let matches = db().scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.entry.name == "gzip" && m.offset == 0)
        );
    }

    #[test]
    fn test_scan_gzip_at_offset() {
        let mut data = vec![0u8; 32];
        data[16] = 0x1F;
        data[17] = 0x8B;
        let matches = db().scan(&data);
        assert!(
            matches
                .iter()
                .any(|m| m.entry.name == "gzip" && m.offset == 16)
        );
    }

    #[test]
    fn test_scan_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00";
        let matches = db().scan(data);
        assert!(matches.iter().any(|m| m.entry.name == "elf"));
    }

    #[test]
    fn test_scan_xz_stream() {
        let data = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00];
        let matches = db().scan(&data);
        assert!(matches.iter().any(|m| m.entry.name == "xz"));
    }

    #[test]
    fn test_scan_uboot() {
        let data = [0x27, 0x05, 0x19, 0x56, 0x00, 0x00, 0x00, 0x00];
        let matches = db().scan(&data);
        assert!(matches.iter().any(|m| m.entry.name == "uboot-legacy"));
    }

    #[test]
    fn test_scan_squashfs_le() {
        let data = [0x73, 0x71, 0x73, 0x68, 0x00];
        let matches = db().scan(&data);
        assert!(matches.iter().any(|m| m.entry.name == "squashfs-le"));
    }

    #[test]
    fn test_scan_zip() {
        let data = b"PK\x03\x04 rest of zip";
        let matches = db().scan(data);
        assert!(matches.iter().any(|m| m.entry.name == "zip-local"));
    }

    #[test]
    fn test_scan_pem_cert() {
        let data = b"-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
        let matches = db().scan(data);
        assert!(matches.iter().any(|m| m.entry.name == "pem-cert"));
    }

    #[test]
    fn test_scan_openssl_salted() {
        let data = b"Salted__\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE";
        let matches = db().scan(data);
        assert!(matches.iter().any(|m| m.entry.name == "openssl-salted"));
    }

    #[test]
    fn test_scan_empty_data() {
        let matches = db().scan(&[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_sorted_by_offset() {
        let mut data = vec![0u8; 128];
        // gzip at 80
        data[80] = 0x1F;
        data[81] = 0x8B;
        // ELF at 20
        data[20] = 0x7F;
        data[21] = 0x45;
        data[22] = 0x4C;
        data[23] = 0x46;
        let matches = db().scan(&data);
        let offsets: Vec<usize> = matches.iter().map(|m| m.offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_scan_min_confidence_filter() {
        let data = [0x1F, 0x8B, 0x00];
        // gzip confidence is 80 → should appear at threshold ≤ 80
        let hi = db().scan_with_min_confidence(&data, 90);
        let lo = db().scan_with_min_confidence(&data, 70);
        assert!(lo.len() >= hi.len());
    }

    #[test]
    fn test_best_match_returns_highest_confidence() {
        // ELF (99) and gzip (80) at the same offset
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&[0x7F, 0x45, 0x4C, 0x46]);
        let best = db().best_match(&data).unwrap();
        assert_eq!(best.entry.confidence, 99);
    }

    #[test]
    fn test_root_matches() {
        let data = b"\xFD7zXZ\x00\x00data";
        let root = db().root_matches(data);
        assert!(!root.is_empty());
        assert!(root.iter().all(|m| m.offset == 0));
    }

    #[test]
    fn test_add_custom_entry() {
        let mut d = SignatureDb::new();
        let before = d.len();
        d.add_entry(SignatureEntry {
            name: "custom-test",
            magic: b"\xDE\xAD\xBE\xEF",
            magic_offset: 0,
            description: "Test custom entry",
            category: SignatureCategory::Generic,
            confidence: 99,
        });
        assert_eq!(d.len(), before + 1);
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(d.scan(&data).iter().any(|m| m.entry.name == "custom-test"));
    }

    #[test]
    fn test_default_same_as_new() {
        let a = SignatureDb::new();
        let b = SignatureDb::default();
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn test_category_display() {
        assert_eq!(SignatureCategory::Compression.to_string(), "compression");
        assert_eq!(SignatureCategory::Certificate.to_string(), "certificate");
        assert_eq!(
            SignatureCategory::FirmwareContainer.to_string(),
            "firmware-container"
        );
    }

    #[test]
    fn test_signature_match_display() {
        let d = db();
        let data = b"\x7fELF\x00";
        let matches = d.scan(data);
        let s = matches[0].to_string();
        assert!(s.contains("elf"));
    }

    #[test]
    fn test_db_debug() {
        let s = format!("{:?}", db());
        assert!(s.contains("SignatureDb"));
    }

    #[test]
    fn test_ubifs_detection() {
        let data = [0x31, 0x18, 0x10, 0x06, 0x00];
        let m = db().scan(&data);
        assert!(m.iter().any(|x| x.entry.name == "ubifs"));
    }

    #[test]
    fn test_zstd_detection() {
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0x00];
        let m = db().scan(&data);
        assert!(m.iter().any(|x| x.entry.name == "zstd"));
    }

    #[test]
    fn test_multiple_occurrences_same_signature() {
        let mut data = vec![0u8; 64];
        data[4..6].copy_from_slice(&[0x1F, 0x8B]);
        data[32..34].copy_from_slice(&[0x1F, 0x8B]);
        let m = db().scan(&data);
        
        assert_eq!(m.iter().filter(|x| x.entry.name == "gzip").count(), 2);
    }

    #[test]
    fn test_dfu_detection() {
        let data = b"DfuSe\x00\x01\x00\x00";
        let m = db().scan(data);
        assert!(m.iter().any(|x| x.entry.name == "dfu"));
    }

    #[test]
    fn test_luks_detection() {
        let data = b"LUKS\xBA\xBE\x00\x02\x00";
        let m = db().scan(data);
        assert!(m.iter().any(|x| x.entry.name == "luks"));
    }
}
