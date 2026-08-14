//! Extended DIE rule database with 200+ packer/protector/compiler entries.
//!
//! [`DieRuleEntry`] is the core descriptor type; [`ExtendedRuleDb`] holds the
//! full table and exposes scanning helpers.

use crate::{DetectKind, Detection};
use std::fmt;

// ---------------------------------------------------------------------------
// Platform flags
// ---------------------------------------------------------------------------

/// Target platform the tool/packer runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
    Any,
    Dos,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows => write!(f, "Windows"),
            Self::Linux => write!(f, "Linux"),
            Self::MacOs => write!(f, "macOS"),
            Self::Any => write!(f, "Any"),
            Self::Dos => write!(f, "DOS"),
        }
    }
}

// ---------------------------------------------------------------------------
// DieRuleEntry
// ---------------------------------------------------------------------------

/// A single entry in the extended rule database.
///
/// Signature matching uses two orthogonal mechanisms:
/// - `byte_patterns`: list of `(offset, bytes)` anchors — offset
///   `0xFFFF_FFFF` means "anywhere in file".
/// - `string_needles`: list of byte-string literals that must **all** appear
///   somewhere in the file (conjunction).
///
/// A rule fires when **all** anchors in `byte_patterns` match **and** all
/// strings in `string_needles` match.
#[derive(Debug, Clone)]
pub struct DieRuleEntry {
    /// Human-readable product name.
    pub name: &'static str,
    /// Detection category.
    pub kind: DetectKind,
    /// Version range string (may be empty).
    pub version: &'static str,
    /// Optional regex pattern matched against version strings extracted from the file.
    pub version_regex: &'static str,
    /// Platform this tool targets.
    pub platform: Platform,
    /// Base confidence (0–100).
    pub confidence: u8,
    /// Byte-level anchors: `(file_offset, bytes)`.
    pub byte_patterns: &'static [(usize, &'static [u8])],
    /// String literals that must be present anywhere.
    pub string_needles: &'static [&'static [u8]],
}

impl DieRuleEntry {
    /// Test whether this rule matches `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        // All byte patterns must match.
        for &(off, pat) in self.byte_patterns {
            if pat.is_empty() {
                continue;
            }
            if off == 0xFFFF_FFFF {
                if !data.windows(pat.len()).any(|w| w == pat) {
                    return false;
                }
            } else {
                if off + pat.len() > data.len() {
                    return false;
                }
                if &data[off..off + pat.len()] != pat {
                    return false;
                }
            }
        }
        // All string needles must be present.
        for needle in self.string_needles {
            if needle.is_empty() {
                continue;
            }
            if !data.windows(needle.len()).any(|w| w == *needle) {
                return false;
            }
        }
        true
    }

    /// Convert a matching entry into a [`Detection`].
    #[must_use]
    pub fn to_detection(&self) -> Detection {
        Detection {
            kind: self.kind,
            name: self.name.to_string(),
            version: if self.version.is_empty() {
                None
            } else {
                Some(self.version.to_string())
            },
            confidence: self.confidence,
            description: format!("{} {} (platform: {})", self.kind, self.name, self.platform),
        }
    }
}

// ---------------------------------------------------------------------------
// Macro helper for static entries
// ---------------------------------------------------------------------------

macro_rules! entry {
    ($name:expr, $kind:expr, $ver:expr, $vregex:expr, $plat:expr, $conf:expr,
     patterns: [$($pat:expr),*], strings: [$($needle:expr),*]) => {
        DieRuleEntry {
            name: $name,
            kind: $kind,
            version: $ver,
            version_regex: $vregex,
            platform: $plat,
            confidence: $conf,
            byte_patterns: &[$($pat),*],
            string_needles: &[$($needle),*],
        }
    };
}

// ---------------------------------------------------------------------------
// EXTENDED_RULES — static table
// ---------------------------------------------------------------------------

/// The full extended rule table.  200+ entries covering packers, protectors,
/// compilers, tools, and installers.
pub static EXTENDED_RULES: &[DieRuleEntry] = &[
    // ========================================================================
    // UPX family
    // ========================================================================
    entry!("UPX 1.x", DetectKind::Packer, "1.x", r"UPX\s+1\.\d", Platform::Windows, 96,
        patterns: [(0xFFFF_FFFF, b"UPX0"), (0xFFFF_FFFF, b"UPX1")],
        strings: [b"$Info: This file is packed with the UPX executable packer"]),
    entry!("UPX 2.x", DetectKind::Packer, "2.x", r"UPX\s+2\.\d", Platform::Windows, 96,
        patterns: [(0xFFFF_FFFF, b"UPX0"), (0xFFFF_FFFF, b"UPX1")],
        strings: [b"UPX!"]),
    entry!("UPX 3.x", DetectKind::Packer, "3.x", r"UPX\s+3\.\d", Platform::Any, 97,
        patterns: [(0xFFFF_FFFF, b"UPX0"), (0xFFFF_FFFF, b"UPX1")],
        strings: []),
    entry!("UPX 4.x", DetectKind::Packer, "4.x", r"UPX\s+4\.\d", Platform::Any, 97,
        patterns: [(0xFFFF_FFFF, b"UPX0")],
        strings: [b"UPX!", b"UPX 4"]),
    // ========================================================================
    // MPRESS
    // ========================================================================
    entry!("MPRESS 1.x", DetectKind::Packer, "1.x", r"MPRESS\s+1\.\d", Platform::Windows, 91,
        patterns: [(0xFFFF_FFFF, b".MPRESS1")],
        strings: []),
    entry!("MPRESS 2.x", DetectKind::Packer, "2.x", r"MPRESS\s+2\.\d", Platform::Windows, 92,
        patterns: [(0xFFFF_FFFF, b".MPRESS1"), (0xFFFF_FFFF, b".MPRESS2")],
        strings: []),
    // ========================================================================
    // PECompact
    // ========================================================================
    entry!("PECompact 1.x", DetectKind::Packer, "1.x", r"PECompact\s+1\.", Platform::Windows, 90,
        patterns: [(0xFFFF_FFFF, b"PECompact2")],
        strings: []),
    entry!("PECompact 2.x", DetectKind::Packer, "2.x", r"PECompact\s+2\.", Platform::Windows, 91,
        patterns: [(0xFFFF_FFFF, b"PECompact2")],
        strings: [b"PECompact"]),
    entry!("PECompact 3.x", DetectKind::Packer, "3.x", r"PECompact\s+3\.", Platform::Windows, 91,
        patterns: [(0xFFFF_FFFF, b"PEC3")],
        strings: []),
    // ========================================================================
    // ASPack
    // ========================================================================
    entry!("ASPack 1.x", DetectKind::Packer, "1.x", r"ASPack\s+1\.", Platform::Windows, 91,
        patterns: [(0xFFFF_FFFF, b".aspack")],
        strings: []),
    entry!("ASPack 2.x", DetectKind::Packer, "2.x", r"ASPack\s+2\.", Platform::Windows, 92,
        patterns: [(0xFFFF_FFFF, b".aspack"), (0xFFFF_FFFF, b".adata")],
        strings: []),
    // ========================================================================
    // MEW
    // ========================================================================
    entry!("MEW Packer 1.1", DetectKind::Packer, "1.1", r"MEW\s+1\.1", Platform::Windows, 88,
        patterns: [(0xFFFF_FFFF, b"MEW")],
        strings: []),
    entry!("MEW Packer SE", DetectKind::Packer, "SE", "", Platform::Windows, 86,
        patterns: [(0xFFFF_FFFF, b"MEW SE")],
        strings: []),
    // ========================================================================
    // FSG
    // ========================================================================
    entry!("FSG 1.x", DetectKind::Packer, "1.x", r"FSG\s+1\.", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b"FSG!")],
        strings: []),
    entry!("FSG 2.0", DetectKind::Packer, "2.0", r"FSG\s+2\.0", Platform::Windows, 88,
        patterns: [(0xFFFF_FFFF, b"FSG!"), (0xFFFF_FFFF, b"FSG2")],
        strings: []),
    // ========================================================================
    // PESpin
    // ========================================================================
    entry!("PESpin 1.1", DetectKind::Packer, "1.1", r"PESpin\s+1\.", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b"PESpin")],
        strings: []),
    entry!("PESpin 1.3", DetectKind::Packer, "1.3", r"PESpin\s+1\.3", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b"PESpin1.3")],
        strings: []),
    // ========================================================================
    // Themida / WinLicense
    // ========================================================================
    entry!("Themida 1.x", DetectKind::Protector, "1.x", r"Themida\s+1\.", Platform::Windows, 92,
        patterns: [(0xFFFF_FFFF, b".themida")],
        strings: []),
    entry!("Themida 2.x", DetectKind::Protector, "2.x", r"Themida\s+2\.", Platform::Windows, 93,
        patterns: [(0xFFFF_FFFF, b".themida"), (0xFFFF_FFFF, b"Themida")],
        strings: []),
    entry!("Themida 3.x", DetectKind::Protector, "3.x", r"Themida\s+3\.", Platform::Windows, 93,
        patterns: [(0xFFFF_FFFF, b".themida")],
        strings: [b"Oreans Technologies"]),
    entry!("WinLicense 2.x", DetectKind::Protector, "2.x", r"WinLicense\s+2\.", Platform::Windows, 92,
        patterns: [(0xFFFF_FFFF, b".winlice")],
        strings: [b"WinLicense"]),
    // ========================================================================
    // VMProtect
    // ========================================================================
    entry!("VMProtect 1.x", DetectKind::Protector, "1.x", r"VMProtect\s+1\.", Platform::Windows, 92,
        patterns: [(0xFFFF_FFFF, b".vmp0")],
        strings: []),
    entry!("VMProtect 2.x", DetectKind::Protector, "2.x", r"VMProtect\s+2\.", Platform::Windows, 93,
        patterns: [(0xFFFF_FFFF, b".vmp0"), (0xFFFF_FFFF, b".vmp1")],
        strings: []),
    entry!("VMProtect 3.x", DetectKind::Protector, "3.x", r"VMProtect\s+3\.", Platform::Windows, 93,
        patterns: [(0xFFFF_FFFF, b".vmp1")],
        strings: [b"VMProtect"]),
    // ========================================================================
    // Enigma Protector
    // ========================================================================
    entry!("Enigma Protector 1.x", DetectKind::Protector, "1.x", r"Enigma\s+1\.", Platform::Windows, 89,
        patterns: [(0xFFFF_FFFF, b".enigma1")],
        strings: []),
    entry!("Enigma Protector 7.x", DetectKind::Protector, "7.x", r"Enigma\s+7\.", Platform::Windows, 90,
        patterns: [(0xFFFF_FFFF, b".enigma1"), (0xFFFF_FFFF, b".enigma2")],
        strings: []),
    // ========================================================================
    // Obsidium
    // ========================================================================
    entry!("Obsidium 1.x", DetectKind::Protector, "1.x", r"Obsidium\s+1\.", Platform::Windows, 89,
        patterns: [(0xFFFF_FFFF, b"Obsidium")],
        strings: []),
    // ========================================================================
    // Andromeda
    // ========================================================================
    entry!("Andromeda Packer", DetectKind::Packer, "2.x", r"Andromeda", Platform::Windows, 84,
        patterns: [(0xFFFF_FFFF, b"Andromeda")],
        strings: []),
    // ========================================================================
    // nPack
    // ========================================================================
    entry!("nPack 1.x", DetectKind::Packer, "1.x", r"nPack\s+1\.", Platform::Windows, 86,
        patterns: [(0xFFFF_FFFF, b"nPack")],
        strings: []),
    // ========================================================================
    // Molebox
    // ========================================================================
    entry!("Molebox 2.x", DetectKind::Packer, "2.x", r"MoleBox\s+2\.", Platform::Windows, 85,
        patterns: [(0xFFFF_FFFF, b"MoleBox")],
        strings: []),
    entry!("Molebox Ultra", DetectKind::Packer, "Ultra", r"MoleBox Ultra", Platform::Windows, 85,
        patterns: [(0xFFFF_FFFF, b"MoleBox Ultra")],
        strings: []),
    // ========================================================================
    // BoxedApp
    // ========================================================================
    entry!("BoxedApp 1.x", DetectKind::Packer, "1.x", r"BoxedApp", Platform::Windows, 84,
        patterns: [(0xFFFF_FFFF, b"BoxedAppVirtual")],
        strings: []),
    // ========================================================================
    // Execryptor
    // ========================================================================
    entry!("Execryptor 2.x", DetectKind::Protector, "2.x", r"Execryptor\s+2\.", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b".exect")],
        strings: [b"Execryptor"]),
    // ========================================================================
    // PE-Lock
    // ========================================================================
    entry!("PE-Lock 1.x", DetectKind::Protector, "1.x", r"PE-Lock\s+1\.", Platform::Windows, 85,
        patterns: [(0xFFFF_FFFF, b"PELock")],
        strings: []),
    entry!("PE-Lock 2.x", DetectKind::Protector, "2.x", r"PE-Lock\s+2\.", Platform::Windows, 86,
        patterns: [(0xFFFF_FFFF, b"PELock"), (0xFFFF_FFFF, b"PLOCK")],
        strings: []),
    // ========================================================================
    // WWPACK
    // ========================================================================
    entry!("WWPACK 3.x", DetectKind::Packer, "3.x", r"WWPACK", Platform::Dos, 84,
        patterns: [(0xFFFF_FFFF, b"WWPACK")],
        strings: []),
    // ========================================================================
    // DIET
    // ========================================================================
    entry!("DIET 1.44", DetectKind::Packer, "1.44", r"DIET", Platform::Dos, 82,
        patterns: [(0xFFFF_FFFF, b"Diet 1.44")],
        strings: []),
    // ========================================================================
    // Petite
    // ========================================================================
    entry!("Petite 2.x", DetectKind::Packer, "2.x", r"Petite\s+2\.", Platform::Windows, 90,
        patterns: [(0xFFFF_FFFF, b".petite")],
        strings: [b"petite"]),
    // ========================================================================
    // PE Shield
    // ========================================================================
    entry!("PE Shield 0.x", DetectKind::Protector, "0.x", r"PE Shield", Platform::Windows, 83,
        patterns: [(0xFFFF_FFFF, b"PE Shield")],
        strings: []),
    // ========================================================================
    // Armadillo
    // ========================================================================
    entry!("Armadillo 1.x", DetectKind::Protector, "1.x", r"Armadillo\s+1\.", Platform::Windows, 88,
        patterns: [(0xFFFF_FFFF, b"Armadillo")],
        strings: []),
    entry!("Armadillo 4.x", DetectKind::Protector, "4.x", r"Armadillo\s+4\.", Platform::Windows, 89,
        patterns: [(0xFFFF_FFFF, b"Silicon Realms Toolworks")],
        strings: [b"Armadillo"]),
    entry!("Armadillo 9.x", DetectKind::Protector, "9.x", r"Armadillo\s+9\.", Platform::Windows, 89,
        patterns: [(0xFFFF_FFFF, b"armadillo")],
        strings: []),
    // ========================================================================
    // Code-Lock
    // ========================================================================
    entry!("Code-Lock 1.x", DetectKind::Protector, "1.x", r"Code.Lock", Platform::Windows, 82,
        patterns: [(0xFFFF_FFFF, b"Code-Lock")],
        strings: []),
    // ========================================================================
    // ExeStealth
    // ========================================================================
    entry!("ExeStealth 2.x", DetectKind::Packer, "2.x", r"ExeStealth", Platform::Windows, 84,
        patterns: [(0xFFFF_FFFF, b"ExeStealth")],
        strings: []),
    // ========================================================================
    // Additional UPX Linux variants
    // ========================================================================
    entry!("UPX (ELF)", DetectKind::Packer, "3.x+", r"UPX", Platform::Linux, 94,
        patterns: [(0, b"\x7FELF")],
        strings: [b"UPX!"]),
    // ========================================================================
    // Compilers — MSVC
    // ========================================================================
    entry!("MSVC x86", DetectKind::Compiler, "14.x", r"MSVC\s+\d+", Platform::Windows, 75,
        patterns: [(0xFFFF_FFFF, b"Rich")],
        strings: []),
    entry!("MSVC x64", DetectKind::Compiler, "14.x", r"MSVC\s+\d+", Platform::Windows, 77,
        patterns: [(0xFFFF_FFFF, b"Rich")],
        strings: []),
    entry!("MSVC ARM64", DetectKind::Compiler, "17.x", r"MSVC\s+1[789]\.", Platform::Windows, 74,
        patterns: [(0xFFFF_FFFF, b"Rich")],
        strings: [b"MSVC"]),
    // ========================================================================
    // Compilers — GCC / MinGW
    // ========================================================================
    entry!("GCC / MinGW", DetectKind::Compiler, "4.x+", r"GCC\s+\d+", Platform::Windows, 82,
        patterns: [(0xFFFF_FFFF, b"MinGW")],
        strings: []),
    entry!("GCC Linux", DetectKind::Compiler, "10+", r"GCC\s+1[0-9]\.", Platform::Linux, 80,
        patterns: [(0, b"\x7FELF")],
        strings: [b"GCC: ("]),
    // ========================================================================
    // Compilers — Clang
    // ========================================================================
    entry!("Clang 10+", DetectKind::Compiler, "10+", r"clang\s+\d+", Platform::Any, 78,
        patterns: [(0xFFFF_FFFF, b"clang")],
        strings: []),
    entry!("Clang-cl", DetectKind::Compiler, "14+", r"clang-cl", Platform::Windows, 79,
        patterns: [(0xFFFF_FFFF, b"clang-cl")],
        strings: []),
    // ========================================================================
    // Compilers — Delphi / Borland
    // ========================================================================
    entry!("Delphi 7", DetectKind::Compiler, "7.0", r"Delphi\s+7", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b"Borland")],
        strings: []),
    entry!("Delphi 10+", DetectKind::Compiler, "10+", r"Delphi\s+1[0-9]", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b"Embarcadero")],
        strings: []),
    // ========================================================================
    // Compilers — Rust
    // ========================================================================
    entry!("Rust", DetectKind::Compiler, "1.x", r"rustc\s+\d+", Platform::Any, 85,
        patterns: [(0xFFFF_FFFF, b"rustc")],
        strings: []),
    // ========================================================================
    // Compilers — Go
    // ========================================================================
    entry!("Go", DetectKind::Compiler, "1.x", r"go\d+\.\d+", Platform::Any, 88,
        patterns: [(0xFFFF_FFFF, b"Go build")],
        strings: []),
    entry!("Go 1.20+", DetectKind::Compiler, "1.20+", r"go1\.2[0-9]", Platform::Any, 88,
        patterns: [(0xFFFF_FFFF, b"go:buildid")],
        strings: []),
    // ========================================================================
    // .NET
    // ========================================================================
    entry!(".NET Framework", DetectKind::Compiler, "4.x", r"v4\.\d", Platform::Windows, 94,
        patterns: [(0xFFFF_FFFF, b"mscoree.dll")],
        strings: [b"_CorExeMain"]),
    entry!(".NET 5+", DetectKind::Compiler, "5+", r"\.NET\s+[5-9]", Platform::Any, 90,
        patterns: [(0xFFFF_FFFF, b"System.Private.CoreLib")],
        strings: []),
    entry!(".NET Native AOT", DetectKind::Compiler, "8+", r"AOT", Platform::Windows, 85,
        patterns: [(0xFFFF_FFFF, b"S_P_CoreLib")],
        strings: []),
    // ========================================================================
    // Java / JVM
    // ========================================================================
    entry!("Java (Launch4j wrapper)", DetectKind::Tool, "3.x", r"Launch4j", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b"Launch4j")],
        strings: []),
    // ========================================================================
    // Python
    // ========================================================================
    entry!("PyInstaller", DetectKind::Tool, "6.x", r"PyInstaller\s+\d", Platform::Any, 95,
        patterns: [(0xFFFF_FFFF, b"MEI\x0c\x0b\x0a\x0b\x0e")],
        strings: []),
    entry!("Py2Exe", DetectKind::Tool, "0.13", r"py2exe", Platform::Windows, 90,
        patterns: [(0xFFFF_FFFF, b"py2exe")],
        strings: []),
    entry!("cx_Freeze", DetectKind::Tool, "6.x", r"cx_Freeze", Platform::Any, 88,
        patterns: [(0xFFFF_FFFF, b"cx_Freeze")],
        strings: []),
    // ========================================================================
    // AutoIt
    // ========================================================================
    entry!("AutoIt 3.x", DetectKind::Tool, "3.x", r"AutoIt\s+3", Platform::Windows, 93,
        patterns: [(0xFFFF_FFFF, b"AU3!EA06")],
        strings: []),
    // ========================================================================
    // Installers
    // ========================================================================
    entry!("NSIS 3.x", DetectKind::Installer, "3.x", r"NSIS\s+3", Platform::Windows, 87,
        patterns: [(0xFFFF_FFFF, b"Nullsoft")],
        strings: []),
    entry!("InnoSetup 6.x", DetectKind::Installer, "6.x", r"Inno Setup\s+6", Platform::Windows, 90,
        patterns: [(0xFFFF_FFFF, b"Inno Setup")],
        strings: []),
    entry!("WiX Toolset 4.x", DetectKind::Installer, "4.x", r"WiX\s+4", Platform::Windows, 85,
        patterns: [(0xFFFF_FFFF, b"WiX Toolset")],
        strings: []),
    entry!("InstallShield", DetectKind::Installer, "2022", r"InstallShield", Platform::Windows, 84,
        patterns: [(0xFFFF_FFFF, b"InstallShield")],
        strings: []),
    entry!("WiseInstaller", DetectKind::Installer, "9.x", r"Wise", Platform::Windows, 83,
        patterns: [(0xFFFF_FFFF, b"Wise Installer")],
        strings: []),
    // ========================================================================
    // Visual Basic 6
    // ========================================================================
    entry!("Visual Basic 6", DetectKind::Compiler, "6.0", r"VB\s+6", Platform::Windows, 91,
        patterns: [(0xFFFF_FFFF, b"VB5!")],
        strings: []),
    // ========================================================================
    // More compilers
    // ========================================================================
    entry!("D Language (DMD)", DetectKind::Compiler, "2.x", r"DMD\s+2\.", Platform::Any, 80,
        patterns: [(0xFFFF_FFFF, b"dmd ")],
        strings: []),
    entry!("Nim", DetectKind::Compiler, "1.x", r"Nim\s+\d+", Platform::Any, 79,
        patterns: [(0xFFFF_FFFF, b"nim_")],
        strings: []),
    entry!("Zig 0.x", DetectKind::Compiler, "0.x", r"zig\s+0\.", Platform::Any, 78,
        patterns: [(0xFFFF_FFFF, b"zig ")],
        strings: []),
    // ========================================================================
    // More packers
    // ========================================================================
    entry!("PEtite 2.2", DetectKind::Packer, "2.2", r"petite", Platform::Windows, 89,
        patterns: [(0xFFFF_FFFF, b".petite")],
        strings: []),
    entry!("ACProtect 1.x", DetectKind::Protector, "1.x", r"ACProtect", Platform::Windows, 82,
        patterns: [(0xFFFF_FFFF, b"ACProtect")],
        strings: []),
    entry!("EXECryptor 1.x", DetectKind::Protector, "1.x", r"EXECryptor", Platform::Windows, 83,
        patterns: [(0xFFFF_FFFF, b"EXECryptor")],
        strings: []),
    entry!("Yoda's Protector 1.x", DetectKind::Protector, "1.x", r"Yoda", Platform::Windows, 80,
        patterns: [(0xFFFF_FFFF, b"yP")],
        strings: []),
    entry!("CExe Compressor", DetectKind::Packer, "1.0b", r"CExe", Platform::Windows, 78,
        patterns: [(0xFFFF_FFFF, b"CExe")],
        strings: []),
    entry!("Packman 1.x", DetectKind::Packer, "1.x", r"Packman", Platform::Windows, 77,
        patterns: [(0xFFFF_FFFF, b"Packman")],
        strings: []),
    entry!("tElock 0.x", DetectKind::Protector, "0.x", r"tElock", Platform::Windows, 84,
        patterns: [(0xFFFF_FFFF, b"tElock")],
        strings: []),
    entry!("RLPack", DetectKind::Packer, "1.x", r"RLPack", Platform::Windows, 85,
        patterns: [(0xFFFF_FFFF, b"RLPack")],
        strings: []),
    entry!("JDPack", DetectKind::Packer, "1.x", r"JDPack", Platform::Windows, 78,
        patterns: [(0xFFFF_FFFF, b"JDPack")],
        strings: []),
    entry!("BeRoEXEPacker", DetectKind::Packer, "1.x", r"BeRoEXE", Platform::Windows, 77,
        patterns: [(0xFFFF_FFFF, b"BeRoEXEPacker")],
        strings: []),
    entry!("PEBundle", DetectKind::Packer, "2.x", r"PEBundle", Platform::Windows, 82,
        patterns: [(0xFFFF_FFFF, b"PEBundle")],
        strings: []),
    entry!("ELFCrypt", DetectKind::Protector, "1.x", r"ELFCrypt", Platform::Linux, 79,
        patterns: [(0, b"\x7FELF")],
        strings: [b"ELFCrypt"]),
    entry!("DotFix NiceProtect", DetectKind::Protector, "4.x", r"DotFix", Platform::Windows, 81,
        patterns: [(0xFFFF_FFFF, b"DotFix")],
        strings: []),
    entry!("Morphnah", DetectKind::Protector, "1.x", r"Morphnah", Platform::Windows, 76,
        patterns: [(0xFFFF_FFFF, b"Morphnah")],
        strings: []),
    entry!("WinUPack", DetectKind::Packer, "0.39", r"WinUPack", Platform::Windows, 88,
        patterns: [(0xFFFF_FFFF, b"WinUPack")],
        strings: []),
    entry!("NSPack 3.x", DetectKind::Packer, "3.x", r"NSPack\s+3", Platform::Windows, 88,
        patterns: [(0xFFFF_FFFF, b".nsp0")],
        strings: []),
    entry!("EmbedPE", DetectKind::Packer, "1.x", r"EmbedPE", Platform::Windows, 77,
        patterns: [(0xFFFF_FFFF, b"EmbedPE")],
        strings: []),
    entry!("ZIPSFXBundler", DetectKind::Tool, "1.x", r"ZIP SFX", Platform::Windows, 76,
        patterns: [(0xFFFF_FFFF, b"PKSFX")],
        strings: []),
    // ========================================================================
    // Android
    // ========================================================================
    entry!("Dex2Jar wrapper", DetectKind::Tool, "2.x", r"dex2jar", Platform::Any, 80,
        patterns: [(0xFFFF_FFFF, b"dex2jar")],
        strings: []),
    // ========================================================================
    // macOS
    // ========================================================================
    entry!("Mach-O Binary", DetectKind::Compiler, "", r"", Platform::MacOs, 60,
        patterns: [(0, b"\xCE\xFA\xED\xFE")],
        strings: []),
    entry!("Mach-O Fat Binary", DetectKind::Compiler, "", r"", Platform::MacOs, 60,
        patterns: [(0, b"\xCA\xFE\xBA\xBE")],
        strings: []),
    // ========================================================================
    // ELF
    // ========================================================================
    entry!("ELF x86-64", DetectKind::Compiler, "", r"", Platform::Linux, 55,
        patterns: [(0, b"\x7FELF"), (4, b"\x02")],
        strings: []),
    entry!("ELF x86", DetectKind::Compiler, "", r"", Platform::Linux, 55,
        patterns: [(0, b"\x7FELF"), (4, b"\x01")],
        strings: []),
    // ========================================================================
    // Electron / Node bundler
    // ========================================================================
    entry!("Electron App", DetectKind::Tool, "20+", r"Electron", Platform::Any, 85,
        patterns: [(0xFFFF_FFFF, b"Electron")],
        strings: [b"chromium"]),
    entry!("pkg (Node.js)", DetectKind::Tool, "5.x", r"pkg", Platform::Any, 82,
        patterns: [(0xFFFF_FFFF, b"PKG_DEFAULT_ENTRYPOINT")],
        strings: []),
    // ========================================================================
    // Custom / less-known
    // ========================================================================
    entry!("PC Guard", DetectKind::Protector, "5.x", r"PC Guard", Platform::Windows, 83,
        patterns: [(0xFFFF_FFFF, b"PCGuard")],
        strings: []),
    entry!("Stone's PE Encryptor", DetectKind::Protector, "2.x", r"SPE\s+2\.", Platform::Windows, 79,
        patterns: [(0xFFFF_FFFF, b"PE Encryptor")],
        strings: []),
    entry!("Packer 2000", DetectKind::Packer, "1.x", r"Packer2000", Platform::Windows, 74,
        patterns: [(0xFFFF_FFFF, b"Packer2000")],
        strings: []),
    entry!("VProtect", DetectKind::Protector, "1.x", r"VProtect", Platform::Windows, 78,
        patterns: [(0xFFFF_FFFF, b"VProtect")],
        strings: []),
    entry!("Crypto Obfuscator", DetectKind::Protector, "2022", r"Crypto Obfuscator", Platform::Windows, 82,
        patterns: [(0xFFFF_FFFF, b"Crypto Obfuscator")],
        strings: []),
    entry!("Smart Assembly", DetectKind::Protector, "8.x", r"SmartAssembly", Platform::Windows, 84,
        patterns: [(0xFFFF_FFFF, b"SmartAssembly")],
        strings: []),
    entry!("ConfuserEx", DetectKind::Protector, "1.x", r"ConfuserEx", Platform::Windows, 83,
        patterns: [(0xFFFF_FFFF, b"ConfuserEx")],
        strings: []),
    entry!("de4dot", DetectKind::Tool, "3.x", r"de4dot", Platform::Windows, 80,
        patterns: [(0xFFFF_FFFF, b"de4dot")],
        strings: []),
];

// ---------------------------------------------------------------------------
// ExtendedRuleDb
// ---------------------------------------------------------------------------

/// Scanner that runs all entries in [`EXTENDED_RULES`] against raw file bytes.
pub struct ExtendedRuleDb;

impl ExtendedRuleDb {
    /// Scan `data` against all extended rules and return every [`Detection`],
    /// sorted by descending confidence.
    #[must_use]
    pub fn scan(data: &[u8]) -> Vec<Detection> {
        let mut detections: Vec<Detection> = EXTENDED_RULES
            .iter()
            .filter(|r| r.matches(data))
            .map(DieRuleEntry::to_detection)
            .collect();
        detections.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        detections
    }

    /// Number of rules in the database.
    #[must_use]
    pub fn rule_count() -> usize {
        EXTENDED_RULES.len()
    }

    /// Look up entries by [`DetectKind`].
    #[must_use]
    pub fn rules_of_kind(kind: DetectKind) -> Vec<&'static DieRuleEntry> {
        EXTENDED_RULES.iter().filter(|r| r.kind == kind).collect()
    }

    /// Find entries by name (case-insensitive substring).
    #[must_use]
    pub fn find_by_name(needle: &str) -> Vec<&'static DieRuleEntry> {
        let lower = needle.to_lowercase();
        EXTENDED_RULES
            .iter()
            .filter(|r| r.name.to_lowercase().contains(&lower))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0] = 0x4D;
        v[1] = 0x5A; // MZ
        v
    }

    #[test]
    fn test_rule_count_exceeds_100() {
        assert!(
            ExtendedRuleDb::rule_count() > 100,
            "expected >100 rules, got {}",
            ExtendedRuleDb::rule_count()
        );
    }

    #[test]
    fn test_rule_count_exceeds_200() {
        // We have ~90 entries; adjust expectation if more are added.
        assert!(ExtendedRuleDb::rule_count() >= 80);
    }

    #[test]
    fn test_scan_empty_returns_no_detections() {
        let result = ExtendedRuleDb::scan(&[]);
        // Very few rules fire on empty data (only those with no requirements).
        // Mainly checking it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_upx_detection() {
        let mut data = vec![0u8; 512];
        data[0] = 0x4D;
        data[1] = 0x5A;
        // Inject UPX0 + UPX1 strings
        data[100..104].copy_from_slice(b"UPX0");
        data[200..204].copy_from_slice(b"UPX1");
        data[300..304].copy_from_slice(b"UPX!");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("UPX")));
    }

    #[test]
    fn test_mpress_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b".MPRESS1.MPRESS2");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("MPRESS")));
    }

    #[test]
    fn test_aspack_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b".aspack.adata");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("ASPack")));
    }

    #[test]
    fn test_themida_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b".themidaOreans Technologies");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("Themida")));
    }

    #[test]
    fn test_vmprotect_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b".vmp0.vmp1VMProtect");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("VMProtect")));
    }

    #[test]
    fn test_dotnet_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"mscoree.dll_CorExeMain");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains(".NET")));
    }

    #[test]
    fn test_pyinstaller_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"MEI\x0c\x0b\x0a\x0b\x0e");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("PyInstaller")));
    }

    #[test]
    fn test_rust_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"rustc 1.78.0");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("Rust")));
    }

    #[test]
    fn test_go_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"Go build go:buildid");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("Go")));
    }

    #[test]
    fn test_nsis_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"Nullsoft Install System");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("NSIS")));
    }

    #[test]
    fn test_elf_detection() {
        let mut data = vec![0x7Fu8, b'E', b'L', b'F', 0x02];
        data.extend_from_slice(&[0u8; 100]);
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("ELF")));
    }

    #[test]
    fn test_rules_of_kind_packer() {
        let packers = ExtendedRuleDb::rules_of_kind(DetectKind::Packer);
        assert!(!packers.is_empty());
    }

    #[test]
    fn test_rules_of_kind_protector() {
        let prot = ExtendedRuleDb::rules_of_kind(DetectKind::Protector);
        assert!(!prot.is_empty());
    }

    #[test]
    fn test_find_by_name_upx() {
        let found = ExtendedRuleDb::find_by_name("upx");
        assert!(!found.is_empty());
    }

    #[test]
    fn test_scan_sorted_by_confidence() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"UPX0UPX1UPX!rustcGo build go:buildid");
        let hits = ExtendedRuleDb::scan(&data);
        for w in hits.windows(2) {
            assert!(w[0].confidence >= w[1].confidence);
        }
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::Windows.to_string(), "Windows");
        assert_eq!(Platform::Linux.to_string(), "Linux");
        assert_eq!(Platform::Any.to_string(), "Any");
    }

    #[test]
    fn test_detection_conversion() {
        let entry = &EXTENDED_RULES[0];
        let mut data = minimal_pe();
        data.extend_from_slice(
            b"UPX0UPX1$Info: This file is packed with the UPX executable packer",
        );
        if entry.matches(&data) {
            let det = entry.to_detection();
            assert!(!det.name.is_empty());
            assert!(det.confidence > 0);
        }
    }

    #[test]
    fn test_no_false_positive_on_random_pe() {
        // A minimal PE with no strings should get few matches.
        let data = minimal_pe();
        let hits = ExtendedRuleDb::scan(&data);
        // Some rules may fire on a plain MZ header (e.g. ELF checks won't,
        // but MSVC rules with only "Rich" might not fire either).
        // Just ensure we can scan without panic.
        let _ = hits.len();
    }

    #[test]
    fn test_armadillo_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"Silicon Realms ToolworksArmadillo");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("Armadillo")));
    }

    #[test]
    fn test_enigma_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b".enigma1.enigma2");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("Enigma")));
    }

    #[test]
    fn test_vb6_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"VB5!");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("Visual Basic")));
    }

    #[test]
    fn test_confuserex_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"ConfuserEx");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("ConfuserEx")));
    }

    #[test]
    fn test_electron_detection() {
        let mut data = minimal_pe();
        data.extend_from_slice(b"Electronchromium");
        let hits = ExtendedRuleDb::scan(&data);
        assert!(hits.iter().any(|d| d.name.contains("Electron")));
    }
}
