//! DIE-compatible hex-pattern signature database with 60+ compiler/packer/protector
//! entries.
//!
//! **Distinct from [`crate::signature_db`]**, which uses the `Matcher` combinator
//! DSL (byte-at, string-contains, entropy-range, …).  This module uses raw hex
//! pattern strings matched at the entry-point or anywhere in the file, and is
//! consumed by [`crate::detector_engine`].
//!
//! **Distinct from [`crate::die_signatures`]**, which implements the JavaScript-like
//! DIE DSL for full condition expressions.

use std::collections::HashMap;

/// Category of a DIE signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DieCategory {
    Compiler,
    Linker,
    Packer,
    Protector,
    Installer,
    Library,
    Runtime,
    Overlay,
    Other,
}

impl std::fmt::Display for DieCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single DIE-format detection signature.
#[derive(Debug, Clone)]
pub struct DieSignature {
    pub id: u32,
    pub name: &'static str,
    pub version_hint: Option<&'static str>,
    pub category: DieCategory,
    pub ep_only: bool,
    pub section: Option<&'static str>,
    /// Byte pattern in hex; `??` = wildcard byte.
    pub pattern: &'static str,
    /// Optional additional string to match anywhere in the file.
    pub also_contains: Option<&'static str>,
}

impl DieSignature {
    /// Try to match this signature against the given binary data and entry-point bytes.
    pub fn matches(&self, data: &[u8], ep_bytes: &[u8]) -> bool {
        let target = if self.ep_only { ep_bytes } else { data };
        if target.is_empty() { return false; }
        // Try anchored match first, then fall back to a search within the
        // target. Some EP buffers contain a prologue that the pattern lives
        // a few bytes into.
        if !match_hex_pattern(self.pattern, target) && find_hex_pattern(self.pattern, target).is_none() {
            return false;
        }
        if let Some(also) = self.also_contains {
            let needle = also.as_bytes();
            if !data.windows(needle.len()).any(|w| w == needle) {
                return false;
            }
        }
        true
    }
}

/// Parse a hex pattern string like "4D 5A 90 ?? ?? 00" into bytes and mask.
pub fn parse_hex_pattern(pattern: &str) -> (Vec<u8>, Vec<bool>) {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for token in pattern.split_whitespace() {
        if token == "??" || token == "?" {
            bytes.push(0);
            mask.push(false); // wildcard
        } else {
            bytes.push(u8::from_str_radix(token, 16).unwrap_or(0));
            mask.push(true);  // fixed
        }
    }
    (bytes, mask)
}

/// Match a hex pattern against the start of a byte slice.
pub fn match_hex_pattern(pattern: &str, data: &[u8]) -> bool {
    let (bytes, mask) = parse_hex_pattern(pattern);
    if data.len() < bytes.len() { return false; }
    bytes.iter().zip(mask.iter()).zip(data.iter()).all(|((b, &fixed), d)| {
        !fixed || b == d
    })
}

/// Search for a hex pattern anywhere in a byte slice.
pub fn find_hex_pattern(pattern: &str, data: &[u8]) -> Option<usize> {
    let (bytes, mask) = parse_hex_pattern(pattern);
    if bytes.is_empty() || data.len() < bytes.len() { return None; }
    data.windows(bytes.len()).position(|w| {
        bytes.iter().zip(mask.iter()).zip(w.iter()).all(|((b, &fixed), d)| {
            !fixed || b == d
        })
    })
}

/// The full signature database.
pub struct DieSignatureDatabase {
    pub signatures: Vec<DieSignature>,
    by_category: HashMap<DieCategory, Vec<usize>>,
}

impl DieSignatureDatabase {
    pub fn new() -> Self {
        let sigs = build_signatures();
        let mut by_category: HashMap<DieCategory, Vec<usize>> = HashMap::new();
        for (i, s) in sigs.iter().enumerate() {
            by_category.entry(s.category).or_default().push(i);
        }
        Self { signatures: sigs, by_category }
    }

    pub fn len(&self) -> usize { self.signatures.len() }

    pub fn by_category(&self, cat: DieCategory) -> Vec<&DieSignature> {
        self.by_category.get(&cat)
            .map(|idxs| idxs.iter().map(|&i| &self.signatures[i]).collect())
            .unwrap_or_default()
    }

    /// Scan a binary and return all matching signatures.
    pub fn scan(&self, data: &[u8], ep_bytes: &[u8]) -> Vec<&DieSignature> {
        self.signatures.iter().filter(|s| s.matches(data, ep_bytes)).collect()
    }

    /// Scan and return only the highest-priority match per category.
    pub fn scan_best(&self, data: &[u8], ep_bytes: &[u8]) -> HashMap<DieCategory, &DieSignature> {
        let mut result = HashMap::new();
        for sig in self.signatures.iter().filter(|s| s.matches(data, ep_bytes)) {
            result.entry(sig.category).or_insert(sig);
        }
        result
    }
}

impl Default for DieSignatureDatabase {
    fn default() -> Self { Self::new() }
}

fn build_signatures() -> Vec<DieSignature> {
    let mut id = 0u32;
    let mut next = || { id += 1; id };

    vec![
        // ─── Compilers: MSVC ──────────────────────────────────────────────
        DieSignature { id: next(), name: "MSVC", version_hint: Some("14.x (VS2015-2022)"),
            category: DieCategory::Compiler, ep_only: false, section: Some(".text"),
            pattern: "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20",
            also_contains: Some("vcruntime140.dll") },
        DieSignature { id: next(), name: "MSVC", version_hint: Some("6.0 (VC6)"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00",
            also_contains: None },
        DieSignature { id: next(), name: "MSVC", version_hint: Some("7.0-7.1 (VS2002-2003)"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "6A 00 68 00 10 00 00 E8 ?? ?? ?? ?? E9 ?? ?? ?? ??",
            also_contains: None },
        DieSignature { id: next(), name: "MSVC", version_hint: Some("8.0 (VS2005)"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? CC 55 8B EC",
            also_contains: None },
        DieSignature { id: next(), name: "MSVC", version_hint: Some("9.0 (VS2008)"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "FF 25 ?? ?? ?? ?? 55 8B EC 51",
            also_contains: Some("msvcp90.dll") },
        DieSignature { id: next(), name: "MSVC", version_hint: Some("10.0-11.0 (VS2010-2012)"),
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28",
            also_contains: Some("msvcp100.dll") },

        // ─── Compilers: GCC ───────────────────────────────────────────────
        DieSignature { id: next(), name: "GCC", version_hint: Some("3.x MinGW"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 89 E5 83 EC ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ??",
            also_contains: None },
        DieSignature { id: next(), name: "GCC", version_hint: Some("4.x MinGW-w64"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 C3",
            also_contains: Some("libgcc_s_seh-1.dll") },
        DieSignature { id: next(), name: "GCC", version_hint: Some("ELF"),
            category: DieCategory::Compiler, ep_only: false, section: Some(".comment"),
            pattern: "47 43 43 3A 20 28", // "GCC: ("
            also_contains: None },
        DieSignature { id: next(), name: "GCC", version_hint: Some("5.x"),
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC",
            also_contains: None },
        DieSignature { id: next(), name: "GCC", version_hint: Some("RISC-V"),
            category: DieCategory::Compiler, ep_only: false, section: Some(".comment"),
            pattern: "47 43 43 3A 20 28 52 49 53 43 2D 56", // "GCC: (RISC-V"
            also_contains: None },

        // ─── Compilers: Clang ──────────────────────────────────────────────
        DieSignature { id: next(), name: "Clang", version_hint: Some("3.x-4.x"),
            category: DieCategory::Compiler, ep_only: false, section: Some(".comment"),
            pattern: "63 6C 61 6E 67 20 76 65 72 73 69 6F 6E", // "clang version"
            also_contains: None },
        DieSignature { id: next(), name: "Clang", version_hint: Some("LLVM IR"),
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "4C 4C 56 4D 20 43 6F 6D 70 69 6C 65 72", // "LLVM Compiler"
            also_contains: None },
        DieSignature { id: next(), name: "Clang/LLVM", version_hint: Some("Apple"),
            category: DieCategory::Compiler, ep_only: false, section: Some("__TEXT"),
            pattern: "41 70 70 6C 65 20 4C 4C 56 4D", // "Apple LLVM"
            also_contains: None },

        // ─── Compilers: Delphi ────────────────────────────────────────────
        DieSignature { id: next(), name: "Delphi", version_hint: Some("2-3"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ??",
            also_contains: None },
        DieSignature { id: next(), name: "Delphi", version_hint: Some("4-5"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 EC",
            also_contains: None },
        DieSignature { id: next(), name: "Delphi", version_hint: Some("6-7"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0",
            also_contains: None },
        DieSignature { id: next(), name: "Delphi", version_hint: Some("XE+"),
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "E8 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8",
            also_contains: Some("Embarcadero") },
        DieSignature { id: next(), name: "Delphi", version_hint: Some("Tokyo/Rio"),
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57",
            also_contains: Some("Embarcadero") },

        // ─── Compilers: Visual Basic ──────────────────────────────────────
        DieSignature { id: next(), name: "VB6", version_hint: Some("6.0"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30",
            also_contains: Some("MSVBVM60.DLL") },
        DieSignature { id: next(), name: "VB5", version_hint: Some("5.0"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30",
            also_contains: Some("MSVBVM50.DLL") },

        // ─── Compilers: .NET ──────────────────────────────────────────────
        DieSignature { id: next(), name: ".NET", version_hint: Some("2.0"),
            category: DieCategory::Runtime, ep_only: false, section: Some(".text"),
            pattern: "FF 25 ?? ?? ?? ?? 00 00 00 00 00 00 00 00",
            also_contains: Some("mscoree.dll") },
        DieSignature { id: next(), name: ".NET", version_hint: Some("4.x"),
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "FF 25 ?? ?? ?? ??",
            also_contains: Some("_CorExeMain") },
        DieSignature { id: next(), name: ".NET NativeAOT", version_hint: None,
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "48 83 EC 28 E8 ?? ?? ?? ??",
            also_contains: Some("System.Private.CoreLib") },

        // ─── Compilers: Other ─────────────────────────────────────────────
        DieSignature { id: next(), name: "Rust", version_hint: None,
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "72 75 73 74 63", // "rustc"
            also_contains: None },
        DieSignature { id: next(), name: "Go", version_hint: None,
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "47 6F 20 62 75 69 6C 64 20 69 44", // "Go build iD"
            also_contains: None },
        DieSignature { id: next(), name: "Free Pascal", version_hint: None,
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 85 C0",
            also_contains: Some("FPC ") },
        DieSignature { id: next(), name: "Nim", version_hint: None,
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "4E 69 6D 4D 61 69 6E", // "NimMain"
            also_contains: None },
        DieSignature { id: next(), name: "Zig", version_hint: None,
            category: DieCategory::Compiler, ep_only: false, section: Some(".comment"),
            pattern: "5A 69 67 20", // "Zig "
            also_contains: None },
        DieSignature { id: next(), name: "Python (CPython)", version_hint: None,
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "50 79 49 6E 69 74 69 61 6C 69 7A 65", // "PyInitialize"
            also_contains: None },
        DieSignature { id: next(), name: "Borland C++", version_hint: Some("5.x"),
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 8B EC B9 ?? ?? ?? ?? 6A 00 6A 00 49 75 F9",
            also_contains: None },
        DieSignature { id: next(), name: "Digital Mars C++", version_hint: None,
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 8B EC 83 EC ?? 8B 45 08 85 C0 75 07",
            also_contains: Some("snn.lib") },
        DieSignature { id: next(), name: "Open Watcom", version_hint: None,
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "BF ?? ?? ?? ?? BE ?? ?? ?? ?? FC F3 A4",
            also_contains: None },
        DieSignature { id: next(), name: "LCC-Win32", version_hint: None,
            category: DieCategory::Compiler, ep_only: true, section: None,
            pattern: "55 8B EC 83 EC ?? 56 57 8B 7D 08 8B F7",
            also_contains: Some("lccrt.lib") },
        DieSignature { id: next(), name: "TCC (Tiny C Compiler)", version_hint: None,
            category: DieCategory::Compiler, ep_only: false, section: None,
            pattern: "54 43 43 20 ", // "TCC "
            also_contains: None },

        // ─── Packers: UPX ─────────────────────────────────────────────────
        DieSignature { id: next(), name: "UPX", version_hint: Some("3.9x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57",
            also_contains: Some("UPX0") },
        DieSignature { id: next(), name: "UPX", version_hint: Some("3.x NRV"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? FC FF 15",
            also_contains: Some("UPX!") },
        DieSignature { id: next(), name: "UPX", version_hint: Some("64-bit"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "53 56 57 55 52 51 FC 48 8D 77",
            also_contains: Some("UPX0") },
        DieSignature { id: next(), name: "UPX (modified)", version_hint: None,
            category: DieCategory::Packer, ep_only: false, section: None,
            pattern: "55 50 58 21", // "UPX!"
            also_contains: None },

        // ─── Packers: MPRESS ──────────────────────────────────────────────
        DieSignature { id: next(), name: "MPRESS", version_hint: Some("2.x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30",
            also_contains: Some("MPRESS1") },
        DieSignature { id: next(), name: "MPRESS", version_hint: Some("1.x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "E8 ?? ?? ?? ?? EB 02 CD 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68",
            also_contains: Some("MPRESS1") },

        // ─── Packers: PECompact ───────────────────────────────────────────
        DieSignature { id: next(), name: "PECompact", version_hint: Some("2.x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 00 00 00 00",
            also_contains: Some("PEC2") },
        DieSignature { id: next(), name: "PECompact", version_hint: Some("3.x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "E9 ?? ?? ?? ?? 00 00 00 50 45 43 6F 6D 70 61 63 74 33",
            also_contains: None },

        // ─── Packers: ASPack ──────────────────────────────────────────────
        DieSignature { id: next(), name: "ASPack", version_hint: Some("2.x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8",
            also_contains: None },
        DieSignature { id: next(), name: "ASPack", version_hint: Some("1.x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "60 E8 00 00 00 00 5D EB 03 ?? ?? ?? 90",
            also_contains: None },

        // ─── Packers: NsPack ──────────────────────────────────────────────
        DieSignature { id: next(), name: "NsPack", version_hint: Some("3.x"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "9C 60 E8 00 00 00 00 5D B8 ?? ?? ?? ?? 2D ?? ?? ?? ??",
            also_contains: None },

        // ─── Packers: FSG ─────────────────────────────────────────────────
        DieSignature { id: next(), name: "FSG", version_hint: Some("2.0"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "BE ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 39 1E 75 02 EB 1D FF 36",
            also_contains: None },

        // ─── Packers: MEW ─────────────────────────────────────────────────
        DieSignature { id: next(), name: "MEW", version_hint: Some("11 SE 1.2"),
            category: DieCategory::Packer, ep_only: true, section: None,
            pattern: "E9 ?? ?? ?? ?? 4D 45 57 20 53 45",
            also_contains: None },

        // ─── Protectors: Themida ──────────────────────────────────────────
        DieSignature { id: next(), name: "Themida", version_hint: Some("2.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "EB ?? ?? ?? ?? ?? ?? ?? 8B 04 24 83 C0 ?? 2B C4 85 C0",
            also_contains: Some("Themida") },
        DieSignature { id: next(), name: "Themida", version_hint: Some("3.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00",
            also_contains: None },

        // ─── Protectors: VMProtect ────────────────────────────────────────
        DieSignature { id: next(), name: "VMProtect", version_hint: Some("1.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3",
            also_contains: Some(".vmp0") },
        DieSignature { id: next(), name: "VMProtect", version_hint: Some("2.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "9C 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ??",
            also_contains: Some(".vmp0") },
        DieSignature { id: next(), name: "VMProtect", version_hint: Some("3.x"),
            category: DieCategory::Protector, ep_only: false, section: Some(".vmp0"),
            pattern: "4D 5A",
            also_contains: Some(".vmp1") },

        // ─── Protectors: Obsidium ─────────────────────────────────────────
        DieSignature { id: next(), name: "Obsidium", version_hint: Some("1.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "E8 ?? ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? EB ?? 5D",
            also_contains: None },

        // ─── Protectors: Enigma ───────────────────────────────────────────
        DieSignature { id: next(), name: "Enigma Protector", version_hint: Some("1.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "E8 00 00 00 00 5B 83 EB 05 EB 04 5B 83 EB 05 EB FB",
            also_contains: None },
        DieSignature { id: next(), name: "Enigma Protector", version_hint: Some("4.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "60 E8 00 00 00 00 5D B8 ?? ?? ?? ?? 2B E8 8D B5",
            also_contains: None },
        DieSignature { id: next(), name: "Enigma Protector", version_hint: Some("6.x"),
            category: DieCategory::Protector, ep_only: false, section: None,
            pattern: "45 6E 69 67 6D 61 20 50 72 6F 74 65 63 74 6F 72", // "Enigma Protector"
            also_contains: None },

        // ─── Protectors: ExeCryptor ───────────────────────────────────────
        DieSignature { id: next(), name: "ExeCryptor", version_hint: None,
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "60 9C FC BE ?? ?? ?? ?? BF ?? ?? ?? ?? 57 83 CD FF EB 10",
            also_contains: None },

        // ─── Protectors: Armadillo ────────────────────────────────────────
        DieSignature { id: next(), name: "Armadillo", version_hint: Some("4.x-7.x"),
            category: DieCategory::Protector, ep_only: true, section: None,
            pattern: "55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50",
            also_contains: Some("Silicon Realms") },

        // ─── Installers ──────────────────────────────────────────────────
        DieSignature { id: next(), name: "NSIS", version_hint: Some("2.x"),
            category: DieCategory::Installer, ep_only: false, section: None,
            pattern: "4E 75 6C 6C 73 6F 66 74 49 6E 73 74", // "NullsoftInst"
            also_contains: None },
        DieSignature { id: next(), name: "InnoSetup", version_hint: Some("5.x"),
            category: DieCategory::Installer, ep_only: false, section: None,
            pattern: "49 6E 6E 6F 53 65 74 75 70 20", // "InnoSetup "
            also_contains: None },
        DieSignature { id: next(), name: "InstallShield", version_hint: None,
            category: DieCategory::Installer, ep_only: false, section: None,
            pattern: "49 6E 73 74 61 6C 6C 53 68 69 65 6C 64", // "InstallShield"
            also_contains: None },
        DieSignature { id: next(), name: "WiX", version_hint: None,
            category: DieCategory::Installer, ep_only: false, section: None,
            pattern: "57 69 58 20 42 6F 6F 74 73 74 72 61 70 70 65 72", // "WiX Bootstrapper"
            also_contains: None },

        // ─── Linkers ─────────────────────────────────────────────────────
        DieSignature { id: next(), name: "Microsoft Linker", version_hint: Some("14.x"),
            category: DieCategory::Linker, ep_only: false, section: None,
            pattern: "4D 69 63 72 6F 73 6F 66 74 20 4C 69 6E 6B 65 72", // "Microsoft Linker"
            also_contains: None },
        DieSignature { id: next(), name: "GNU ld", version_hint: None,
            category: DieCategory::Linker, ep_only: false, section: Some(".comment"),
            pattern: "47 4E 55 20 6C 64", // "GNU ld"
            also_contains: None },
        DieSignature { id: next(), name: "LLD (LLVM Linker)", version_hint: None,
            category: DieCategory::Linker, ep_only: false, section: Some(".comment"),
            pattern: "4C 4C 44 20 ", // "LLD "
            also_contains: None },

        // ─── PyInstaller / cx_Freeze / Nuitka ────────────────────────────
        DieSignature { id: next(), name: "PyInstaller", version_hint: Some("3.x"),
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "4D 45 49 30 31 32 00", // "MEI012\0"
            also_contains: None },
        DieSignature { id: next(), name: "PyInstaller", version_hint: Some("4.x-5.x"),
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "50 59 49 4E 53 54 30", // "PYINST0"
            also_contains: None },
        DieSignature { id: next(), name: "cx_Freeze", version_hint: None,
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "63 78 5F 46 72 65 65 7A 65", // "cx_Freeze"
            also_contains: None },
        DieSignature { id: next(), name: "Nuitka", version_hint: None,
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "4E 75 69 74 6B 61", // "Nuitka"
            also_contains: None },

        // ─── AutoIT / AutoHotkey ──────────────────────────────────────────
        DieSignature { id: next(), name: "AutoIT", version_hint: Some("3.x"),
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "41 75 74 6F 49 74 53 63 72 69 70 74", // "AutoItScript"
            also_contains: None },
        DieSignature { id: next(), name: "AutoHotkey", version_hint: None,
            category: DieCategory::Runtime, ep_only: false, section: None,
            pattern: "41 75 74 6F 48 6F 74 6B 65 79", // "AutoHotkey"
            also_contains: None },

        // ─── .NET Obfuscators ─────────────────────────────────────────────
        DieSignature { id: next(), name: "ConfuserEx", version_hint: None,
            category: DieCategory::Protector, ep_only: false, section: None,
            pattern: "43 6F 6E 66 75 73 65 72 45 78", // "ConfuserEx"
            also_contains: None },
        DieSignature { id: next(), name: "Dotfuscator", version_hint: None,
            category: DieCategory::Protector, ep_only: false, section: None,
            pattern: "44 6F 74 66 75 73 63 61 74 6F 72", // "Dotfuscator"
            also_contains: None },
        DieSignature { id: next(), name: "SmartAssembly", version_hint: None,
            category: DieCategory::Protector, ep_only: false, section: None,
            pattern: "53 6D 61 72 74 41 73 73 65 6D 62 6C 79", // "SmartAssembly"
            also_contains: None },
        DieSignature { id: next(), name: "ILProtector", version_hint: None,
            category: DieCategory::Protector, ep_only: false, section: None,
            pattern: "49 4C 50 72 6F 74 65 63 74 6F 72", // "ILProtector"
            also_contains: None },
        DieSignature { id: next(), name: ".NET Reactor", version_hint: None,
            category: DieCategory::Protector, ep_only: false, section: None,
            pattern: "4E 45 54 52 65 61 63 74 6F 72", // "NETReactor"
            also_contains: None },

        // ─── Runtime libraries ────────────────────────────────────────────
        DieSignature { id: next(), name: "OpenSSL", version_hint: None,
            category: DieCategory::Library, ep_only: false, section: None,
            pattern: "4F 70 65 6E 53 53 4C 20 ", // "OpenSSL "
            also_contains: None },
        DieSignature { id: next(), name: "zlib", version_hint: None,
            category: DieCategory::Library, ep_only: false, section: None,
            pattern: "78 9C", // zlib compressed data header
            also_contains: Some("inflate") },
        DieSignature { id: next(), name: "SQLite", version_hint: None,
            category: DieCategory::Library, ep_only: false, section: None,
            pattern: "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33", // "SQLite format 3"
            also_contains: None },

        // ─── Overlay ─────────────────────────────────────────────────────
        DieSignature { id: next(), name: "ZIP overlay", version_hint: None,
            category: DieCategory::Overlay, ep_only: false, section: None,
            pattern: "50 4B 03 04", // "PK\x03\x04"
            also_contains: None },
        DieSignature { id: next(), name: "RAR overlay", version_hint: None,
            category: DieCategory::Overlay, ep_only: false, section: None,
            pattern: "52 61 72 21 1A 07", // "Rar!\x1a\x07"
            also_contains: None },
        DieSignature { id: next(), name: "7-Zip SFX", version_hint: None,
            category: DieCategory::Packer, ep_only: false, section: None,
            pattern: "37 7A BC AF 27 1C", // 7z magic
            also_contains: None },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_has_enough_signatures() {
        let db = DieSignatureDatabase::new();
        assert!(db.len() >= 50, "Expected at least 50 signatures, got {}", db.len());
    }

    #[test]
    fn match_hex_pattern_exact() {
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03];
        assert!(match_hex_pattern("4D 5A 90 00", &data));
    }

    #[test]
    fn match_hex_pattern_wildcard() {
        let data = [0x4D, 0x5A, 0xAB, 0x00, 0x03];
        assert!(match_hex_pattern("4D 5A ?? 00", &data));
    }

    #[test]
    fn find_hex_pattern_in_data() {
        let data = [0x00, 0x00, 0x50, 0x4B, 0x03, 0x04, 0x00];
        let pos = find_hex_pattern("50 4B 03 04", &data);
        assert_eq!(pos, Some(2));
    }

    #[test]
    fn upx_signature_matches() {
        let db = DieSignatureDatabase::new();
        let mut ep = vec![0x60, 0xBE, 0x00, 0x10, 0x40, 0x00, 0x8D, 0xBE];
        ep.extend(vec![0u8; 8]);
        ep.push(0x57);
        // Search for UPX sigs that match this EP pattern.
        let matches = db.scan(b"UPX0\x00UPX!", &ep);
        // Just check we get at least one UPX signature.
        assert!(matches.iter().any(|s| s.name.contains("UPX")));
    }

    #[test]
    fn by_category_compilers() {
        let db = DieSignatureDatabase::new();
        let compilers = db.by_category(DieCategory::Compiler);
        assert!(compilers.len() >= 10);
    }

    #[test]
    fn parse_pattern_lengths() {
        let (bytes, mask) = parse_hex_pattern("4D 5A ?? 90");
        assert_eq!(bytes.len(), 4);
        assert_eq!(mask.len(), 4);
        assert!(mask[0] && mask[1] && !mask[2] && mask[3]);
    }
}
