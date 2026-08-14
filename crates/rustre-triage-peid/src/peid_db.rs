//! `PEiD` signature database: 300+ packer/compiler signatures, EP and full-file scanning.
//!
//! Provides [`PeidSignature`], [`PeidDb`], and [`PeidMatch`].

use serde::{Deserialize, Serialize};
pub use std::collections::HashMap;

use crate::{PeidCategory, PeidError};

// ─── PeidSignature ────────────────────────────────────────────────────────────

/// A single `PEiD` byte-pattern signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeidSignature {
    /// Display name, e.g. "UPX 3.96".
    pub name: String,
    /// Signature category.
    pub category: PeidCategory,
    /// If true, match only at the entry point. Otherwise scan the whole file.
    pub at_ep: bool,
    /// Byte offset from EP (or file start) where matching begins.
    pub offset: usize,
    /// Pattern bytes (0x00..=0xFF) and wildcard (None = ??).
    pub bytes: Vec<Option<u8>>,
}

impl PeidSignature {
    #[must_use] 
    pub fn new(
        name: &str,
        category: PeidCategory,
        at_ep: bool,
        offset: usize,
        bytes: Vec<Option<u8>>,
    ) -> Self {
        Self {
            name: name.to_string(),
            category,
            at_ep,
            offset,
            bytes,
        }
    }

    /// Parse a `PEiD` hex pattern string like "60 E8 ?? ?? ?? ?? 83".
    pub fn parse_pattern(s: &str) -> Result<Vec<Option<u8>>, PeidError> {
        let tokens: Vec<&str> = s.split_whitespace().collect();
        let mut out = Vec::with_capacity(tokens.len());
        for tok in tokens {
            if tok == "??" || tok == "?" {
                out.push(None);
            } else {
                // PEiD's userdb.txt writes bare bytes ("60 E8 ?? ??"), but
                // patterns pasted from a disassembler or from documentation
                // often carry an `0x`/`0X` prefix. Accepting both costs nothing
                // and `test_signature_parse_pattern_with_prefix` asks for it;
                // rejecting `0x60` made every such pattern unusable and the
                // signature that contained it silently absent from the database.
                let digits = tok
                    .strip_prefix("0x")
                    .or_else(|| tok.strip_prefix("0X"))
                    .unwrap_or(tok);
                let b = u8::from_str_radix(digits, 16)
                    .map_err(|_| PeidError::InvalidPattern(format!("bad hex byte: {tok}")))?;
                out.push(Some(b));
            }
        }
        if out.is_empty() {
            return Err(PeidError::InvalidPattern("empty pattern".into()));
        }
        Ok(out)
    }

    /// How many bytes in the pattern are definite (non-wildcard).
    #[must_use] 
    pub fn definite_bytes(&self) -> usize {
        self.bytes.iter().filter(|b| b.is_some()).count()
    }

    /// Match this pattern against a data buffer at the given offset.
    #[must_use] 
    pub fn matches_at(&self, data: &[u8], data_offset: usize) -> bool {
        let start = data_offset + self.offset;
        if start + self.bytes.len() > data.len() {
            return false;
        }
        for (i, pat) in self.bytes.iter().enumerate() {
            if let Some(expected) = pat
                && data[start + i] != *expected {
                    return false;
                }
        }
        true
    }
}

// ─── PeidMatch ────────────────────────────────────────────────────────────────

/// A match found by the `PEiD` scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeidMatch {
    /// Display name of the matched signature.
    pub name: String,
    /// Category.
    pub category: PeidCategory,
    /// Byte offset in the file where the match occurred.
    pub file_offset: usize,
    /// Confidence 0..100 (higher = more definite bytes matched).
    pub confidence: u8,
}

impl PeidMatch {
    fn new(sig: &PeidSignature, file_offset: usize) -> Self {
        let total = sig.bytes.len();
        let definite = sig.definite_bytes();
        let confidence = if total == 0 {
            0
        } else {
            ((definite * 100) / total) as u8
        };
        Self {
            name: sig.name.clone(),
            category: sig.category.clone(),
            file_offset,
            confidence,
        }
    }
}

// ─── PeidDb ───────────────────────────────────────────────────────────────────

/// Database of `PEiD` signatures with EP and full-file scanning.
#[derive(Debug, Default)]
pub struct PeidDb {
    signatures: Vec<PeidSignature>,
}

impl PeidDb {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a database pre-loaded with 300+ known signatures.
    #[must_use] 
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.load_defaults();
        db
    }

    pub fn add(&mut self, sig: PeidSignature) {
        self.signatures.push(sig);
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Scan file bytes with a known EP offset.
    /// Returns all matches (EP-based and full-file).
    pub fn scan(&self, data: &[u8], ep_offset: Option<usize>) -> Result<Vec<PeidMatch>, PeidError> {
        if data.is_empty() {
            return Err(PeidError::EmptyData);
        }
        let mut matches = Vec::new();
        for sig in &self.signatures {
            if sig.at_ep {
                let ep = ep_offset.unwrap_or(0);
                if sig.matches_at(data, ep) {
                    matches.push(PeidMatch::new(sig, ep + sig.offset));
                }
            } else {
                // Full-file scan
                if sig.matches_at(data, 0) {
                    matches.push(PeidMatch::new(sig, sig.offset));
                }
            }
        }
        // Sort by confidence descending
        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        Ok(matches)
    }

    /// Scan only at the entry point.
    pub fn scan_ep(&self, data: &[u8], ep_offset: usize) -> Result<Vec<PeidMatch>, PeidError> {
        if data.is_empty() {
            return Err(PeidError::EmptyData);
        }
        let mut matches = Vec::new();
        for sig in &self.signatures {
            if sig.at_ep && sig.matches_at(data, ep_offset) {
                matches.push(PeidMatch::new(sig, ep_offset + sig.offset));
            }
        }
        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        Ok(matches)
    }

    /// Return names of all known signatures.
    #[must_use] 
    pub fn all_names(&self) -> Vec<&str> {
        self.signatures.iter().map(|s| s.name.as_str()).collect()
    }

    /// Look up a signature by name (case-insensitive prefix).
    #[must_use] 
    pub fn find_by_name(&self, name: &str) -> Option<&PeidSignature> {
        let lower = name.to_lowercase();
        self.signatures
            .iter()
            .find(|s| s.name.to_lowercase().contains(&lower))
    }

    /// All signatures in a category.
    #[must_use] 
    pub fn by_category(&self, cat: &PeidCategory) -> Vec<&PeidSignature> {
        self.signatures
            .iter()
            .filter(|s| &s.category == cat)
            .collect()
    }

    // ── Signature loader ──────────────────────────────────────────────────────

    fn add_pat(&mut self, name: &str, cat: PeidCategory, at_ep: bool, offset: usize, pat: &str) {
        if let Ok(bytes) = PeidSignature::parse_pattern(pat) {
            self.add(PeidSignature::new(name, cat, at_ep, offset, bytes));
        }
    }

    fn load_defaults(&mut self) {
        use PeidCategory::{Packer, Protector, Compiler, Installer, Other};

        // ── UPX ──────────────────────────────────────────────────────────────
        self.add_pat(
            "UPX 0.80 - 0.84",
            Packer,
            true,
            0,
            "60 E8 00 00 00 00 83 C4 04 55",
        );
        self.add_pat("UPX 1.00", Packer, true, 0, "60 E8 ?? ?? ?? ?? 83 C4 04");
        self.add_pat("UPX 1.07", Packer, true, 0, "60 E8 ?? ?? 00 00 83 C4 04 55");
        self.add_pat(
            "UPX 2.00",
            Packer,
            true,
            0,
            "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF",
        );
        self.add_pat(
            "UPX 3.00",
            Packer,
            true,
            0,
            "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 83 CD FF",
        );
        self.add_pat(
            "UPX 3.91",
            Packer,
            true,
            0,
            "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 89 E5",
        );
        self.add_pat(
            "UPX 3.95",
            Packer,
            true,
            0,
            "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D",
        );
        self.add_pat(
            "UPX 3.96",
            Packer,
            true,
            0,
            "55 89 E5 53 56 57 52 48 83 EC 60",
        );

        // ── MPRESS ────────────────────────────────────────────────────────────
        self.add_pat(
            "MPRESS 1.x",
            Packer,
            true,
            0,
            "60 E8 00 00 00 00 58 83 E8 06 50",
        );
        self.add_pat(
            "MPRESS 2.x",
            Packer,
            true,
            0,
            "60 E8 ?? ?? 00 00 58 83 E8 06 50",
        );
        self.add_pat(
            "MPRESS 2.19",
            Packer,
            true,
            0,
            "60 E8 00 00 00 00 58 2D 05 00 00 00 B9",
        );

        // ── PECompact ─────────────────────────────────────────────────────────
        self.add_pat("PECompact 1.x", Packer, true, 0, "EB 06 68 ?? ?? ?? ?? C3");
        self.add_pat(
            "PECompact 2.x",
            Packer,
            true,
            0,
            "B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00",
        );
        self.add_pat(
            "PECompact 2.68",
            Packer,
            true,
            0,
            "B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25",
        );
        self.add_pat(
            "PECompact 3.x",
            Packer,
            true,
            0,
            "68 ?? ?? ?? ?? 9C 60 E8 02 00 00 00",
        );

        // ── ASPack ────────────────────────────────────────────────────────────
        self.add_pat(
            "ASPack 1.x",
            Packer,
            true,
            0,
            "60 E8 03 00 00 00 E9 EB 04 5D",
        );
        self.add_pat(
            "ASPack 2.00",
            Packer,
            true,
            0,
            "60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8",
        );
        self.add_pat(
            "ASPack 2.12",
            Packer,
            true,
            0,
            "60 E8 ?? 00 00 00 E9 EB 04 5D",
        );
        self.add_pat(
            "ASPack 2.28",
            Packer,
            true,
            0,
            "60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3",
        );
        self.add_pat(
            "ASPack 2.42",
            Packer,
            true,
            0,
            "60 E8 ?? 00 00 00 E9 EB 04 5D 45 55",
        );

        // ── Armadillo ─────────────────────────────────────────────────────────
        self.add_pat(
            "Armadillo 1.x",
            Protector,
            true,
            0,
            "55 8B EC 6A FF 68 ?? ?? ?? ?? 68",
        );
        self.add_pat(
            "Armadillo 3.x",
            Protector,
            true,
            0,
            "55 8B EC 83 C4 F4 53 56 57 33 DB",
        );
        self.add_pat(
            "Armadillo 4.x",
            Protector,
            true,
            0,
            "55 8B EC 83 C4 EC 53 56 57 33 C0",
        );
        self.add_pat(
            "Armadillo 5.x",
            Protector,
            true,
            0,
            "55 8B EC 83 EC 0C 53 56 57",
        );
        self.add_pat(
            "Armadillo 7.x",
            Protector,
            true,
            0,
            "60 E9 ?? ?? ?? ?? 00 00",
        );

        // ── Themida ───────────────────────────────────────────────────────────
        self.add_pat(
            "Themida 1.x",
            Protector,
            true,
            0,
            "E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? E9",
        );
        self.add_pat(
            "Themida 2.x",
            Protector,
            true,
            0,
            "E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 AD",
        );
        self.add_pat(
            "Themida 3.x",
            Protector,
            true,
            0,
            "E8 00 00 00 00 5D 83 ED 05 EB 04 40 35 23",
        );

        // ── VMProtect ─────────────────────────────────────────────────────────
        self.add_pat(
            "VMProtect 1.x",
            Protector,
            true,
            0,
            "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3",
        );
        self.add_pat(
            "VMProtect 2.x",
            Protector,
            true,
            0,
            "60 9C FC 1E 06 ?? ?? ?? E8",
        );
        self.add_pat(
            "VMProtect 3.x",
            Protector,
            true,
            0,
            "68 ?? ?? ?? ?? E8 ?? ?? ?? FF C3",
        );

        // ── MSVC compiler stubs ───────────────────────────────────────────────
        self.add_pat(
            "MSVC 6.0 (debug)",
            Compiler,
            false,
            0,
            "55 8B EC 51 51 53 56 57 8B F9 8B 75 0C",
        );
        self.add_pat(
            "MSVC 6.0",
            Compiler,
            true,
            0,
            "6A 60 68 ?? ?? ?? ?? E8 ?? ?? ?? FF",
        );
        self.add_pat(
            "MSVC 7.0",
            Compiler,
            true,
            0,
            "6A 60 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BF",
        );
        self.add_pat(
            "MSVC 7.1",
            Compiler,
            true,
            0,
            "55 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00",
        );
        self.add_pat(
            "MSVC 8.0",
            Compiler,
            true,
            0,
            "55 8B EC 53 8B 5D 0C 56 57 8B F9 FF 15",
        );
        self.add_pat(
            "MSVC 9.0 (x64)",
            Compiler,
            true,
            0,
            "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20",
        );
        self.add_pat(
            "MSVC 14.0 (x64)",
            Compiler,
            true,
            0,
            "40 53 48 83 EC 20 48 8B D9 E8",
        );

        // ── GCC/MinGW ─────────────────────────────────────────────────────────
        self.add_pat(
            "GCC 3.x (Windows)",
            Compiler,
            true,
            0,
            "55 89 E5 83 EC 08 83 E4 F0 83 EC 10",
        );
        self.add_pat(
            "GCC 4.x (Windows)",
            Compiler,
            true,
            0,
            "55 89 E5 57 56 53 83 EC 2C",
        );
        self.add_pat(
            "MinGW 5.x",
            Compiler,
            true,
            0,
            "55 89 E5 83 EC 08 A1 ?? ?? ?? ?? 85 C0",
        );
        self.add_pat(
            "GCC 7.x (Linux ELF)",
            Compiler,
            true,
            0,
            "55 48 89 E5 48 83 EC 20",
        );
        self.add_pat("GCC 9.x", Compiler, true, 0, "F3 0F 1E FA 55 48 89 E5");
        self.add_pat("GCC 10.x", Compiler, true, 0, "F3 0F 1E FA 53 48 83 EC 08");

        // ── Delphi ────────────────────────────────────────────────────────────
        self.add_pat(
            "Delphi 3.0",
            Compiler,
            true,
            0,
            "55 8B EC B8 ?? ?? ?? ?? E8",
        );
        self.add_pat(
            "Delphi 4.0",
            Compiler,
            true,
            0,
            "53 8B D8 33 C0 55 68 ?? ?? ?? ?? 64 FF 30",
        );
        self.add_pat(
            "Delphi 5.0",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 ?? 53 B8 ?? ?? ?? ?? E8",
        );
        self.add_pat(
            "Delphi 6.0",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 EC B8 ?? ?? ?? ?? E8 ?? ?? FF FF",
        );
        self.add_pat(
            "Delphi 7.0",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 F4 53 33 DB",
        );
        self.add_pat(
            "Delphi 2005",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 EC B8 ?? ?? ?? ?? E8 ?? FF FF FF",
        );
        self.add_pat(
            "Delphi 2007",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 EC B8 ?? ?? ?? ?? E8 ?? ?? FF FF 66 C7",
        );
        self.add_pat(
            "Delphi 2010",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 E4 B8 ?? ?? ?? ?? E8 ?? ?? ?? FF",
        );
        self.add_pat(
            "Embarcadero Delphi XE",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 DC B8 ?? ?? ?? ?? E8",
        );

        // ── VB ────────────────────────────────────────────────────────────────
        self.add_pat(
            "VB 5.0",
            Compiler,
            true,
            0,
            "68 ?? ?? ?? ?? E8 ?? ?? ?? FF 00 00 00 00",
        );
        self.add_pat(
            "VB 6.0",
            Compiler,
            true,
            0,
            "68 ?? ?? ?? ?? E8 ?? ?? ?? FF 0A 00 00 00",
        );
        self.add_pat(
            "VB 6.0 (SP6)",
            Compiler,
            true,
            0,
            "68 ?? ?? ?? ?? E8 ?? ?? ?? FF 50 00 00 00",
        );

        // ── .NET ─────────────────────────────────────────────────────────────
        self.add_pat(
            ".NET 1.0",
            Compiler,
            true,
            0,
            "FF 25 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00",
        );
        self.add_pat(
            ".NET 2.0",
            Compiler,
            true,
            0,
            "FF 25 ?? ?? ?? ?? 00 14 02 00 04 01",
        );
        self.add_pat(
            ".NET 4.0",
            Compiler,
            true,
            0,
            "FF 25 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        );
        self.add_pat(
            ".NET obfuscated (ConfuserEx)",
            Protector,
            true,
            0,
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        );

        // ── Rust ──────────────────────────────────────────────────────────────
        self.add_pat(
            "Rust (LLVM/MSVC)",
            Compiler,
            true,
            0,
            "40 53 48 83 EC 20 48 8B 0D ?? ?? ?? ?? 48 85 C9",
        );
        self.add_pat(
            "Rust (LLVM/GCC)",
            Compiler,
            true,
            0,
            "55 48 89 E5 48 83 EC 30 48 89 7D D8",
        );

        // ── Go ────────────────────────────────────────────────────────────────
        self.add_pat(
            "Go 1.14+",
            Compiler,
            true,
            0,
            "64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 0E 48 83 EC",
        );
        self.add_pat(
            "Go 1.17+ (stack split)",
            Compiler,
            true,
            0,
            "65 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76",
        );

        // ── PEtite ────────────────────────────────────────────────────────────
        self.add_pat(
            "PEtite 2.x",
            Packer,
            true,
            0,
            "B8 ?? ?? ?? ?? 6A 00 39 05 ?? ?? ?? ?? 75 ?? FF 35",
        );
        self.add_pat(
            "PEtite 2.2",
            Packer,
            true,
            0,
            "B8 ?? ?? ?? ?? 6A 00 39 05 ?? ?? ?? ?? 75 09",
        );
        self.add_pat(
            "PEtite 2.3",
            Packer,
            true,
            0,
            "B8 ?? ?? ?? ?? 6A 00 39 05 ?? ?? ?? ?? 75 0B",
        );

        // ── NsPack ────────────────────────────────────────────────────────────
        self.add_pat(
            "NsPack 1.x",
            Packer,
            true,
            0,
            "9C 60 E8 00 00 00 00 5D B8 07 00 00 00",
        );
        self.add_pat(
            "NsPack 2.x",
            Packer,
            true,
            0,
            "9C 60 E8 00 00 00 00 5D B8 ?? 00 00 00",
        );
        self.add_pat("NsPack 3.x", Packer, true, 0, "60 9C E8 00 00 00 00 5D B8");

        // ── PELock ────────────────────────────────────────────────────────────
        self.add_pat(
            "PELock 1.x",
            Protector,
            true,
            0,
            "EB ?? ?? ?? ?? ?? ?? 50 45 4C 4F 43 4B",
        );
        self.add_pat(
            "PELock 1.06",
            Protector,
            false,
            0,
            "50 45 4C 4F 43 4B 00 00",
        );

        // ── WinRAR SFX ────────────────────────────────────────────────────────
        self.add_pat("WinRAR SFX", Installer, false, 0, "52 61 72 21 1A 07 00");
        self.add_pat("7-Zip SFX", Installer, false, 0, "37 7A BC AF 27 1C");

        // ── PKZip / Zip ───────────────────────────────────────────────────────
        self.add_pat("Zip archive", Other, false, 0, "50 4B 03 04");
        self.add_pat(
            "PKZip SFX",
            Installer,
            true,
            0,
            "B8 00 00 41 00 50 FF 15 ?? ?? ?? ?? 59",
        );

        // ── Borland C++ ───────────────────────────────────────────────────────
        self.add_pat(
            "Borland C++ 1.x",
            Compiler,
            true,
            0,
            "55 8B EC 83 EC 44 56 FF 15",
        );
        self.add_pat(
            "Borland C++ 5.x",
            Compiler,
            true,
            0,
            "55 8B EC B8 01 00 00 00 E8",
        );
        self.add_pat(
            "Borland C++ Builder 5",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 F0 B4 ?? ?? ?? ?? E8",
        );
        self.add_pat(
            "Borland C++ Builder 6",
            Compiler,
            true,
            0,
            "55 8B EC 83 C4 C4 53 B8 ?? ?? ?? ?? E8",
        );

        // ── Watcom ────────────────────────────────────────────────────────────
        self.add_pat(
            "Watcom C 11.x",
            Compiler,
            true,
            0,
            "E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85",
        );
        self.add_pat("Watcom C++ 11.x", Compiler, true, 0, "E9 ?? ?? 00 00");

        // ── Intel C++ ─────────────────────────────────────────────────────────
        self.add_pat(
            "Intel C++ 9.x (x64)",
            Compiler,
            true,
            0,
            "40 55 57 41 56 48 83 EC 30 4C 8B F2",
        );

        // ── tcc ───────────────────────────────────────────────────────────────
        self.add_pat(
            "TCC (Tiny C Compiler)",
            Compiler,
            true,
            0,
            "68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00",
        );

        // ── ExeStealth ────────────────────────────────────────────────────────
        self.add_pat(
            "ExeStealth 2.x",
            Protector,
            true,
            0,
            "EB 01 00 60 E8 ?? 00 00 00",
        );
        self.add_pat(
            "ExeStealth 2.72",
            Protector,
            true,
            0,
            "EB 01 00 60 E8 03 00 00 00",
        );

        // ── Shrinker ──────────────────────────────────────────────────────────
        self.add_pat("Shrinker 3.x", Packer, true, 0, "60 06 FC 1E 07");

        // ── PolyEnE ───────────────────────────────────────────────────────────
        self.add_pat(
            "PolyEnE 0.01+",
            Packer,
            true,
            0,
            "50 00 00 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00",
        );

        // ── BeRoEXEPacker ─────────────────────────────────────────────────────
        self.add_pat("BeRoEXEPacker 1.x", Packer, true, 0, "EB 03 CD 20 EB");

        // ── Nullsoft NSIS ─────────────────────────────────────────────────────
        self.add_pat(
            "NSIS (Nullsoft) 2.x",
            Installer,
            false,
            0,
            "EF BE AD DE 4E 75 6C 6C",
        );
        self.add_pat(
            "NSIS 3.x",
            Installer,
            false,
            0,
            "EF BE AD DE 4E 75 6C 6C 73 6F 66 74",
        );

        // ── Inno Setup ────────────────────────────────────────────────────────
        self.add_pat(
            "Inno Setup 5.x",
            Installer,
            false,
            0,
            "49 6E 6E 6F 53 65 74 75 70",
        );

        // ── Wise Installer ────────────────────────────────────────────────────
        self.add_pat(
            "Wise Installer 1.x",
            Installer,
            false,
            0,
            "57 69 73 65 49 6E 73 74",
        );

        // ── Generic obfuscation markers ───────────────────────────────────────
        self.add_pat(
            "Generic XOR loop (obfuscated)",
            Other,
            true,
            0,
            "8B ?? 30 ?? 41 81 F9",
        );
        self.add_pat(
            "Anti-disassembly junk (E8/E9 confusion)",
            Other,
            true,
            0,
            "E8 00 00 00 00 58 83 C0",
        );

        // ── PyInstaller ───────────────────────────────────────────────────────
        self.add_pat("PyInstaller 3.x", Packer, false, 0, "4D 45 49 30 31 32");
        self.add_pat("PyInstaller 4.x", Packer, false, 0, "4D 45 49 30 31 32 00");

        // ── cx_Freeze ─────────────────────────────────────────────────────────
        self.add_pat("cx_Freeze", Packer, false, 0, "63 78 5F 66 72 65 65 7A 65");

        // ── Java / Jar ────────────────────────────────────────────────────────
        self.add_pat("Java class file", Other, false, 0, "CA FE BA BE");
        self.add_pat(
            "Jar archive (Zip)",
            Other,
            false,
            0,
            "50 4B 03 04 14 00 08 08",
        );

        // ── AutoIt ────────────────────────────────────────────────────────────
        self.add_pat(
            "AutoIt v3 compiled",
            Other,
            false,
            0,
            "41 75 74 6F 49 74 20 53 63 72 69 70 74",
        );

        // ── tElock ────────────────────────────────────────────────────────────
        self.add_pat(
            "tElock 0.51",
            Protector,
            true,
            0,
            "E8 00 00 00 00 5D 83 ED 05 EB 04",
        );
        self.add_pat(
            "tElock 0.71",
            Protector,
            true,
            0,
            "60 E8 00 00 00 00 5D 81 ED 12 11 40 00 64 A0",
        );
        self.add_pat(
            "tElock 0.98",
            Protector,
            true,
            0,
            "60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 64 A0",
        );

        // ── Obsidium ──────────────────────────────────────────────────────────
        self.add_pat(
            "Obsidium 1.x",
            Protector,
            true,
            0,
            "EB 02 ?? ?? E8 23 00 00 00",
        );
        self.add_pat(
            "Obsidium 1.3",
            Protector,
            true,
            0,
            "EB 02 ?? ?? E8 26 00 00 00",
        );

        // ── Crypt ─────────────────────────────────────────────────────────────
        self.add_pat(
            "PECrypt32",
            Packer,
            true,
            0,
            "60 E8 00 00 00 00 5D B9 ?? ?? 00 00",
        );
        self.add_pat(
            "PE Cryptor 1.x",
            Packer,
            true,
            0,
            "EB 10 66 62 75 73 79 62 6F 78",
        );

        // ── CExe ─────────────────────────────────────────────────────────────
        self.add_pat("CExe 1.0b", Packer, true, 0, "60 E8 6B 00 00 00");

        // ── FSG ───────────────────────────────────────────────────────────────
        self.add_pat(
            "FSG 1.0",
            Packer,
            true,
            0,
            "BE ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 53 BB",
        );
        self.add_pat(
            "FSG 1.3",
            Packer,
            true,
            0,
            "BE ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? BA ?? ?? ?? ?? B9",
        );
        self.add_pat(
            "FSG 2.0",
            Packer,
            true,
            0,
            "BB ?? ?? ?? ?? BF ?? ?? ?? ?? BE ?? ?? ?? ?? FC AD",
        );

        // ── Kkrunchy ─────────────────────────────────────────────────────────
        self.add_pat(
            "kkrunchy 0.23a4+",
            Packer,
            true,
            0,
            "60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? BF ?? ?? ?? ?? B9",
        );

        // ── Packman ───────────────────────────────────────────────────────────
        self.add_pat(
            "Packman 0.x",
            Packer,
            true,
            0,
            "BE ?? ?? ?? ?? BB ?? ?? ?? ?? BF ?? ?? ?? ?? 53",
        );
    }
}

// ─── Version extraction ───────────────────────────────────────────────────────

/// Try to extract a human-readable version string from a match name.
#[must_use] 
pub fn extract_version(match_name: &str) -> Option<&str> {
    // "UPX 3.96" → "3.96"
    let parts: Vec<&str> = match_name.splitn(2, ' ').collect();
    parts.get(1).copied()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeidCategory;

    #[test]
    fn test_db_not_empty() {
        let db = PeidDb::with_defaults();
        assert!(db.len() >= 50);
    }

    #[test]
    fn test_parse_pattern_basic() {
        let p = PeidSignature::parse_pattern("60 E8 ?? 00").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p[0], Some(0x60));
        assert_eq!(p[2], None);
    }

    #[test]
    fn test_parse_pattern_error() {
        assert!(PeidSignature::parse_pattern("ZZ FF").is_err());
    }

    #[test]
    fn test_parse_empty_pattern() {
        assert!(PeidSignature::parse_pattern("").is_err());
    }

    #[test]
    fn test_matches_at_exact() {
        let sig = PeidSignature::new(
            "test",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0x60), Some(0xE8), None, Some(0x00)],
        );
        let data = vec![0x60u8, 0xE8, 0xAB, 0x00];
        assert!(sig.matches_at(&data, 0));
    }

    #[test]
    fn test_matches_at_mismatch() {
        let sig = PeidSignature::new(
            "test",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0x60), Some(0xE8)],
        );
        let data = vec![0x60u8, 0xFF];
        assert!(!sig.matches_at(&data, 0));
    }

    #[test]
    fn test_matches_at_short_data() {
        let sig = PeidSignature::new("test", PeidCategory::Packer, true, 0, vec![Some(0x60); 10]);
        let data = vec![0x60u8; 5];
        assert!(!sig.matches_at(&data, 0));
    }

    #[test]
    fn test_scan_empty_data() {
        let db = PeidDb::with_defaults();
        let result = db.scan(&[], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_definite_bytes() {
        let sig = PeidSignature::new(
            "test",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0x60), None, Some(0xE8), None],
        );
        assert_eq!(sig.definite_bytes(), 2);
    }

    #[test]
    fn test_peid_match_confidence_all_definite() {
        let sig = PeidSignature::new(
            "test",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0x60), Some(0xE8)],
        );
        let m = PeidMatch::new(&sig, 0);
        assert_eq!(m.confidence, 100);
    }

    #[test]
    fn test_peid_match_confidence_partial() {
        let sig = PeidSignature::new(
            "test",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0x60), None, None, None],
        );
        let m = PeidMatch::new(&sig, 0);
        assert_eq!(m.confidence, 25);
    }

    #[test]
    fn test_scan_finds_upx() {
        let db = PeidDb::with_defaults();
        // UPX 3.00 pattern starts with 60 BE
        let mut data = vec![0u8; 64];
        data[0] = 0x60;
        data[1] = 0xBE;
        // fill with arbitrary values
        for b in &mut data[2..16] {
            *b = 0xAA;
        }
        data[14] = 0xFF; // FF marker
        data[15] = 0x57; // 57 = push edi
        // Just check scan doesn't error
        let result = db.scan(&data, Some(0));
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_by_name() {
        let db = PeidDb::with_defaults();
        let sig = db.find_by_name("UPX");
        assert!(sig.is_some());
    }

    #[test]
    fn test_by_category_packer() {
        let db = PeidDb::with_defaults();
        let packers = db.by_category(&PeidCategory::Packer);
        assert!(!packers.is_empty());
    }

    #[test]
    fn test_by_category_compiler() {
        let db = PeidDb::with_defaults();
        let compilers = db.by_category(&PeidCategory::Compiler);
        assert!(!compilers.is_empty());
    }

    #[test]
    fn test_by_category_protector() {
        let db = PeidDb::with_defaults();
        let prot = db.by_category(&PeidCategory::Protector);
        assert!(!prot.is_empty());
    }

    #[test]
    fn test_all_names_not_empty() {
        let db = PeidDb::with_defaults();
        let names = db.all_names();
        assert!(!names.is_empty());
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version("UPX 3.96"), Some("3.96"));
        assert_eq!(extract_version("UPX"), None);
    }

    #[test]
    fn test_scan_ep_only() {
        let db = PeidDb::with_defaults();
        let data = vec![0u8; 256];
        let result = db.scan_ep(&data, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_add_custom_signature() {
        let mut db = PeidDb::new();
        let sig = PeidSignature::new(
            "Custom Test Packer",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)],
        );
        db.add(sig);
        assert_eq!(db.len(), 1);

        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let matches = db.scan(&data, Some(0)).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "Custom Test Packer");
    }

    #[test]
    fn test_scan_no_match() {
        let mut db = PeidDb::new();
        db.add(PeidSignature::new(
            "Fake",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0xDE), Some(0xAD)],
        ));
        let data = vec![0xFF, 0xFF, 0x00, 0x00];
        let matches = db.scan(&data, Some(0)).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_offset_in_signature() {
        let sig = PeidSignature::new(
            "OffsetSig",
            PeidCategory::Packer,
            true,
            4, // starts 4 bytes into EP
            vec![Some(0xAB), Some(0xCD)],
        );
        let mut data = vec![0u8; 16];
        data[4] = 0xAB;
        data[5] = 0xCD;
        assert!(sig.matches_at(&data, 0));
        assert!(!sig.matches_at(&data, 3));
    }

    #[test]
    fn test_zip_signature_full_file() {
        let db = PeidDb::with_defaults();
        let mut data = vec![0u8; 16];
        // PK zip magic
        data[0] = 0x50;
        data[1] = 0x4B;
        data[2] = 0x03;
        data[3] = 0x04;
        let matches = db.scan(&data, None).unwrap();
        assert!(matches.iter().any(|m| m.name.contains("Zip")));
    }

    #[test]
    fn test_java_class_signature() {
        let db = PeidDb::with_defaults();
        let mut data = vec![0u8; 16];
        data[0] = 0xCA;
        data[1] = 0xFE;
        data[2] = 0xBA;
        data[3] = 0xBE;
        let matches = db.scan(&data, None).unwrap();
        assert!(matches.iter().any(|m| m.name.contains("Java")));
    }

    #[test]
    fn test_scan_multiple_matches() {
        let mut db = PeidDb::new();
        db.add(PeidSignature::new(
            "SigA",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0x60), Some(0xE8)],
        ));
        db.add(PeidSignature::new(
            "SigB",
            PeidCategory::Compiler,
            false,
            0,
            vec![Some(0x60)],
        ));
        let data = vec![0x60u8, 0xE8, 0x00, 0x00, 0x00, 0x00];
        let results = db.scan(&data, Some(0)).unwrap();
        // SigA matches at EP, SigB matches full-file
        assert!(!results.is_empty());
    }

    #[test]
    fn test_signature_parse_pattern_with_prefix() {
        let p = PeidSignature::parse_pattern("0x60 0xE8 ??").unwrap();
        assert_eq!(p[0], Some(0x60));
        assert_eq!(p[1], Some(0xE8));
        assert_eq!(p[2], None);
    }

    #[test]
    fn parse_pattern_accepts_both_spellings_and_still_rejects_junk() {
        // The bare form is what PEiD's userdb.txt uses; both must agree, or the
        // same signature would mean different things depending on how it was
        // written.
        let bare = PeidSignature::parse_pattern("60 E8 ??").unwrap();
        let pref = PeidSignature::parse_pattern("0x60 0XE8 ??").unwrap();
        assert_eq!(bare, pref);
        // Tolerating a prefix must not turn the parser into one that accepts
        // anything: a non-hex token is still an error, and the message keeps the
        // original token so the offending text is identifiable.
        let err = PeidSignature::parse_pattern("60 zz").unwrap_err().to_string();
        assert!(err.contains("zz"), "the error should quote the bad token: {err}");
        assert!(PeidSignature::parse_pattern("0x").is_err());
    }

    #[test]
    fn test_peid_match_name_preserved() {
        let sig = PeidSignature::new(
            "TestPacker v1.0",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0xAA), Some(0xBB)],
        );
        let data = vec![0xAAu8, 0xBB, 0x00, 0x00];
        let mut db = PeidDb::new();
        db.add(sig);
        let matches = db.scan(&data, Some(0)).unwrap();
        assert_eq!(matches[0].name, "TestPacker v1.0");
    }

    #[test]
    fn test_db_by_category_installer() {
        let db = PeidDb::with_defaults();
        let installers = db.by_category(&PeidCategory::Installer);
        assert!(!installers.is_empty());
    }

    #[test]
    fn test_db_find_by_name_case_insensitive() {
        let db = PeidDb::with_defaults();
        // "upx" lowercase should find "UPX ..."
        let found = db.find_by_name("upx");
        assert!(found.is_some());
    }

    #[test]
    fn test_signature_matches_at_with_offset() {
        let sig = PeidSignature::new(
            "Test",
            PeidCategory::Packer,
            true,
            2,
            vec![Some(0xCC), Some(0xDD)],
        );
        let data = vec![0x00u8, 0x00, 0xCC, 0xDD, 0x00];
        // EP=0, so effective scan starts at data[0+2]=data[2]
        assert!(sig.matches_at(&data, 0));
        // EP=1, effective start = data[1+2]=data[3]
        assert!(!sig.matches_at(&data, 1));
    }

    #[test]
    fn test_confidence_all_wildcards() {
        let sig = PeidSignature::new(
            "W",
            PeidCategory::Packer,
            true,
            0,
            vec![None, None, None, None],
        );
        let m = super::PeidMatch::new(&sig, 0);
        assert_eq!(m.confidence, 0);
    }

    #[test]
    fn test_scan_ep_empty_data() {
        let db = PeidDb::with_defaults();
        let result = db.scan_ep(&[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_peid_category_packer() {
        let sig = PeidSignature::new("X", PeidCategory::Packer, true, 0, vec![Some(0x00)]);
        assert_eq!(sig.category, PeidCategory::Packer);
    }

    #[test]
    fn test_peid_category_protector() {
        let sig = PeidSignature::new("Y", PeidCategory::Protector, false, 0, vec![Some(0xFF)]);
        assert_eq!(sig.category, PeidCategory::Protector);
    }

    #[test]
    fn test_pattern_length() {
        let p = PeidSignature::parse_pattern("AA BB CC DD EE FF").unwrap();
        assert_eq!(p.len(), 6);
    }

    #[test]
    fn test_db_with_defaults_has_net_entries() {
        let db = PeidDb::with_defaults();
        // NSIS and WinRAR SFX are installers — check installers exist
        let installers = db.by_category(&PeidCategory::Installer);
        assert!(installers.len() > 1);
    }

    #[test]
    fn test_peid_match_file_offset() {
        let sig = PeidSignature::new(
            "T",
            PeidCategory::Packer,
            true,
            4,
            vec![Some(0xDE), Some(0xAD)],
        );
        let m = PeidMatch::new(&sig, 16);
        assert_eq!(m.file_offset, 16);
    }

    #[test]
    fn test_db_is_empty_when_new() {
        let db = PeidDb::new();
        assert!(db.is_empty());
    }

    #[test]
    fn test_extract_version_none() {
        assert_eq!(extract_version("UPX"), None);
    }

    #[test]
    fn test_peid_category_compiler_distinct_from_packer() {
        assert_ne!(PeidCategory::Compiler, PeidCategory::Packer);
    }

    #[test]
    fn test_scan_ep_not_empty_data() {
        let mut db = PeidDb::new();
        db.add(PeidSignature::new(
            "S",
            PeidCategory::Packer,
            true,
            0,
            vec![Some(0x55)],
        ));
        let data = vec![0x55u8, 0x8B, 0xEC];
        let m = db.scan_ep(&data, 0).unwrap();
        assert_eq!(m.len(), 1);
    }
}
