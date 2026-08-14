//! Signature database for Detect-It-Easy style scanning.
//!
//! A [`SignatureDb`] holds a collection of [`Signature`] entries, each with a
//! [`Matcher`] that is evaluated against binary data.  Matchers can be
//! combined using `AllOf`, `AnyOf`, and `Not` combinators.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{DetectKind, Detection};

// ─────────────────────────────────────────────────────────────────────────────
// Matcher
// ─────────────────────────────────────────────────────────────────────────────

/// A composable matching rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Matcher {
    /// Match a fixed byte pattern at a specific offset.
    ByteAt {
        /// Byte offset from the start of the file.
        offset: usize,
        /// Expected byte value.
        value: u8,
    },
    /// Match a byte sequence (with optional wildcard mask) anywhere in the file.
    BytePattern {
        /// Pattern bytes.
        pattern: Vec<u8>,
        /// Mask bytes (`0xFF` = exact match, `0x00` = wildcard).
        mask: Vec<u8>,
    },
    /// Match a byte sequence at a specific offset.
    BytePatternAt {
        offset: usize,
        pattern: Vec<u8>,
        mask: Vec<u8>,
    },
    /// Match an ASCII/UTF-8 string anywhere in the file.
    StringContains(String),
    /// Match a string at a specific offset.
    StringAt { offset: usize, value: String },
    /// Match a string at a specific offset from the end of the file.
    StringAtEnd {
        offset_from_end: usize,
        value: String,
    },
    /// Entropy of the file is in the specified range (inclusive).
    EntropyRange { min: f64, max: f64 },
    /// File size is at least `min` and at most `max` bytes.
    FileSizeRange { min: usize, max: usize },
    /// All sub-matchers must match.
    AllOf(Vec<Self>),
    /// At least one sub-matcher must match.
    AnyOf(Vec<Self>),
    /// The sub-matcher must NOT match.
    Not(Box<Self>),
}

impl Matcher {
    /// Evaluate this matcher against `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::ByteAt { offset, value } => data.get(*offset) == Some(value),
            Self::BytePattern { pattern, mask } => find_pattern(data, pattern, mask, 0).is_some(),
            Self::BytePatternAt {
                offset,
                pattern,
                mask,
            } => {
                if *offset + pattern.len() > data.len() {
                    return false;
                }
                let window = &data[*offset..*offset + pattern.len()];
                window
                    .iter()
                    .zip(pattern.iter())
                    .zip(mask.iter())
                    .all(|((b, p), m)| (*m == 0) || (*b & m == *p & m))
            }
            Self::StringContains(s) => {
                // Search as ASCII/Latin-1 bytes
                let needle = s.as_bytes();
                data.windows(needle.len()).any(|w| w == needle)
            }
            Self::StringAt { offset, value } => {
                let needle = value.as_bytes();
                if *offset + needle.len() > data.len() {
                    return false;
                }
                &data[*offset..*offset + needle.len()] == needle
            }
            Self::StringAtEnd {
                offset_from_end,
                value,
            } => {
                let needle = value.as_bytes();
                let nlen = needle.len();
                if data.len() < *offset_from_end + nlen {
                    return false;
                }
                let start = data.len() - offset_from_end - nlen;
                &data[start..start + nlen] == needle
            }
            Self::EntropyRange { min, max } => {
                let e = byte_entropy(data);
                e >= *min && e <= *max
            }
            Self::FileSizeRange { min, max } => data.len() >= *min && data.len() <= *max,
            Self::AllOf(matchers) => matchers.iter().all(|m| m.matches(data)),
            Self::AnyOf(matchers) => matchers.iter().any(|m| m.matches(data)),
            Self::Not(inner) => !inner.matches(data),
        }
    }
}

/// Find `pattern` (with `mask`) starting at `search_from` in `data`.
fn find_pattern(data: &[u8], pattern: &[u8], mask: &[u8], search_from: usize) -> Option<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > data.len() {
        return None;
    }
    for offset in search_from..=(data.len() - plen) {
        let window = &data[offset..offset + plen];
        let ok = window
            .iter()
            .zip(pattern.iter())
            .zip(mask.iter())
            .all(|((b, p), m)| (*m == 0) || (*b & m == *p & m));
        if ok {
            return Some(offset);
        }
    }
    None
}

/// Compute Shannon entropy in bits per byte.
fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature
// ─────────────────────────────────────────────────────────────────────────────

/// A named detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Unique name for this signature (e.g. `"UPX_header"`).
    pub name: String,
    /// The detection category.
    pub kind: DetectKind,
    /// Human-readable product name (e.g. `"UPX"`).
    pub product: String,
    /// Product version, if applicable.
    pub version: Option<String>,
    /// Confidence weight in range `[0.0, 1.0]`.
    pub confidence: f64,
    /// The matching rule.
    pub matcher: Matcher,
    /// Human-readable description.
    pub description: String,
}

impl Signature {
    /// Evaluate this signature against `data`.
    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        self.matcher.matches(data)
    }

    /// Build a [`Detection`] from this signature (assumes `matches()` returned `true`).
    #[must_use]
    pub fn to_detection(&self) -> Detection {
        Detection {
            kind: self.kind,
            name: self.product.clone(),
            version: self.version.clone(),
            confidence: (self.confidence * 100.0).clamp(0.0, 100.0) as u8,
            description: self.description.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureDb
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of [`Signature`] entries.
///
/// ```rust
/// use rustre_triage_die::signature_db::SignatureDb;
/// let db = SignatureDb::with_defaults();
/// println!("{} signatures loaded", db.len());
/// ```
#[derive(Debug, Default)]
pub struct SignatureDb {
    signatures: Vec<Signature>,
    by_name: HashMap<String, usize>,
}

impl SignatureDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate with built-in default signatures.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.load_defaults();
        db
    }

    /// Number of signatures in the database.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Return `true` if the database is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Add a signature to the database.
    pub fn add(&mut self, sig: Signature) {
        let idx = self.signatures.len();
        self.by_name.insert(sig.name.clone(), idx);
        self.signatures.push(sig);
    }

    /// Look up a signature by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Signature> {
        self.by_name.get(name).map(|&i| &self.signatures[i])
    }

    /// Evaluate all signatures against `data` and return matches.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<&Signature> {
        self.signatures.iter().filter(|s| s.matches(data)).collect()
    }

    /// Evaluate signatures of a given kind.
    #[must_use]
    pub fn scan_kind(&self, data: &[u8], kind: DetectKind) -> Vec<&Signature> {
        self.signatures
            .iter()
            .filter(|s| s.kind == kind && s.matches(data))
            .collect()
    }

    fn load_defaults(&mut self) {
        // ── PE magic ──────────────────────────────────────────────────────────
        self.add(Signature {
            name: "pe_magic".to_owned(),
            kind: DetectKind::Compiler,
            product: "PE".to_owned(),
            version: None,
            confidence: 0.99,
            matcher: Matcher::AllOf(vec![
                Matcher::ByteAt {
                    offset: 0,
                    value: 0x4D,
                },
                Matcher::ByteAt {
                    offset: 1,
                    value: 0x5A,
                },
            ]),
            description: "Windows PE executable (MZ header)".to_owned(),
        });

        // ── ELF magic ─────────────────────────────────────────────────────────
        self.add(Signature {
            name: "elf_magic".to_owned(),
            kind: DetectKind::Compiler,
            product: "ELF".to_owned(),
            version: None,
            confidence: 0.99,
            matcher: Matcher::BytePattern {
                pattern: vec![0x7F, b'E', b'L', b'F'],
                mask: vec![0xFF, 0xFF, 0xFF, 0xFF],
            },
            description: "ELF binary".to_owned(),
        });

        // ── UPX ───────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "upx_header".to_owned(),
            kind: DetectKind::Packer,
            product: "UPX".to_owned(),
            version: None,
            confidence: 0.97,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("UPX0".to_owned()),
                Matcher::StringContains("UPX1".to_owned()),
                Matcher::StringContains("UPX2".to_owned()),
            ]),
            description: "UPX packer (section name)".to_owned(),
        });

        self.add(Signature {
            name: "upx_magic".to_owned(),
            kind: DetectKind::Packer,
            product: "UPX".to_owned(),
            version: Some("3.x+".to_owned()),
            confidence: 0.95,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("UPX!".to_owned()),
                Matcher::StringContains("$Info: This file is packed".to_owned()),
            ]),
            description: "UPX runtime signature or info string".to_owned(),
        });

        // ── MSVC ──────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "msvc_runtime".to_owned(),
            kind: DetectKind::Compiler,
            product: "MSVC".to_owned(),
            version: None,
            confidence: 0.80,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("MSVCP".to_owned()),
                Matcher::StringContains("MSVCR".to_owned()),
                Matcher::StringContains("VCRUNTIME".to_owned()),
            ]),
            description: "MSVC runtime DLL import".to_owned(),
        });

        self.add(Signature {
            name: "msvc_crt_entry".to_owned(),
            kind: DetectKind::Compiler,
            product: "MSVC".to_owned(),
            version: None,
            confidence: 0.75,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("__CxxFrameHandler".to_owned()),
                Matcher::StringContains("_CrtDbgReport".to_owned()),
                Matcher::StringContains("_RTC_InitBase".to_owned()),
            ]),
            description: "MSVC CRT exception / debug helper function".to_owned(),
        });

        // ── GCC / MinGW ───────────────────────────────────────────────────────
        self.add(Signature {
            name: "gcc_crt".to_owned(),
            kind: DetectKind::Compiler,
            product: "GCC".to_owned(),
            version: None,
            confidence: 0.78,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("GCC:".to_owned()),
                Matcher::StringContains("libgcc".to_owned()),
                Matcher::StringContains("__gcc_personality".to_owned()),
            ]),
            description: "GCC runtime / unwind helper".to_owned(),
        });

        self.add(Signature {
            name: "mingw_crt".to_owned(),
            kind: DetectKind::Compiler,
            product: "MinGW".to_owned(),
            version: None,
            confidence: 0.72,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("mingw".to_owned()),
                Matcher::StringContains("libmingwex".to_owned()),
            ]),
            description: "MinGW CRT string".to_owned(),
        });

        // ── Rust ──────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "rust_panicking".to_owned(),
            kind: DetectKind::Compiler,
            product: "Rust".to_owned(),
            version: None,
            confidence: 0.90,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("panicked at".to_owned()),
                Matcher::StringContains("rust_begin_unwind".to_owned()),
                Matcher::StringContains("core::panicking".to_owned()),
            ]),
            description: "Rust panic message or unwind symbol".to_owned(),
        });

        // ── Go ────────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "golang_magic".to_owned(),
            kind: DetectKind::Compiler,
            product: "Go".to_owned(),
            version: None,
            confidence: 0.88,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("runtime.main".to_owned()),
                Matcher::StringContains("go.buildid".to_owned()),
                Matcher::StringContains("runtime.goexit".to_owned()),
            ]),
            description: "Go runtime symbol".to_owned(),
        });

        // ── Delphi ────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "delphi_string".to_owned(),
            kind: DetectKind::Compiler,
            product: "Delphi".to_owned(),
            version: None,
            confidence: 0.82,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("Borland C++".to_owned()),
                Matcher::StringContains("Embarcadero".to_owned()),
                Matcher::StringContains("System.@LStrLen".to_owned()),
                Matcher::StringContains("SysUtils".to_owned()),
            ]),
            description: "Delphi/Borland CRT or RTL string".to_owned(),
        });

        // ── .NET ──────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "dotnet_header".to_owned(),
            kind: DetectKind::Compiler,
            product: ".NET".to_owned(),
            version: None,
            confidence: 0.95,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("mscoree.dll".to_owned()),
                Matcher::StringContains("_CorExeMain".to_owned()),
            ]),
            description: ".NET CLR bootstrap import".to_owned(),
        });

        // ── Themida ───────────────────────────────────────────────────────────
        self.add(Signature {
            name: "themida".to_owned(),
            kind: DetectKind::Protector,
            product: "Themida".to_owned(),
            version: None,
            confidence: 0.88,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains(".themida".to_owned()),
                Matcher::StringContains("Oreans Technologies".to_owned()),
            ]),
            description: "Themida section name or author string".to_owned(),
        });

        // ── VMProtect ─────────────────────────────────────────────────────────
        self.add(Signature {
            name: "vmprotect".to_owned(),
            kind: DetectKind::Protector,
            product: "VMProtect".to_owned(),
            version: None,
            confidence: 0.90,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains(".vmp0".to_owned()),
                Matcher::StringContains(".vmp1".to_owned()),
                Matcher::StringContains("VMProtect Software".to_owned()),
            ]),
            description: "VMProtect section name or author string".to_owned(),
        });

        // ── ASPack ────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "aspack".to_owned(),
            kind: DetectKind::Packer,
            product: "ASPack".to_owned(),
            version: None,
            confidence: 0.88,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains(".aspack".to_owned()),
                Matcher::StringContains(".adata".to_owned()),
            ]),
            description: "ASPack section name".to_owned(),
        });

        // ── MPRESS ────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "mpress".to_owned(),
            kind: DetectKind::Packer,
            product: "MPRESS".to_owned(),
            version: None,
            confidence: 0.85,
            matcher: Matcher::StringContains(".MPRESS".to_owned()),
            description: "MPRESS section name".to_owned(),
        });

        // ── PECompact ─────────────────────────────────────────────────────────
        self.add(Signature {
            name: "pecompact".to_owned(),
            kind: DetectKind::Packer,
            product: "PECompact".to_owned(),
            version: None,
            confidence: 0.85,
            matcher: Matcher::StringContains("PEC2".to_owned()),
            description: "PECompact signature".to_owned(),
        });

        // ── NSIS ──────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "nsis_installer".to_owned(),
            kind: DetectKind::Installer,
            product: "NSIS".to_owned(),
            version: None,
            confidence: 0.88,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("Nullsoft.NSIS.exehead".to_owned()),
                Matcher::StringContains("NullsoftInst".to_owned()),
            ]),
            description: "NSIS installer section or string".to_owned(),
        });

        // ── Inno Setup ────────────────────────────────────────────────────────
        self.add(Signature {
            name: "inno_setup".to_owned(),
            kind: DetectKind::Installer,
            product: "Inno Setup".to_owned(),
            version: None,
            confidence: 0.90,
            matcher: Matcher::StringContains("Inno Setup Setup Data".to_owned()),
            description: "Inno Setup embedded data block string".to_owned(),
        });

        // ── VB6 ───────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "vb6".to_owned(),
            kind: DetectKind::Compiler,
            product: "Visual Basic 6".to_owned(),
            version: Some("6.x".to_owned()),
            confidence: 0.90,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("VB5!".to_owned()),
                Matcher::StringContains("VB6!".to_owned()),
                Matcher::StringContains("MSVBVM50.DLL".to_owned()),
                Matcher::StringContains("MSVBVM60.DLL".to_owned()),
            ]),
            description: "Visual Basic 6 magic or VM DLL import".to_owned(),
        });

        // ── Obsidium ──────────────────────────────────────────────────────────
        self.add(Signature {
            name: "obsidium".to_owned(),
            kind: DetectKind::Protector,
            product: "Obsidium".to_owned(),
            version: None,
            confidence: 0.85,
            matcher: Matcher::StringContains(".obsidium".to_owned()),
            description: "Obsidium section name".to_owned(),
        });

        // ── High-entropy (likely packed) ──────────────────────────────────────
        self.add(Signature {
            name: "high_entropy_packed".to_owned(),
            kind: DetectKind::Packer,
            product: "Unknown Packer".to_owned(),
            version: None,
            confidence: 0.60,
            matcher: Matcher::EntropyRange { min: 7.2, max: 8.0 },
            description: "Very high entropy suggests packed or encrypted payload".to_owned(),
        });

        // ── PyInstaller ───────────────────────────────────────────────────────
        self.add(Signature {
            name: "pyinstaller".to_owned(),
            kind: DetectKind::Compiler,
            product: "PyInstaller".to_owned(),
            version: None,
            confidence: 0.92,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("MEI\x00\x00\x00\x00".to_owned()),
                Matcher::StringContains("PyInstaller archive".to_owned()),
                Matcher::StringContains("_MEIPASS".to_owned()),
            ]),
            description: "PyInstaller frozen executable marker".to_owned(),
        });

        // ── Clang ─────────────────────────────────────────────────────────────
        self.add(Signature {
            name: "clang".to_owned(),
            kind: DetectKind::Compiler,
            product: "Clang".to_owned(),
            version: None,
            confidence: 0.78,
            matcher: Matcher::AnyOf(vec![
                Matcher::StringContains("clang version".to_owned()),
                Matcher::StringContains("__clang__".to_owned()),
                Matcher::StringContains("llvm.lifetime".to_owned()),
            ]),
            description: "Clang/LLVM version string or intrinsic".to_owned(),
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_load_defaults() {
        let db = SignatureDb::with_defaults();
        assert!(db.len() > 10);
    }

    #[test]
    fn test_matcher_byte_at() {
        let m = Matcher::ByteAt {
            offset: 0,
            value: 0x4D,
        };
        assert!(m.matches(b"\x4D\x5A"));
        assert!(!m.matches(b"\x5A\x4D"));
    }

    #[test]
    fn test_matcher_string_contains() {
        let m = Matcher::StringContains("UPX!".to_owned());
        assert!(m.matches(b"this file UPX! packed"));
        assert!(!m.matches(b"no upx here"));
    }

    #[test]
    fn test_matcher_all_of() {
        let m = Matcher::AllOf(vec![
            Matcher::ByteAt {
                offset: 0,
                value: 0x4D,
            },
            Matcher::ByteAt {
                offset: 1,
                value: 0x5A,
            },
        ]);
        assert!(m.matches(b"\x4D\x5A\x90\x00"));
        assert!(!m.matches(b"\x4D\x00"));
    }

    #[test]
    fn test_matcher_any_of() {
        let m = Matcher::AnyOf(vec![
            Matcher::StringContains("UPX0".to_owned()),
            Matcher::StringContains("UPX1".to_owned()),
        ]);
        assert!(m.matches(b"section UPX1 is present"));
        assert!(!m.matches(b"no sections here"));
    }

    #[test]
    fn test_matcher_not() {
        let m = Matcher::Not(Box::new(Matcher::ByteAt {
            offset: 0,
            value: 0xCC,
        }));
        assert!(m.matches(b"\x4D\x5A"));
        assert!(!m.matches(b"\xCC\x00"));
    }

    #[test]
    fn test_matcher_entropy_range() {
        let uniform: Vec<u8> = (0..=255u8).collect();
        let m = Matcher::EntropyRange { min: 7.9, max: 8.0 };
        assert!(m.matches(&uniform));

        let constant = vec![0u8; 256];
        assert!(!m.matches(&constant));
    }

    #[test]
    fn test_matcher_file_size_range() {
        let data = vec![0u8; 100];
        let m = Matcher::FileSizeRange { min: 50, max: 200 };
        assert!(m.matches(&data));

        let m2 = Matcher::FileSizeRange { min: 200, max: 400 };
        assert!(!m2.matches(&data));
    }

    #[test]
    fn test_scan_pe() {
        let data = b"\x4D\x5A\x90\x00";
        let db = SignatureDb::with_defaults();
        let hits = db.scan(data);
        assert!(hits.iter().any(|s| s.name == "pe_magic"));
    }

    #[test]
    fn test_scan_upx() {
        let data = b"\x4D\x5A\x90\x00UPX0\x00UPX1\x00";
        let db = SignatureDb::with_defaults();
        let hits = db.scan(data);
        assert!(hits.iter().any(|s| s.product == "UPX"));
    }

    #[test]
    fn test_scan_kind() {
        let data = b"\x4D\x5AUPXUPXUPXUPXUPXUPXUPXUPXUPXu\x00UPX0\x00";
        let db = SignatureDb::with_defaults();
        let packers = db.scan_kind(data, DetectKind::Packer);
        let _ = packers;
    }

    #[test]
    fn test_get_signature() {
        let db = SignatureDb::with_defaults();
        assert!(db.get("pe_magic").is_some());
        assert!(db.get("nonexistent").is_none());
    }

    #[test]
    fn test_to_detection() {
        let sig = Signature {
            name: "test".to_owned(),
            kind: DetectKind::Packer,
            product: "TestPacker".to_owned(),
            version: Some("1.0".to_owned()),
            confidence: 0.9,
            matcher: Matcher::ByteAt {
                offset: 0,
                value: 0x00,
            },
            description: "test description".to_owned(),
        };
        let det = sig.to_detection();
        assert_eq!(det.name, "TestPacker");
        assert_eq!(det.confidence, 90);
    }
}
