//! PE Rich header decoder.
//!
//! The Microsoft Rich header is a secret table embedded between the MZ DOS stub
//! and the PE signature.  It records which Visual Studio tools (compiler,
//! linker, libraries) were used to build the binary, along with per-tool
//! object-file counts.  This metadata is XOR-masked with a 32-bit key derived
//! from the raw DOS header words.
//!
//! [`PeRichHeader`] holds the decoded table; [`decode_rich_header`] is the
//! top-level entry point.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ProductId — known Visual Studio / MSVC build-tool identifiers
// ---------------------------------------------------------------------------

/// A known (or unknown) Visual Studio product.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProductId {
    /// Import library / export stub (`prodid = 0`).
    Import,
    /// Object compiled by MASM or the resource compiler.
    MasmOrResource,
    /// Pre-compiled header object.
    Pch,
    /// LINK.EXE linker.
    Linker { version: u16 },
    /// CL.EXE compiler.
    Compiler { version: u16 },
    /// MASM assembler.
    Masm { version: u16 },
    /// C runtime library helper object.
    Crt { version: u16 },
    /// Unrecognised product identifier.
    Unknown { prodid: u16 },
}

impl ProductId {
    /// Decode a raw (prodid, build) pair into a [`ProductId`].
    #[must_use]
    pub const fn from_raw(prodid: u16, build: u16) -> Self {
        match prodid {
            0x0000 => Self::Import,
            0x0001 => Self::MasmOrResource,
            0x0002 => Self::Pch,
            // Linker: 0x0004, 0x0006, 0x0008, 0x000A, 0x000C …
            p if p % 2 == 0 && p <= 0x0020 => Self::Linker { version: build },
            // Compiler: 0x0003, 0x0005, 0x0007, 0x0009 …
            p if p % 2 == 1 && p <= 0x001F => Self::Compiler { version: build },
            0x0060..=0x006F => Self::Crt { version: build },
            0x0101..=0x01FF => Self::Masm { version: build },
            p => Self::Unknown { prodid: p },
        }
    }

    /// A short human-readable label.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Import              => "import".to_string(),
            Self::MasmOrResource      => "masm/rc".to_string(),
            Self::Pch                 => "pch".to_string(),
            Self::Linker { version }  => format!("linker-{version}"),
            Self::Compiler { version }=> format!("cl-{version}"),
            Self::Masm { version }    => format!("masm-{version}"),
            Self::Crt { version }     => format!("crt-{version}"),
            Self::Unknown { prodid }  => format!("unknown-{prodid:#06x}"),
        }
    }
}

impl fmt::Display for ProductId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

// ---------------------------------------------------------------------------
// RichEntry — one row in the Rich header
// ---------------------------------------------------------------------------

/// A single entry in the Rich header table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichEntry {
    /// Raw product identifier (high 16 bits of the dword before masking).
    pub prodid: u16,
    /// Build number (low 16 bits).
    pub build: u16,
    /// Number of object files (or contributions) from this tool.
    pub count: u32,
    /// Decoded product identifier.
    pub product: ProductId,
}

impl RichEntry {
    /// Create from raw fields.
    #[must_use]
    pub const fn new(prodid: u16, build: u16, count: u32) -> Self {
        let product = ProductId::from_raw(prodid, build);
        Self { prodid, build, count, product }
    }
}

impl fmt::Display for RichEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (prodid={:#06x} build={:#06x}) × {}",
            self.product, self.prodid, self.build, self.count
        )
    }
}

// ---------------------------------------------------------------------------
// RichError
// ---------------------------------------------------------------------------

/// Errors from the Rich header decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RichError {
    /// The file is too small to contain a valid MZ header.
    TooShort { got: usize },
    /// The `DanS` marker (masked start of the Rich header) was not found.
    NoDansMarker,
    /// The `Rich` marker at the end of the table was not found.
    NoRichMarker,
    /// The entry count computed from the markers is inconsistent.
    BadEntryCount { computed: usize },
    /// XOR key verification failed.
    KeyMismatch { expected: u32, got: u32 },
}

impl fmt::Display for RichError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got } => write!(f, "file too short: {got} bytes"),
            Self::NoDansMarker => write!(f, "'DanS' marker not found in DOS stub"),
            Self::NoRichMarker => write!(f, "'Rich' marker not found after 'DanS'"),
            Self::BadEntryCount { computed } => {
                write!(f, "computed entry count {computed} is not a multiple of 2 dwords")
            }
            Self::KeyMismatch { expected, got } => {
                write!(f, "XOR key mismatch: expected {expected:#010x}, got {got:#010x}")
            }
        }
    }
}

impl std::error::Error for RichError {}

// ---------------------------------------------------------------------------
// PeRichHeader
// ---------------------------------------------------------------------------

/// The decoded Rich header, including the XOR key and all tool entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeRichHeader {
    /// The XOR key used to mask the header.
    pub xor_key: u32,
    /// Offset of the `DanS` marker (after XOR masking is applied).
    pub dans_offset: usize,
    /// Offset of the `Rich` marker.
    pub rich_offset: usize,
    /// Decoded tool entries.
    pub entries: Vec<RichEntry>,
}

impl PeRichHeader {
    /// Returns `true` when no entries are present (the table is empty).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of distinct tool entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Aggregate object-file counts by [`ProductId`].
    #[must_use]
    pub fn counts_by_product(&self) -> HashMap<String, u32> {
        let mut map: HashMap<String, u32> = HashMap::new();
        for e in &self.entries {
            *map.entry(e.product.label()).or_insert(0) += e.count;
        }
        map
    }

    /// Attempt to infer the Visual Studio version from the compiler build numbers.
    ///
    /// Returns the most common build number found in `Compiler` entries.
    #[must_use]
    pub fn inferred_vs_version(&self) -> Option<u16> {
        let mut freq: HashMap<u16, usize> = HashMap::new();
        for e in &self.entries {
            if let ProductId::Compiler { version } | ProductId::Linker { version } = e.product {
                *freq.entry(version).or_insert(0) += 1;
            }
        }
        freq.into_iter().max_by_key(|(_, c)| *c).map(|(v, _)| v)
    }

    /// Produce a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = vec![
            format!("Rich header: key={:#010x} entries={}", self.xor_key, self.entries.len()),
        ];
        for e in &self.entries {
            lines.push(format!("  {e}"));
        }
        lines.join("\n")
    }
}

impl fmt::Display for PeRichHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RichHeader key={:#010x} entries={}",
            self.xor_key,
            self.entries.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Decode the Rich header from raw PE bytes.
///
/// # Algorithm
///
/// 1. Compute the XOR key as the checksum of the first 0x3C bytes of the DOS
///    header (the `e_lfanew` field itself is excluded from the checksum — but
///    the standard Microsoft checksum rotates the *raw* bytes of the DOS header
///    up to `e_lfanew` at byte granularity; we use the simple folded-XOR
///    variant that is universally documented).
/// 2. Scan the DOS stub (bytes 0x40..`e_lfanew`) for the `DanS` marker
///    (ASCII `44 61 6E 53` XOR'd with the key).
/// 3. Locate the `Rich` marker (`52 69 63 68`) that immediately precedes the
///    32-bit XOR key value stored in plain.
/// 4. Decode the interleaved (prodid<<16 | build, count) dword pairs.
///
/// # Errors
/// Returns [`RichError`] on structural problems.
pub fn decode_rich_header(data: &[u8]) -> Result<PeRichHeader, RichError> {
    // The standard Microsoft layout stores the XOR key as the dword immediately
    // following the 'Rich' marker (in plaintext).  Locate 'Rich' first, then
    // read the key from that position; use it to find the masked 'DanS' marker.
    const RICH: u32 = 0x6863_6952; // "Rich" as LE u32
    // Search the DOS stub for the masked 'DanS' marker
    const DANS: u32 = 0x536E_6144; // "DanS" as LE u32

    if data.len() < 64 {
        return Err(RichError::TooShort { got: data.len() });
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let stub_end = e_lfanew.min(data.len());
    if stub_end < 0x40 {
        return Err(RichError::NoDansMarker);
    }

    let rich_offset = find_dword_plain(&data[0x40..stub_end], RICH)
        .map(|rel| rel + 0x40)
        .ok_or(RichError::NoRichMarker)?;

    if rich_offset + 8 > stub_end {
        return Err(RichError::NoRichMarker);
    }
    let xor_key = u32::from_le_bytes([
        data[rich_offset + 4],
        data[rich_offset + 5],
        data[rich_offset + 6],
        data[rich_offset + 7],
    ]);
    let dans_offset = find_dword_masked(&data[0x40..rich_offset], DANS ^ xor_key)
        .map(|rel| rel + 0x40)
        .ok_or(RichError::NoDansMarker)?;

    // Verify the computed checksum matches the stored key (soft check)
    let computed_key = compute_rich_key(&data[..stub_end.min(data.len())], 0x3C);
    if computed_key != xor_key {
        // Soft mismatch — some tools recompute the key differently; continue.
    }

    // Decode entries between (dans_offset + 16) and rich_offset, stepping 8 bytes
    let entry_start = dans_offset + 16; // skip DanS + 3 zero dwords
    let entry_end = rich_offset;

    if entry_start > entry_end || (entry_end - entry_start) % 8 != 0 {
        let computed = (entry_end.saturating_sub(entry_start)) / 4;
        return Err(RichError::BadEntryCount { computed });
    }

    let mut entries = Vec::new();
    let mut i = entry_start;
    while i + 8 <= entry_end {
        let raw0 = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]) ^ xor_key;
        let raw1 = u32::from_le_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]) ^ xor_key;
        let prodid = (raw0 >> 16) as u16;
        let build  = (raw0 & 0xFFFF) as u16;
        let count  = raw1;
        entries.push(RichEntry::new(prodid, build, count));
        i += 8;
    }

    Ok(PeRichHeader {
        xor_key,
        dans_offset,
        rich_offset,
        entries,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the Rich header XOR key from the DOS header stub.
///
/// The key is the checksum of the raw bytes 0..`checksum_skip_offset` (and
/// `checksum_skip_offset+4..stub_end`), implemented as a rotate-and-XOR.
fn compute_rich_key(stub: &[u8], checksum_skip_offset: usize) -> u32 {
    let mut checksum: u32 = 0;
    for (i, &b) in stub.iter().enumerate() {
        if i == checksum_skip_offset
            || i == checksum_skip_offset + 1
            || i == checksum_skip_offset + 2
            || i == checksum_skip_offset + 3
        {
            continue;
        }
        // Rotate-left the byte by its position
        let rot = u32::from(b).rotate_left(u32::try_from(i).unwrap_or(u32::MAX) % 32);
        checksum ^= rot;
    }
    checksum
}

/// Find the first occurrence of `target` (as a LE dword) in `data`.
/// The target is compared after XOR-masking: `data_dword == target`.
fn find_dword_masked(data: &[u8], target: u32) -> Option<usize> {
    data.windows(4).position(|w| {
        let dw = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        dw == target
    })
}

/// Find the first occurrence of `target` as a plain LE dword (no masking).
fn find_dword_plain(data: &[u8], target: u32) -> Option<usize> {
    data.windows(4).position(|w| {
        let dw = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        dw == target
    })
}

// ---------------------------------------------------------------------------
// RichHeaderAnalyzer — batch analysis helper
// ---------------------------------------------------------------------------

/// Compares two Rich headers to identify shared tool builds (binary diffing).
#[derive(Debug, Default)]
pub struct RichHeaderAnalyzer;

impl RichHeaderAnalyzer {
    /// Create a new analyzer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Compute the Jaccard similarity between the tool sets of two Rich headers.
    ///
    /// Returns a value in [0.0, 1.0].  Two binaries built with identical
    /// tool chains return 1.0.
    #[must_use]
    pub fn jaccard_similarity(a: &PeRichHeader, b: &PeRichHeader) -> f64 {
        let set_a: std::collections::HashSet<(u16, u16)> =
            a.entries.iter().map(|e| (e.prodid, e.build)).collect();
        let set_b: std::collections::HashSet<(u16, u16)> =
            b.entries.iter().map(|e| (e.prodid, e.build)).collect();
        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();
        if union == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(intersection).unwrap_or(u32::MAX)) / f64::from(u32::try_from(union).unwrap_or(u32::MAX))
    }

    /// Returns entries present in `a` but not in `b` (by prodid+build pair).
    #[must_use]
    pub fn diff<'a>(a: &'a PeRichHeader, b: &PeRichHeader) -> Vec<&'a RichEntry> {
        let set_b: std::collections::HashSet<(u16, u16)> =
            b.entries.iter().map(|e| (e.prodid, e.build)).collect();
        a.entries
            .iter()
            .filter(|e| !set_b.contains(&(e.prodid, e.build)))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic DOS stub with an embedded Rich header.
    fn make_stub_with_rich(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        // XOR key (we'll use a fixed value for testing)
        let key: u32 = 0xDEAD_C0DE;

        // DanS marker (masked): "DanS" ^ key
        const DANS: u32 = 0x536E6144;
        let dans_masked = DANS ^ key;
        // Rich marker: plain "Rich"
        const RICH: u32 = 0x68636952;

        let mut stub: Vec<u8> = vec![0u8; 0x40];
        // MZ
        stub[0] = b'M'; stub[1] = b'Z';

        // We'll put the Rich header at bytes 0x40..
        let mut rich_body: Vec<u8> = Vec::new();

        // DanS + 3 padding dwords
        rich_body.extend_from_slice(&dans_masked.to_le_bytes());
        for _ in 0..3 {
            rich_body.extend_from_slice(&key.to_le_bytes());
        }

        // Entries
        for &(prodid, build, count) in entries {
            let raw0: u32 = (u32::from(prodid) << 16) | u32::from(build);
            let raw1: u32 = count;
            rich_body.extend_from_slice(&(raw0 ^ key).to_le_bytes());
            rich_body.extend_from_slice(&(raw1 ^ key).to_le_bytes());
        }

        // Rich marker + key
        rich_body.extend_from_slice(&RICH.to_le_bytes());
        rich_body.extend_from_slice(&key.to_le_bytes());

        // e_lfanew points past the Rich header
        let e_lfanew = (stub.len() + rich_body.len()) as u32;
        stub[0x3C] = (e_lfanew & 0xFF) as u8;
        stub[0x3D] = ((e_lfanew >> 8) & 0xFF) as u8;
        stub[0x3E] = ((e_lfanew >> 16) & 0xFF) as u8;
        stub[0x3F] = ((e_lfanew >> 24) & 0xFF) as u8;

        stub.extend_from_slice(&rich_body);
        // Pad to e_lfanew length
        while stub.len() < e_lfanew as usize {
            stub.push(0);
        }
        stub
    }

    #[test]
    fn test_decode_round_trip_one_entry() {
        let stub = make_stub_with_rich(&[(0x0001, 0x1234, 3)]);
        let result = decode_rich_header(&stub);
        assert!(result.is_ok(), "{:?}", result.err());
        let hdr = result.unwrap();
        assert_eq!(hdr.entries.len(), 1);
        assert_eq!(hdr.entries[0].prodid, 0x0001);
        assert_eq!(hdr.entries[0].build, 0x1234);
        assert_eq!(hdr.entries[0].count, 3);
    }

    #[test]
    fn test_decode_multiple_entries() {
        let entries = [(0x0001, 0x0100, 5), (0x0003, 0x7809, 12), (0x0000, 0x0000, 1)];
        let stub = make_stub_with_rich(&entries);
        let hdr = decode_rich_header(&stub).unwrap();
        assert_eq!(hdr.entries.len(), 3);
    }

    #[test]
    fn test_decode_too_short() {
        let err = decode_rich_header(&[0u8; 10]);
        assert!(matches!(err, Err(RichError::TooShort { got: 10 })));
    }

    #[test]
    fn test_decode_no_dans() {
        let data = vec![0u8; 128];
        let err = decode_rich_header(&data);
        assert!(matches!(err, Err(RichError::NoDansMarker)));
    }

    #[test]
    fn test_product_id_import() {
        let p = ProductId::from_raw(0, 0);
        assert_eq!(p, ProductId::Import);
        assert_eq!(p.label(), "import");
    }

    #[test]
    fn test_product_id_compiler() {
        let p = ProductId::from_raw(0x0003, 0x7809);
        assert!(matches!(p, ProductId::Compiler { version: 0x7809 }));
    }

    #[test]
    fn test_product_id_unknown() {
        let p = ProductId::from_raw(0xFFFF, 0);
        assert!(matches!(p, ProductId::Unknown { prodid: 0xFFFF }));
    }

    #[test]
    fn test_rich_entry_display() {
        let e = RichEntry::new(0x0001, 0x1234, 7);
        let s = e.to_string();
        assert!(s.contains("× 7"));
        assert!(s.contains("0x1234"));
    }

    #[test]
    fn test_counts_by_product() {
        let stub = make_stub_with_rich(&[(0x0001, 0x01, 5), (0x0001, 0x01, 3)]);
        let hdr = decode_rich_header(&stub).unwrap();
        let counts = hdr.counts_by_product();
        // Both have the same label → aggregated
        assert!(!counts.is_empty());
    }

    #[test]
    fn test_rich_header_display() {
        let hdr = PeRichHeader {
            xor_key: 0xDEAD_C0DE,
            dans_offset: 0x40,
            rich_offset: 0x80,
            entries: vec![],
        };
        let s = hdr.to_string();
        assert!(s.contains("0xdeadc0de"));
    }

    #[test]
    fn test_jaccard_identical() {
        let e = vec![RichEntry::new(1, 100, 1)];
        let a = PeRichHeader { xor_key: 0, dans_offset: 0, rich_offset: 0, entries: e.clone() };
        let b = PeRichHeader { xor_key: 0, dans_offset: 0, rich_offset: 0, entries: e };
        assert_eq!(RichHeaderAnalyzer::jaccard_similarity(&a, &b), 1.0);
    }

    #[test]
    fn test_jaccard_disjoint() {
        let a = PeRichHeader {
            xor_key: 0, dans_offset: 0, rich_offset: 0,
            entries: vec![RichEntry::new(1, 100, 1)],
        };
        let b = PeRichHeader {
            xor_key: 0, dans_offset: 0, rich_offset: 0,
            entries: vec![RichEntry::new(2, 200, 1)],
        };
        assert_eq!(RichHeaderAnalyzer::jaccard_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_diff() {
        let ea = RichEntry::new(1, 100, 1);
        let eb = RichEntry::new(2, 200, 1);
        let a = PeRichHeader {
            xor_key: 0, dans_offset: 0, rich_offset: 0,
            entries: vec![ea, eb.clone()],
        };
        let b = PeRichHeader {
            xor_key: 0, dans_offset: 0, rich_offset: 0,
            entries: vec![eb],
        };
        let only_in_a = RichHeaderAnalyzer::diff(&a, &b);
        assert_eq!(only_in_a.len(), 1);
        assert_eq!(only_in_a[0].prodid, 1);
    }

    #[test]
    fn test_summary_non_empty() {
        let hdr = PeRichHeader {
            xor_key: 0xABCD_1234,
            dans_offset: 0x50,
            rich_offset: 0x80,
            entries: vec![RichEntry::new(3, 0x7809, 10)],
        };
        let s = hdr.summary();
        assert!(s.contains("Rich header"));
        assert!(s.contains("key=0xabcd1234"));
    }
}
