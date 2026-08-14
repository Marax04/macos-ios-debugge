//! Packer signature database: byte-level and structural signatures for common
//! executable packers, with fast multi-pattern matching and confidence scoring.

use std::collections::HashMap;
use std::fmt;

use crate::{compute_entropy, find_bytes, DetectKind};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors produced by the packer signature database.
#[derive(Debug)]
pub enum SigError {
    /// The hex pattern string is malformed.
    BadPattern(String),
    /// The database was queried before any signatures were loaded.
    Empty,
}

impl fmt::Display for SigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPattern(s) => write!(f, "bad hex pattern: {s}"),
            Self::Empty => write!(f, "signature database is empty"),
        }
    }
}

impl std::error::Error for SigError {}

// ── SigKind ───────────────────────────────────────────────────────────────────

/// The structural kind of a signature anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigKind {
    /// The pattern must appear at an exact file offset.
    Absolute,
    /// The pattern must appear anywhere inside the file (linear scan).
    AnyOffset,
    /// The pattern must appear in the first `n` bytes of the PE entry-point
    /// code (first 64 bytes).
    EntryPoint,
    /// The pattern must appear in the overlay (bytes after last PE section).
    Overlay,
}

impl fmt::Display for SigKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── SigEntry ──────────────────────────────────────────────────────────────────

/// A single anchor within a packer signature: an offset, a byte pattern, and a
/// matching strategy.
///
/// Patterns use the space-separated hex notation of [`find_bytes`]:
/// `"60 BE ?? ?? ??"` — `??` is a wildcard byte.
#[derive(Debug, Clone)]
pub struct SigEntry {
    /// File offset for `Absolute` kind; ignored for other kinds.
    pub offset: usize,
    /// Hex pattern string (space-separated, `??` for wildcards).
    pub pattern: String,
    /// How to locate this anchor in the file.
    pub kind: SigKind,
    /// Minimum entropy of the section/region containing this match.
    /// `None` means no entropy check.
    pub min_entropy: Option<f32>,
}

impl SigEntry {
    /// Create an `AnyOffset` anchor.
    #[must_use]
    pub fn anywhere(pattern: impl Into<String>) -> Self {
        Self {
            offset: 0,
            pattern: pattern.into(),
            kind: SigKind::AnyOffset,
            min_entropy: None,
        }
    }

    /// Create an `Absolute` anchor at a fixed file offset.
    #[must_use]
    pub fn at_offset(offset: usize, pattern: impl Into<String>) -> Self {
        Self {
            offset,
            pattern: pattern.into(),
            kind: SigKind::Absolute,
            min_entropy: None,
        }
    }

    /// Create an `EntryPoint` anchor (matched against the first 64 EP bytes).
    #[must_use]
    pub fn at_entry_point(pattern: impl Into<String>) -> Self {
        Self {
            offset: 0,
            pattern: pattern.into(),
            kind: SigKind::EntryPoint,
            min_entropy: None,
        }
    }

    /// Create an `Overlay` anchor.
    #[must_use]
    pub fn in_overlay(pattern: impl Into<String>) -> Self {
        Self {
            offset: 0,
            pattern: pattern.into(),
            kind: SigKind::Overlay,
            min_entropy: None,
        }
    }

    /// Require a minimum entropy of the matched region.
    #[must_use]
    pub fn with_min_entropy(mut self, e: f32) -> Self {
        self.min_entropy = Some(e);
        self
    }

    /// Test whether this anchor matches inside `data`.
    ///
    /// `ep_bytes` must be the first ≤64 bytes of PE entry-point code (may be
    /// empty if entry point is unavailable).
    /// `overlay_start` is the file offset at which the PE overlay begins; if
    /// `None` no overlay is present.
    #[must_use]
    pub fn matches(&self, data: &[u8], ep_bytes: &[u8], overlay_start: Option<usize>) -> bool {
        let matched_offset = match self.kind {
            SigKind::Absolute => {
                if self.offset >= data.len() {
                    return false;
                }
                find_bytes(&data[self.offset..], &self.pattern).map(|o| self.offset + o)
            }
            SigKind::AnyOffset => find_bytes(data, &self.pattern),
            SigKind::EntryPoint => {
                if ep_bytes.is_empty() {
                    return false;
                }
                find_bytes(ep_bytes, &self.pattern).map(|o| o) // relative to ep_bytes
            }
            SigKind::Overlay => {
                let Some(ov) = overlay_start else {
                    return false;
                };
                if ov >= data.len() {
                    return false;
                }
                find_bytes(&data[ov..], &self.pattern).map(|o| ov + o)
            }
        };

        let Some(file_off) = matched_offset else {
            return false;
        };

        // Optional entropy check over a 256-byte window around the match.
        if let Some(min_e) = self.min_entropy {
            let window_start = file_off.saturating_sub(128);
            let window_end = (file_off + 128).min(data.len());
            if window_end > window_start {
                let ent = compute_entropy(&data[window_start..window_end]);
                if ent < min_e {
                    return false;
                }
            }
        }

        true
    }
}

// ── PackerSig ─────────────────────────────────────────────────────────────────

/// A complete packer signature: a name, category, version, one or more anchors,
/// and a base confidence score.
///
/// A signature fires when **all** of its [`SigEntry`] anchors match.
#[derive(Debug, Clone)]
pub struct PackerSig {
    /// Human-readable product name (e.g. `"UPX"`).
    pub name: String,
    /// Version string if known (e.g. `"3.x"`).
    pub version: Option<String>,
    /// Category for this packer.
    pub kind: DetectKind,
    /// All anchors that must match.
    pub entries: Vec<SigEntry>,
    /// Base confidence 0–100 when all anchors match.
    pub confidence: u8,
    /// Additional tags for grouping / filtering.
    pub tags: Vec<String>,
}

impl PackerSig {
    /// Create a new packer signature with no entries.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        kind: DetectKind,
        confidence: u8,
    ) -> Self {
        Self {
            name: name.into(),
            version: None,
            kind,
            entries: Vec::new(),
            confidence,
            tags: Vec::new(),
        }
    }

    /// Set the version string.
    #[must_use]
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    /// Add a signature anchor.
    #[must_use]
    pub fn entry(mut self, e: SigEntry) -> Self {
        self.entries.push(e);
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    /// Return `true` if every anchor in this signature matches inside `data`.
    #[must_use]
    pub fn matches(
        &self,
        data: &[u8],
        ep_bytes: &[u8],
        overlay_start: Option<usize>,
    ) -> bool {
        self.entries
            .iter()
            .all(|e| e.matches(data, ep_bytes, overlay_start))
    }
}

impl fmt::Display for PackerSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = self.version.as_deref().unwrap_or("?");
        write!(f, "{} v{} ({:?}, {}%)", self.name, ver, self.kind, self.confidence)
    }
}

// ── MatchResult ───────────────────────────────────────────────────────────────

/// A single match produced by [`PackerSignatureDb::match_bytes`].
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The signature that matched.
    pub sig: PackerSig,
    /// Confidence at the time of matching (may be adjusted from base).
    pub confidence: u8,
    /// Byte offset of the first anchor match (informational; `usize::MAX` when
    /// not determinable).
    pub first_offset: usize,
}

impl fmt::Display for MatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] {} (conf {}%)",
            self.sig.kind, self.sig.name, self.confidence
        )
    }
}

// ── PackerSignatureDb ─────────────────────────────────────────────────────────

/// In-memory database of [`PackerSig`] signatures, with batch-match
/// and index-by-tag capabilities.
///
/// ```
/// use rustre_triage_die::packer_signature_db::{PackerSignatureDb, PackerSig, SigEntry};
/// use rustre_triage_die::DetectKind;
///
/// let mut db = PackerSignatureDb::new();
/// db.add(
///     PackerSig::new("UPX", DetectKind::Packer, 95)
///         .version("3.x")
///         .entry(SigEntry::anywhere("55 50 58 30"))   // "UPX0"
///         .entry(SigEntry::anywhere("55 50 58 31")), // "UPX1"
/// );
/// let data = b"MZ...UPX0...UPX1...";
/// let hits = db.match_bytes(data);
/// assert!(!hits.is_empty());
/// ```
#[derive(Debug, Default)]
pub struct PackerSignatureDb {
    sigs: Vec<PackerSig>,
    /// Quick index: tag → indices into `sigs`.
    tag_index: HashMap<String, Vec<usize>>,
}

impl PackerSignatureDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a signature to the database.
    pub fn add(&mut self, sig: PackerSig) {
        let idx = self.sigs.len();
        for tag in &sig.tags {
            self.tag_index.entry(tag.clone()).or_default().push(idx);
        }
        self.sigs.push(sig);
    }

    /// Total number of signatures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    /// Returns `true` if the database contains no signatures.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    /// Return all signatures with the given tag.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&PackerSig> {
        self.tag_index
            .get(tag)
            .map(|idxs| idxs.iter().map(|&i| &self.sigs[i]).collect())
            .unwrap_or_default()
    }

    /// Return all signatures of a given [`DetectKind`].
    #[must_use]
    pub fn by_kind(&self, kind: DetectKind) -> Vec<&PackerSig> {
        self.sigs.iter().filter(|s| s.kind == kind).collect()
    }

    /// Match all signatures against raw file bytes.
    ///
    /// Computes the PE entry-point bytes and overlay start internally, then
    /// runs every signature.  Results are sorted by confidence descending.
    ///
    /// # Parameters
    /// - `data` — raw file bytes.
    #[must_use]
    pub fn match_bytes(&self, data: &[u8]) -> Vec<MatchResult> {
        let ep_bytes = crate::get_entry_point_bytes(data);
        let overlay_start = Self::find_overlay_start(data);

        let mut results: Vec<MatchResult> = self
            .sigs
            .iter()
            .filter(|sig| sig.matches(data, &ep_bytes, overlay_start))
            .map(|sig| MatchResult {
                confidence: sig.confidence,
                first_offset: usize::MAX,
                sig: sig.clone(),
            })
            .collect();

        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Match only signatures of a specific kind.
    #[must_use]
    pub fn match_kind(&self, data: &[u8], kind: DetectKind) -> Vec<MatchResult> {
        let ep_bytes = crate::get_entry_point_bytes(data);
        let overlay_start = Self::find_overlay_start(data);

        let mut results: Vec<MatchResult> = self
            .sigs
            .iter()
            .filter(|sig| sig.kind == kind && sig.matches(data, &ep_bytes, overlay_start))
            .map(|sig| MatchResult {
                confidence: sig.confidence,
                first_offset: usize::MAX,
                sig: sig.clone(),
            })
            .collect();

        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Compute the file offset at which the PE overlay begins, or `None`.
    fn find_overlay_start(data: &[u8]) -> Option<usize> {
        if data.len() < 0x40 {
            return None;
        }
        if &data[0..2] != b"MZ" {
            return None;
        }
        let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
        if pe_off + 0x18 > data.len() {
            return None;
        }
        if &data[pe_off..pe_off + 4] != b"PE\0\0" {
            return None;
        }
        let num_sections =
            u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
        let opt_size =
            u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
        let sec_tbl = pe_off + 0x18 + opt_size;

        let mut end_of_sections: usize = 0;
        for i in 0..num_sections {
            let s = sec_tbl + i * 40;
            if s + 40 > data.len() {
                break;
            }
            let raw_off =
                u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?) as usize;
            let raw_size =
                u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?) as usize;
            let end = raw_off + raw_size;
            if end > end_of_sections {
                end_of_sections = end;
            }
        }
        if end_of_sections > 0 && data.len() > end_of_sections {
            Some(end_of_sections)
        } else {
            None
        }
    }

    /// Build a [`PackerSignatureDb`] pre-loaded with a curated set of
    /// well-known packer signatures.
    #[must_use]
    pub fn load_defaults() -> Self {
        let mut db = Self::new();

        // UPX 3.x / 4.x — section name anchors
        db.add(
            PackerSig::new("UPX", DetectKind::Packer, 96)
                .version("3.x/4.x")
                .entry(SigEntry::anywhere("55 50 58 30")) // "UPX0"
                .entry(SigEntry::anywhere("55 50 58 31")) // "UPX1"
                .tag("upx"),
        );

        // UPX entry-point stub: PUSHAD + MOV ESI, … (x86)
        db.add(
            PackerSig::new("UPX x86 EP", DetectKind::Packer, 85)
                .version("3.x")
                .entry(SigEntry::at_entry_point("60 BE ?? ?? ?? ?? 8D BE"))
                .tag("upx"),
        );

        // MPRESS packer
        db.add(
            PackerSig::new("MPRESS", DetectKind::Packer, 91)
                .version("2.x")
                .entry(SigEntry::anywhere("2E 4D 50 52 45 53 53")) // ".MPRESS"
                .tag("mpress"),
        );

        // ASPack
        db.add(
            PackerSig::new("ASPack", DetectKind::Packer, 90)
                .version("2.x")
                .entry(SigEntry::anywhere("2E 61 73 70 61 63 6B")) // ".aspack"
                .tag("aspack"),
        );

        // PECompact 2
        db.add(
            PackerSig::new("PECompact", DetectKind::Packer, 89)
                .version("2.x")
                .entry(SigEntry::anywhere("50 45 43 6F 6D 70 61 63 74 32")) // "PECompact2"
                .tag("pecompact"),
        );

        // FSG Packer
        db.add(
            PackerSig::new("FSG", DetectKind::Packer, 87)
                .version("2.0")
                .entry(SigEntry::anywhere("46 53 47 21")) // "FSG!"
                .tag("fsg"),
        );

        // MEW packer entry stub: JMP opcode 0xE9
        db.add(
            PackerSig::new("MEW", DetectKind::Packer, 82)
                .version("1.1")
                .entry(SigEntry::at_entry_point("E9"))
                .entry(SigEntry::anywhere("4D 45 57")) // "MEW"
                .tag("mew"),
        );

        // PESpin
        db.add(
            PackerSig::new("PESpin", DetectKind::Packer, 86)
                .version("1.3")
                .entry(SigEntry::anywhere("50 45 53 70 69 6E")) // "PESpin"
                .tag("pespin"),
        );

        // Themida / WinLicense
        db.add(
            PackerSig::new("Themida", DetectKind::Protector, 93)
                .version("3.x")
                .entry(SigEntry::anywhere("2E 74 68 65 6D 69 64 61")) // ".themida"
                .tag("themida"),
        );

        // VMProtect 2/3
        db.add(
            PackerSig::new("VMProtect", DetectKind::Protector, 93)
                .version("2.x/3.x")
                .entry(SigEntry::anywhere("2E 76 6D 70 30")) // ".vmp0"
                .tag("vmprotect"),
        );

        // Obsidium
        db.add(
            PackerSig::new("Obsidium", DetectKind::Protector, 88)
                .version("1.x")
                .entry(SigEntry::anywhere("4F 62 73 69 64 69 75 6D")) // "Obsidium"
                .tag("obsidium"),
        );

        // Enigma Protector
        db.add(
            PackerSig::new("Enigma Protector", DetectKind::Protector, 90)
                .version("7.x")
                .entry(SigEntry::anywhere("2E 65 6E 69 67 6D 61 31")) // ".enigma1"
                .tag("enigma"),
        );

        // PyInstaller
        db.add(
            PackerSig::new("PyInstaller", DetectKind::Tool, 94)
                .version("6.x")
                .entry(SigEntry::anywhere("4D 45 49 0C 0B 0A 0B 0E")) // MEI magic
                .tag("pyinstaller"),
        );

        // NSIS installer
        db.add(
            PackerSig::new("NSIS", DetectKind::Installer, 86)
                .version("3.x")
                .entry(SigEntry::anywhere("4E 75 6C 6C 73 6F 66 74")) // "Nullsoft"
                .tag("nsis"),
        );

        // AutoIt script
        db.add(
            PackerSig::new("AutoIt", DetectKind::Tool, 92)
                .version("3.x")
                .entry(SigEntry::anywhere("41 55 33 21 45 41")) // "AU3!EA"
                .tag("autoit"),
        );

        db
    }

    /// Merge another database into this one (appends all signatures).
    pub fn merge(&mut self, other: PackerSignatureDb) {
        for sig in other.sigs {
            self.add(sig);
        }
    }

    /// Remove all signatures with the given tag.
    pub fn remove_by_tag(&mut self, tag: &str) {
        if let Some(idxs) = self.tag_index.remove(tag) {
            let to_remove: std::collections::HashSet<usize> = idxs.into_iter().collect();
            let mut new_sigs: Vec<PackerSig> = Vec::new();
            let mut new_idx: HashMap<String, Vec<usize>> = HashMap::new();
            for (old_idx, sig) in self.sigs.drain(..).enumerate() {
                if to_remove.contains(&old_idx) {
                    continue;
                }
                let new_i = new_sigs.len();
                for t in &sig.tags {
                    new_idx.entry(t.clone()).or_default().push(new_i);
                }
                new_sigs.push(sig);
            }
            self.sigs = new_sigs;
            self.tag_index = new_idx;
        }
    }

    /// Return the name → confidence map for a quick overview.
    #[must_use]
    pub fn summary(&self) -> Vec<(String, u8)> {
        self.sigs
            .iter()
            .map(|s| (s.name.clone(), s.confidence))
            .collect()
    }
}

// ── Free function: match_bytes ─────────────────────────────────────────────────

/// Convenience wrapper: create a default [`PackerSignatureDb`] and run it
/// against `data`.  Returns matches sorted by confidence descending.
///
/// Equivalent to `PackerSignatureDb::load_defaults().match_bytes(data)`.
#[must_use]
pub fn match_bytes(data: &[u8]) -> Vec<MatchResult> {
    PackerSignatureDb::load_defaults().match_bytes(data)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mz_stub() -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0] = b'M';
        v[1] = b'Z';
        v
    }

    #[test]
    fn db_starts_empty() {
        let db = PackerSignatureDb::new();
        assert!(db.is_empty());
    }

    #[test]
    fn add_and_len() {
        let mut db = PackerSignatureDb::new();
        db.add(PackerSig::new("X", DetectKind::Packer, 50).entry(SigEntry::anywhere("AA BB")));
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn match_simple_pattern() {
        let mut db = PackerSignatureDb::new();
        db.add(
            PackerSig::new("X", DetectKind::Packer, 90)
                .entry(SigEntry::anywhere("DE AD BE EF")),
        );
        let data = b"\xDE\xAD\xBE\xEF";
        let hits = db.match_bytes(data);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sig.name, "X");
    }

    #[test]
    fn no_match_when_pattern_absent() {
        let mut db = PackerSignatureDb::new();
        db.add(
            PackerSig::new("X", DetectKind::Packer, 90)
                .entry(SigEntry::anywhere("DE AD BE EF")),
        );
        let hits = db.match_bytes(b"\x00\x01\x02");
        assert!(hits.is_empty());
    }

    #[test]
    fn wildcard_anchor_matches() {
        let mut db = PackerSignatureDb::new();
        db.add(
            PackerSig::new("W", DetectKind::Packer, 70)
                .entry(SigEntry::anywhere("AA ?? CC")),
        );
        let data = b"\xAA\xBB\xCC";
        assert_eq!(db.match_bytes(data).len(), 1);
    }

    #[test]
    fn absolute_offset_match() {
        let mut db = PackerSignatureDb::new();
        db.add(
            PackerSig::new("A", DetectKind::Packer, 70)
                .entry(SigEntry::at_offset(2, "CC DD")),
        );
        let data = b"\x00\x00\xCC\xDD";
        assert_eq!(db.match_bytes(data).len(), 1);
    }

    #[test]
    fn absolute_offset_no_match_wrong_position() {
        let mut db = PackerSignatureDb::new();
        db.add(
            PackerSig::new("A", DetectKind::Packer, 70)
                .entry(SigEntry::at_offset(10, "CC DD")),
        );
        let data = b"\xCC\xDD\x00\x00";
        assert!(db.match_bytes(data).is_empty());
    }

    #[test]
    fn by_kind_filters_correctly() {
        let db = PackerSignatureDb::load_defaults();
        let packers = db.by_kind(DetectKind::Packer);
        let protectors = db.by_kind(DetectKind::Protector);
        assert!(!packers.is_empty());
        assert!(!protectors.is_empty());
        assert!(packers.iter().all(|s| s.kind == DetectKind::Packer));
        assert!(protectors.iter().all(|s| s.kind == DetectKind::Protector));
    }

    #[test]
    fn by_tag_returns_correct_sigs() {
        let db = PackerSignatureDb::load_defaults();
        let upx = db.by_tag("upx");
        assert!(!upx.is_empty());
        assert!(upx.iter().all(|s| s.tags.contains(&"upx".to_string())));
    }

    #[test]
    fn match_bytes_free_fn_returns_vec() {
        // Minimal MZ header + UPX markers
        let mut data = mz_stub();
        data.extend_from_slice(b"UPX0");
        data.extend_from_slice(b"UPX1");
        let hits = match_bytes(&data);
        assert!(!hits.is_empty());
    }

    #[test]
    fn remove_by_tag_works() {
        let mut db = PackerSignatureDb::load_defaults();
        let before = db.len();
        db.remove_by_tag("upx");
        assert!(db.len() < before);
        assert!(db.by_tag("upx").is_empty());
    }

    #[test]
    fn sig_display() {
        let s = PackerSig::new("Test", DetectKind::Packer, 75).version("1.0");
        assert!(s.to_string().contains("Test"));
        assert!(s.to_string().contains("75%"));
    }

    #[test]
    fn match_result_display() {
        let r = MatchResult {
            sig: PackerSig::new("Foo", DetectKind::Packer, 80),
            confidence: 80,
            first_offset: 0,
        };
        assert!(r.to_string().contains("Foo"));
    }

    #[test]
    fn merge_databases() {
        let mut db1 = PackerSignatureDb::new();
        db1.add(PackerSig::new("A", DetectKind::Packer, 80));
        let mut db2 = PackerSignatureDb::new();
        db2.add(PackerSig::new("B", DetectKind::Packer, 90));
        db1.merge(db2);
        assert_eq!(db1.len(), 2);
    }

    #[test]
    fn all_anchors_must_match() {
        let mut db = PackerSignatureDb::new();
        db.add(
            PackerSig::new("Both", DetectKind::Packer, 99)
                .entry(SigEntry::anywhere("AA BB"))
                .entry(SigEntry::anywhere("CC DD")),
        );
        // Only first anchor present
        assert!(db.match_bytes(b"\xAA\xBB").is_empty());
        // Both present
        assert_eq!(db.match_bytes(b"\xAA\xBB\xCC\xDD").len(), 1);
    }
}
