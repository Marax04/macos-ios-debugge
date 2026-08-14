//! PDB OMAP (Object Map) translation support.
//!
//! OMAP streams allow a debugger to translate addresses between the original
//! linked layout of a PE file and the post-link-optimised layout that was
//! actually written to disk (or vice-versa).  Two streams are involved:
//!
//! * `OMAPTO` – translates *from* the original address *to* the remapped one.
//! * `OMAPFROM` – translates *from* the remapped address *to* the original.
//!
//! Each stream contains a sorted array of `{ rva: u32, rva_to: u32 }` pairs.
//! An RVA `x` in stream `S` maps to `entry.rva_to + (x - entry.rva)` where
//! `entry` is the last entry whose `rva` field is `<= x`.

use std::fmt;

// ── Error type ────────────────────────────────────────────────────────────────

/// Error type for OMAP operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OmapError {
    /// The raw byte stream is not a multiple of 8 bytes.
    BadAlignment,
    /// The OMAP table is empty; no translation is possible.
    EmptyTable,
    /// The supplied RVA is below the lowest entry in the table.
    RvaBelowRange(u32),
    /// The entry for this RVA has a zero target (`rva_to == 0`), indicating
    /// the address was removed by the optimiser.
    Unmapped(u32),
}

impl fmt::Display for OmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadAlignment => write!(f, "OMAP stream length is not a multiple of 8"),
            Self::EmptyTable => write!(f, "OMAP table is empty"),
            Self::RvaBelowRange(r) => write!(f, "RVA 0x{r:08X} is below the first OMAP entry"),
            Self::Unmapped(r) => write!(f, "RVA 0x{r:08X} is unmapped (removed by optimiser)"),
        }
    }
}

impl std::error::Error for OmapError {}

// ── OmapKind ──────────────────────────────────────────────────────────────────

/// Which direction the OMAP stream translates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OmapKind {
    /// Translates original RVAs to remapped RVAs (`OMAPTO` stream).
    ToRemapped,
    /// Translates remapped RVAs to original RVAs (`OMAPFROM` stream).
    FromRemapped,
}

impl OmapKind {
    /// Return the PDB stream name for this OMAP direction.
    #[must_use]
    pub const fn stream_name(self) -> &'static str {
        match self {
            Self::ToRemapped => "OMAPTO",
            Self::FromRemapped => "OMAPFROM",
        }
    }
}

impl fmt::Display for OmapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stream_name())
    }
}

// ── OmapEntry ─────────────────────────────────────────────────────────────────

/// A single entry in an OMAP stream.
///
/// The binary layout is two consecutive `u32` values in little-endian order:
/// `[rva: u32, rva_to: u32]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OmapEntry {
    /// Source RVA (start of a range in the source address space).
    pub rva: u32,
    /// Destination RVA that `rva` maps to.  Zero means the range was removed.
    pub rva_to: u32,
}

impl OmapEntry {
    /// Construct an entry from its raw `u32` fields.
    #[must_use]
    pub const fn new(rva: u32, rva_to: u32) -> Self {
        Self { rva, rva_to }
    }

    /// Return `true` if this entry represents an unmapped (removed) range.
    #[must_use]
    pub const fn is_unmapped(self) -> bool {
        self.rva_to == 0
    }
}

// ── PdbOmap ───────────────────────────────────────────────────────────────────

/// A parsed OMAP stream from a PDB file.
///
/// Entries are stored sorted by `rva` (ascending) so that binary search can be
/// used to resolve any source RVA in O(log n) time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PdbOmap {
    /// Direction of this OMAP stream.
    pub kind: OmapKind,
    /// Sorted entries.
    entries: Vec<OmapEntry>,
}

impl PdbOmap {
    /// Parse an OMAP stream from raw bytes.
    ///
    /// The raw format is a tightly-packed array of `(rva: u32le, rva_to: u32le)`
    /// pairs with no header or terminator.
    ///
    /// # Errors
    /// Returns [`OmapError::BadAlignment`] if `raw.len() % 8 != 0`.
    pub fn from_bytes(kind: OmapKind, raw: &[u8]) -> Result<Self, OmapError> {
        if !raw.len().is_multiple_of(8) {
            return Err(OmapError::BadAlignment);
        }
        let count = raw.len() / 8;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let off = i * 8;
            let rva = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
            let rva_to = u32::from_le_bytes([
                raw[off + 4],
                raw[off + 5],
                raw[off + 6],
                raw[off + 7],
            ]);
            entries.push(OmapEntry { rva, rva_to });
        }
        // Guarantee sorted order.  Well-formed PDB OMAP streams are already
        // sorted, but we sort defensively to make `translate_rva` correct even
        // for malformed input.
        entries.sort_unstable_by_key(|e| e.rva);
        Ok(Self { kind, entries })
    }

    /// Build a `PdbOmap` directly from a `Vec<OmapEntry>` (already sorted).
    ///
    /// The entries will be re-sorted to ensure correctness.
    #[must_use]
    pub fn from_entries(kind: OmapKind, mut entries: Vec<OmapEntry>) -> Self {
        entries.sort_unstable_by_key(|e| e.rva);
        Self { kind, entries }
    }

    /// Return the number of entries in this OMAP table.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the OMAP table contains no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return a slice of all entries.
    #[must_use]
    pub fn entries(&self) -> &[OmapEntry] {
        &self.entries
    }

    /// Translate a source RVA to its destination RVA.
    ///
    /// The algorithm is a standard OMAP binary search:
    /// 1. Find the last entry whose `rva <= source`.
    /// 2. Compute `destination = entry.rva_to + (source - entry.rva)`.
    /// 3. If `entry.rva_to == 0` the range was deleted → return [`OmapError::Unmapped`].
    ///
    /// # Errors
    /// * [`OmapError::EmptyTable`] – no entries loaded.
    /// * [`OmapError::RvaBelowRange`] – `source` is below the first entry.
    /// * [`OmapError::Unmapped`] – the range containing `source` was removed.
    pub fn translate_rva(&self, source: u32) -> Result<u32, OmapError> {
        if self.entries.is_empty() {
            return Err(OmapError::EmptyTable);
        }
        // Binary search for the last entry with rva <= source.
        let idx = match self.entries.partition_point(|e| e.rva <= source) {
            0 => return Err(OmapError::RvaBelowRange(source)),
            n => n - 1,
        };
        let entry = self.entries[idx];
        if entry.rva_to == 0 {
            return Err(OmapError::Unmapped(source));
        }
        let offset = source - entry.rva;
        Ok(entry.rva_to + offset)
    }

    /// Attempt to translate `source`, returning `None` on any error.
    ///
    /// Convenience wrapper for callers that do not need to distinguish error kinds.
    #[must_use]
    pub fn try_translate(&self, source: u32) -> Option<u32> {
        self.translate_rva(source).ok()
    }

    /// Translate a list of RVAs, silently dropping any that fail to map.
    #[must_use]
    pub fn translate_many(&self, rvas: &[u32]) -> Vec<(u32, u32)> {
        rvas.iter()
            .filter_map(|&r| self.translate_rva(r).ok().map(|t| (r, t)))
            .collect()
    }

    /// Return the entry that covers `source`, if any.
    ///
    /// Returns `None` when the table is empty or `source` is below the first entry.
    #[must_use]
    pub fn covering_entry(&self, source: u32) -> Option<OmapEntry> {
        if self.entries.is_empty() {
            return None;
        }
        let idx = self.entries.partition_point(|e| e.rva <= source);
        if idx == 0 {
            return None;
        }
        Some(self.entries[idx - 1])
    }

    /// Serialize the OMAP table to raw bytes in PDB format.
    ///
    /// Each entry is written as two little-endian `u32` values (`rva`, `rva_to`).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * 8);
        for e in &self.entries {
            out.extend_from_slice(&e.rva.to_le_bytes());
            out.extend_from_slice(&e.rva_to.to_le_bytes());
        }
        out
    }

    /// Return the highest source RVA present in the table, if any.
    #[must_use]
    pub fn max_source_rva(&self) -> Option<u32> {
        self.entries.last().map(|e| e.rva)
    }

    /// Return the highest destination RVA present in the mapped entries.
    #[must_use]
    pub fn max_dest_rva(&self) -> Option<u32> {
        self.entries
            .iter()
            .filter(|e| !e.is_unmapped())
            .map(|e| e.rva_to)
            .max()
    }

    /// Count the number of unmapped (removed) entries.
    #[must_use]
    pub fn unmapped_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_unmapped()).count()
    }

    /// Build a merged OMAP by composing `self` with `other`.
    ///
    /// That is, for every RVA `x`, compute `other.translate(self.translate(x))`.
    /// Only RVAs that are successfully translated by both maps are included.
    ///
    /// The resulting map uses the kind of `other`.
    #[must_use]
    pub fn compose(&self, other: &Self) -> Self {
        let composed: Vec<OmapEntry> = self
            .entries
            .iter()
            .filter_map(|e| {
                if e.is_unmapped() {
                    return None;
                }
                let dest = other.translate_rva(e.rva_to).ok()?;
                Some(OmapEntry::new(e.rva, dest))
            })
            .collect();
        Self::from_entries(other.kind, composed)
    }
}

// ── Standalone translation function ──────────────────────────────────────────

/// Translate `rva` using a raw OMAP byte stream without constructing a
/// [`PdbOmap`] object.
///
/// Useful for one-shot translations where constructing the full struct is
/// unnecessary.  The stream is searched with a linear scan; prefer
/// [`PdbOmap::translate_rva`] for repeated queries on the same table.
///
/// # Errors
/// See [`OmapError`] for the possible failure modes.
pub fn translate_rva(raw: &[u8], rva: u32) -> Result<u32, OmapError> {
    if !raw.len().is_multiple_of(8) {
        return Err(OmapError::BadAlignment);
    }
    let count = raw.len() / 8;
    if count == 0 {
        return Err(OmapError::EmptyTable);
    }
    // Linear scan to find the predecessor entry.
    let mut best: Option<OmapEntry> = None;
    for i in 0..count {
        let off = i * 8;
        let entry_rva =
            u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
        if entry_rva > rva {
            break;
        }
        let rva_to = u32::from_le_bytes([
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ]);
        best = Some(OmapEntry { rva: entry_rva, rva_to });
    }
    match best {
        None => Err(OmapError::RvaBelowRange(rva)),
        Some(e) if e.rva_to == 0 => Err(OmapError::Unmapped(rva)),
        Some(e) => Ok(e.rva_to + (rva - e.rva)),
    }
}

// ── OmapStatistics ────────────────────────────────────────────────────────────

/// Summary statistics for a [`PdbOmap`] table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OmapStatistics {
    /// Total number of entries.
    pub total_entries: usize,
    /// Number of unmapped (removed) entries.
    pub unmapped_entries: usize,
    /// Lowest source RVA, if any.
    pub min_source_rva: Option<u32>,
    /// Highest source RVA, if any.
    pub max_source_rva: Option<u32>,
    /// Lowest non-zero destination RVA.
    pub min_dest_rva: Option<u32>,
    /// Highest non-zero destination RVA.
    pub max_dest_rva: Option<u32>,
}

impl OmapStatistics {
    /// Compute statistics for the given [`PdbOmap`].
    #[must_use]
    pub fn compute(omap: &PdbOmap) -> Self {
        let entries = omap.entries();
        let unmapped_entries = entries.iter().filter(|e| e.is_unmapped()).count();
        let min_source_rva = entries.first().map(|e| e.rva);
        let max_source_rva = entries.last().map(|e| e.rva);
        let mut min_dest: Option<u32> = None;
        let mut max_dest: Option<u32> = None;
        for e in entries.iter().filter(|e| !e.is_unmapped()) {
            min_dest = Some(min_dest.map_or(e.rva_to, |m: u32| m.min(e.rva_to)));
            max_dest = Some(max_dest.map_or(e.rva_to, |m: u32| m.max(e.rva_to)));
        }
        Self {
            total_entries: entries.len(),
            unmapped_entries,
            min_source_rva,
            max_source_rva,
            min_dest_rva: min_dest,
            max_dest_rva: max_dest,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(pairs: &[(u32, u32)]) -> Vec<u8> {
        let mut v = Vec::with_capacity(pairs.len() * 8);
        for &(rva, rva_to) in pairs {
            v.extend_from_slice(&rva.to_le_bytes());
            v.extend_from_slice(&rva_to.to_le_bytes());
        }
        v
    }

    fn simple_omap() -> PdbOmap {
        // source range [0x1000, 0x2000) → destination starting at 0x5000
        // source range [0x2000, 0x3000) → removed
        // source range [0x3000, 0x4000) → destination starting at 0x7000
        PdbOmap::from_entries(
            OmapKind::ToRemapped,
            vec![
                OmapEntry::new(0x1000, 0x5000),
                OmapEntry::new(0x2000, 0x0000), // unmapped
                OmapEntry::new(0x3000, 0x7000),
            ],
        )
    }

    #[test]
    fn test_omap_kind_stream_names() {
        assert_eq!(OmapKind::ToRemapped.stream_name(), "OMAPTO");
        assert_eq!(OmapKind::FromRemapped.stream_name(), "OMAPFROM");
    }

    #[test]
    fn test_omap_entry_is_unmapped() {
        assert!(!OmapEntry::new(0x1000, 0x5000).is_unmapped());
        assert!(OmapEntry::new(0x2000, 0).is_unmapped());
    }

    #[test]
    fn test_from_bytes_basic() {
        let raw = make_raw(&[(0x1000, 0x5000), (0x2000, 0x6000)]);
        let omap = PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap();
        assert_eq!(omap.len(), 2);
        assert_eq!(omap.entries()[0].rva, 0x1000);
        assert_eq!(omap.entries()[1].rva_to, 0x6000);
    }

    #[test]
    fn test_from_bytes_bad_alignment() {
        let raw = vec![0u8; 7];
        assert_eq!(
            PdbOmap::from_bytes(OmapKind::ToRemapped, &raw).unwrap_err(),
            OmapError::BadAlignment
        );
    }

    #[test]
    fn test_from_bytes_empty() {
        let omap = PdbOmap::from_bytes(OmapKind::FromRemapped, &[]).unwrap();
        assert!(omap.is_empty());
    }

    #[test]
    fn test_translate_basic_offset() {
        let omap = simple_omap();
        // 0x1000 → 0x5000 (exact hit)
        assert_eq!(omap.translate_rva(0x1000).unwrap(), 0x5000);
        // 0x1080 → 0x5000 + 0x80
        assert_eq!(omap.translate_rva(0x1080).unwrap(), 0x5080);
        // 0x3FFF → 0x7000 + 0xFFF
        assert_eq!(omap.translate_rva(0x3FFF).unwrap(), 0x7FFF);
    }

    #[test]
    fn test_translate_unmapped() {
        let omap = simple_omap();
        match omap.translate_rva(0x2500).unwrap_err() {
            OmapError::Unmapped(r) => assert_eq!(r, 0x2500),
            e => panic!("unexpected error {e}"),
        }
    }

    #[test]
    fn test_translate_below_range() {
        let omap = simple_omap();
        match omap.translate_rva(0x0FFF).unwrap_err() {
            OmapError::RvaBelowRange(r) => assert_eq!(r, 0x0FFF),
            e => panic!("unexpected error {e}"),
        }
    }

    #[test]
    fn test_translate_empty_table() {
        let omap = PdbOmap::from_entries(OmapKind::ToRemapped, vec![]);
        assert_eq!(omap.translate_rva(0x1000).unwrap_err(), OmapError::EmptyTable);
    }

    #[test]
    fn test_try_translate_none_on_error() {
        let omap = simple_omap();
        assert!(omap.try_translate(0x2000).is_none());
        assert_eq!(omap.try_translate(0x1000), Some(0x5000));
    }

    #[test]
    fn test_translate_many() {
        let omap = simple_omap();
        let results = omap.translate_many(&[0x1000, 0x2000, 0x3000]);
        // 0x2000 is unmapped → not in results
        assert_eq!(results.len(), 2);
        assert!(results.contains(&(0x1000, 0x5000)));
        assert!(results.contains(&(0x3000, 0x7000)));
    }

    #[test]
    fn test_covering_entry() {
        let omap = simple_omap();
        assert_eq!(
            omap.covering_entry(0x1500),
            Some(OmapEntry::new(0x1000, 0x5000))
        );
        assert_eq!(omap.covering_entry(0x0FFF), None);
    }

    #[test]
    fn test_to_bytes_roundtrip() {
        let omap = simple_omap();
        let bytes = omap.to_bytes();
        let omap2 = PdbOmap::from_bytes(OmapKind::ToRemapped, &bytes).unwrap();
        assert_eq!(omap.entries(), omap2.entries());
    }

    #[test]
    fn test_max_source_and_dest_rva() {
        let omap = simple_omap();
        assert_eq!(omap.max_source_rva(), Some(0x3000));
        assert_eq!(omap.max_dest_rva(), Some(0x7000));
    }

    #[test]
    fn test_unmapped_count() {
        let omap = simple_omap();
        assert_eq!(omap.unmapped_count(), 1);
    }

    #[test]
    fn test_standalone_translate_rva() {
        let raw = make_raw(&[(0x1000, 0x5000), (0x2000, 0x6000)]);
        assert_eq!(translate_rva(&raw, 0x1080).unwrap(), 0x5080);
        assert_eq!(
            translate_rva(&raw, 0x0100).unwrap_err(),
            OmapError::RvaBelowRange(0x0100)
        );
        assert_eq!(translate_rva(&[1u8; 7], 0).unwrap_err(), OmapError::BadAlignment);
        assert_eq!(translate_rva(&[], 0).unwrap_err(), OmapError::EmptyTable);
    }

    #[test]
    fn test_omap_statistics() {
        let omap = simple_omap();
        let stats = OmapStatistics::compute(&omap);
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.unmapped_entries, 1);
        assert_eq!(stats.min_source_rva, Some(0x1000));
        assert_eq!(stats.max_source_rva, Some(0x3000));
        assert_eq!(stats.min_dest_rva, Some(0x5000));
        assert_eq!(stats.max_dest_rva, Some(0x7000));
    }

    #[test]
    fn test_compose_maps() {
        // Map1: 0x1000 → 0x5000
        // Map2: 0x5000 → 0xA000
        // Composed: 0x1000 → 0xA000
        let map1 = PdbOmap::from_entries(
            OmapKind::ToRemapped,
            vec![OmapEntry::new(0x1000, 0x5000)],
        );
        let map2 = PdbOmap::from_entries(
            OmapKind::FromRemapped,
            vec![OmapEntry::new(0x5000, 0xA000)],
        );
        let composed = map1.compose(&map2);
        assert_eq!(composed.translate_rva(0x1000).unwrap(), 0xA000);
    }

    #[test]
    fn test_from_entries_sorts() {
        // Supply entries out of order.
        let omap = PdbOmap::from_entries(
            OmapKind::ToRemapped,
            vec![OmapEntry::new(0x3000, 0x7000), OmapEntry::new(0x1000, 0x5000)],
        );
        assert_eq!(omap.entries()[0].rva, 0x1000);
        assert_eq!(omap.entries()[1].rva, 0x3000);
    }

    #[test]
    fn test_omap_error_display() {
        let e = OmapError::Unmapped(0x1234);
        assert!(e.to_string().contains("0x00001234"));
        let e2 = OmapError::BadAlignment;
        assert!(!e2.to_string().is_empty());
    }

    #[test]
    fn test_omap_kind_display() {
        assert_eq!(OmapKind::ToRemapped.to_string(), "OMAPTO");
    }
}
