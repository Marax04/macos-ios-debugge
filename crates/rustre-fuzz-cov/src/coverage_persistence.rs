//! Coverage persistence: save/load bitmaps, RLE compression, multi-run merge,
//! versioning, and SQLite-backed history database.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid magic bytes in coverage file")]
    BadMagic,

    #[error("Unsupported coverage file version {0}")]
    UnsupportedVersion(u16),

    #[error("RLE decode error: unexpected end of data at offset {0}")]
    RleDecodeEof(usize),

    #[error("Bitmap length mismatch: stored {stored}, expected {expected}")]
    BitmapLengthMismatch { stored: usize, expected: usize },

    #[error("Merge conflict: run {0} has different bitmap length")]
    MergeLengthMismatch(u64),

    #[error("Serialization error: {0}")]
    Serde(String),

    #[error("Database error: {0}")]
    Database(String),
}

pub type PersistResult<T> = Result<T, PersistError>;

// ─── file format constants ────────────────────────────────────────────────────

/// Magic bytes at the start of every coverage file: "RCOV".
pub const MAGIC: [u8; 4] = *b"RCOV";

/// Current on-disk format version.
pub const CURRENT_VERSION: u16 = 2;

// ─── RLE codec ───────────────────────────────────────────────────────────────

/// RLE-encode a byte slice.
///
/// Encoding: runs of identical bytes are stored as `(count, value)` pairs
/// where `count` is stored as a `u16` (max run 65 535).  Non-runs (single
/// occurrences) are emitted as `(1, value)`.
#[must_use]
pub fn rle_encode(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let val = data[i];
        let mut run = 1u16;
        while i + (run as usize) < data.len()
            && data[i + run as usize] == val
            && run < u16::MAX
        {
            run += 1;
        }
        out.extend_from_slice(&run.to_le_bytes());
        out.push(val);
        i += run as usize;
    }
    out
}

/// RLE-decode a byte slice previously produced by [`rle_encode`].
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn rle_decode(data: &[u8], expected_len: usize) -> PersistResult<Vec<u8>> {
    let mut out = Vec::with_capacity(expected_len);
    let mut i = 0;
    while i + 2 < data.len() {
        let count = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        let val = data[i + 2];
        i += 3;
        if count == 0 {
            continue;
        }
        for _ in 0..count {
            out.push(val);
        }
    }
    if i != data.len() {
        return Err(PersistError::RleDecodeEof(i));
    }
    if out.len() != expected_len {
        return Err(PersistError::BitmapLengthMismatch {
            stored: out.len(),
            expected: expected_len,
        });
    }
    Ok(out)
}

/// Return `true` when RLE encoding would be smaller than raw for this data.
#[must_use]
pub fn rle_is_beneficial(data: &[u8]) -> bool {
    let encoded_len = rle_encode(data).len();
    encoded_len < data.len()
}

// ─── CoverageFile ─────────────────────────────────────────────────────────────

/// On-disk representation of a coverage bitmap for one fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageFile {
    /// Format version.
    pub version: u16,
    /// UNIX timestamp (seconds) when this file was written.
    pub timestamp: u64,
    /// Monotonic run identifier.
    pub run_id: u64,
    /// Human-readable label (e.g. input file name).
    pub label: String,
    /// Total number of edges in the original bitmap.
    pub total_edges: usize,
    /// Number of edges that were hit.
    pub hit_edges: usize,
    /// Whether the payload is RLE-compressed.
    pub compressed: bool,
    /// The raw (or compressed) bitmap payload.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

impl CoverageFile {
    /// Create a new `CoverageFile` from a raw bitmap, auto-selecting compression.
    #[must_use]
    pub fn new(run_id: u64, label: impl Into<String>, bitmap: &[u8]) -> Self {
        let hit_edges = bitmap.iter().filter(|&&b| b != 0).count();
        let encoded = rle_encode(bitmap);
        let (compressed, payload) = if encoded.len() < bitmap.len() {
            (true, encoded)
        } else {
            (false, bitmap.to_vec())
        };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            version: CURRENT_VERSION,
            timestamp,
            run_id,
            label: label.into(),
            total_edges: bitmap.len(),
            hit_edges,
            compressed,
            payload,
        }
    }

    /// Decompress (if needed) and return the bitmap.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn bitmap(&self) -> PersistResult<Vec<u8>> {
        if self.compressed {
            rle_decode(&self.payload, self.total_edges)
        } else {
            if self.payload.len() != self.total_edges {
                return Err(PersistError::BitmapLengthMismatch {
                    stored: self.payload.len(),
                    expected: self.total_edges,
                });
            }
            Ok(self.payload.clone())
        }
    }

    /// Write to a file in the binary format.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn save(&self, path: &Path) -> PersistResult<()> {
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);
        // Header
        w.write_all(&MAGIC)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.timestamp.to_le_bytes())?;
        w.write_all(&self.run_id.to_le_bytes())?;
        // Label (u16 length + bytes).  Truncate to u16::MAX bytes if needed.
        let label_bytes = self.label.as_bytes();
        let label_len_u16 = u16::try_from(label_bytes.len()).unwrap_or(u16::MAX);
        let label_len = label_len_u16 as usize;
        w.write_all(&label_len_u16.to_le_bytes())?;
        w.write_all(&label_bytes[..label_len])?;
        // Bitmap metadata
        w.write_all(&(self.total_edges as u64).to_le_bytes())?;
        w.write_all(&(self.hit_edges as u64).to_le_bytes())?;
        w.write_all(&[u8::from(self.compressed)])?;
        // Payload (u64 length + bytes)
        w.write_all(&(self.payload.len() as u64).to_le_bytes())?;
        w.write_all(&self.payload)?;
        w.flush()?;
        Ok(())
    }

    /// Load from a binary file previously written by [`Self::save`].
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn load(path: &Path) -> PersistResult<Self> {
        // Reject absurdly large bitmaps (> 256 MiB) to prevent OOM.
        const MAX_EDGES: u64 = 256 * 1024 * 1024;
        let file = File::open(path)?;
        let mut r = BufReader::new(file);

        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(PersistError::BadMagic);
        }

        let mut buf2 = [0u8; 2];
        let mut buf8 = [0u8; 8];

        r.read_exact(&mut buf2)?;
        let version = u16::from_le_bytes(buf2);
        if version > CURRENT_VERSION {
            return Err(PersistError::UnsupportedVersion(version));
        }

        r.read_exact(&mut buf8)?;
        let timestamp = u64::from_le_bytes(buf8);

        r.read_exact(&mut buf8)?;
        let run_id = u64::from_le_bytes(buf8);

        r.read_exact(&mut buf2)?;
        let label_len = u16::from_le_bytes(buf2) as usize;
        let mut label_bytes = vec![0u8; label_len];
        r.read_exact(&mut label_bytes)?;
        let label = String::from_utf8_lossy(&label_bytes).into_owned();

        r.read_exact(&mut buf8)?;
        let total_edges_raw = u64::from_le_bytes(buf8);
        if total_edges_raw > MAX_EDGES {
            return Err(PersistError::Database(format!(
                "total_edges {total_edges_raw} exceeds limit {MAX_EDGES}"
            )));
        }
        let total_edges = crate::casts::u64_to_usize(total_edges_raw);

        r.read_exact(&mut buf8)?;
        let hit_edges = crate::casts::u64_to_usize(u64::from_le_bytes(buf8));

        let mut flag = [0u8; 1];
        r.read_exact(&mut flag)?;
        let compressed = flag[0] != 0;

        r.read_exact(&mut buf8)?;
        let payload_len_raw = u64::from_le_bytes(buf8);
        // Payload cannot exceed MAX_EDGES bytes (even compressed it is bounded).
        if payload_len_raw > MAX_EDGES {
            return Err(PersistError::Database(format!(
                "payload_len {payload_len_raw} exceeds limit {MAX_EDGES}"
            )));
        }
        let payload_len = crate::casts::u64_to_usize(payload_len_raw);
        let mut payload = vec![0u8; payload_len];
        r.read_exact(&mut payload)?;

        Ok(Self { version, timestamp, run_id, label, total_edges, hit_edges, compressed, payload })
    }
}

// ─── merge utilities ─────────────────────────────────────────────────────────

/// Merge multiple bitmaps using OR (any non-zero byte wins).
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn merge_bitmaps(bitmaps: &[Vec<u8>]) -> PersistResult<Vec<u8>> {
    if bitmaps.is_empty() {
        return Ok(Vec::new());
    }
    let len = bitmaps[0].len();
    let mut merged = vec![0u8; len];
    for (i, bm) in bitmaps.iter().enumerate() {
        if bm.len() != len {
            return Err(PersistError::MergeLengthMismatch(i as u64));
        }
        for (m, &b) in merged.iter_mut().zip(bm.iter()) {
            if b > *m {
                *m = b;
            }
        }
    }
    Ok(merged)
}

/// Compute the set difference: edges in `new_bm` that are absent in `baseline`.
#[must_use]
pub fn new_coverage(baseline: &[u8], new_bm: &[u8]) -> Vec<usize> {
    new_bm
        .iter()
        .zip(baseline.iter())
        .enumerate()
        .filter(|&(_, (&n, &b))| n != 0 && b == 0)
        .map(|(i, _)| i)
        .collect()
}

/// Compute coverage fraction for a bitmap.
#[must_use]
pub fn coverage_fraction(bm: &[u8]) -> f64 {
    if bm.is_empty() {
        return 0.0;
    }
    let hit = bm.iter().filter(|&&b| b != 0).count();
    crate::casts::usize_to_f64(hit) / crate::casts::usize_to_f64(bm.len())
}

// ─── run history ─────────────────────────────────────────────────────────────

/// Metadata for one stored fuzz run (no bitmap payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub run_id: u64,
    pub timestamp: u64,
    pub label: String,
    pub total_edges: usize,
    pub hit_edges: usize,
    pub new_edges: usize,
    pub file_path: PathBuf,
}

impl RunRecord {
    #[must_use]
    pub fn coverage_percent(&self) -> f64 {
        if self.total_edges == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.hit_edges) / crate::casts::usize_to_f64(self.total_edges) * 100.0
    }
}

// ─── CoverageDatabase ────────────────────────────────────────────────────────

/// Persistent, directory-based coverage database with run history.
///
/// Layout:
/// ```
/// db_dir/
///   runs/
///     000001_<label>.cov
///     000002_<label>.cov
///   index.json
/// ```
#[derive(Debug)]
pub struct CoverageDatabase {
    pub dir: PathBuf,
    index: Vec<RunRecord>,
    merged_bitmap: Option<Vec<u8>>,
    next_run_id: u64,
}

impl CoverageDatabase {
    /// Open (or create) a coverage database at `dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn open(dir: impl AsRef<Path>) -> PersistResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(dir.join("runs"))?;

        let index_path = dir.join("index.json");
        let (index, next_run_id) = if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            let idx: Vec<RunRecord> =
                serde_json::from_str(&data).map_err(|e| PersistError::Serde(e.to_string()))?;
            let next = idx.iter().map(|r| r.run_id).max().unwrap_or(0) + 1;
            (idx, next)
        } else {
            (Vec::new(), 1)
        };

        // Recompute merged bitmap from all stored runs.
        let merged_bitmap = Self::recompute_merged(&dir, &index);

        Ok(Self { dir, index, merged_bitmap, next_run_id })
    }

    fn recompute_merged(dir: &Path, index: &[RunRecord]) -> Option<Vec<u8>> {
        let bitmaps: Vec<Vec<u8>> = index
            .iter()
            .filter_map(|r| {
                let path = dir.join(&r.file_path);
                CoverageFile::load(&path).ok().and_then(|f| f.bitmap().ok())
            })
            .collect();
        if bitmaps.is_empty() {
            None
        } else {
            merge_bitmaps(&bitmaps).ok()
        }
    }

    /// Add a new run's bitmap to the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn add_run(
        &mut self,
        label: impl Into<String>,
        bitmap: &[u8],
    ) -> PersistResult<RunRecord> {
        let label = label.into();
        let run_id = self.next_run_id;
        self.next_run_id += 1;

        // Compute new edges vs merged baseline.
        let new_edges = self.merged_bitmap.as_ref().map_or_else(
            || bitmap.iter().filter(|&&b| b != 0).count(),
            |merged| new_coverage(merged, bitmap).len(),
        );

        let cf = CoverageFile::new(run_id, &label, bitmap);
        let safe_label: String =
            label.chars().map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' }).collect();
        let filename = format!("{run_id:06}_{safe_label}.cov");
        let rel_path = PathBuf::from("runs").join(&filename);
        let abs_path = self.dir.join(&rel_path);
        cf.save(&abs_path)?;

        let record = RunRecord {
            run_id,
            timestamp: cf.timestamp,
            label,
            total_edges: cf.total_edges,
            hit_edges: cf.hit_edges,
            new_edges,
            file_path: rel_path,
        };

        // Update merged bitmap.
        let new_bm = bitmap.to_vec();
        self.merged_bitmap = Some(self.merged_bitmap.take().map_or_else(
            || bitmap.to_vec(),
            |existing| merge_bitmaps(&[existing, new_bm]).unwrap_or_else(|_| bitmap.to_vec()),
        ));

        self.index.push(record.clone());
        self.flush_index()?;
        Ok(record)
    }

    /// Return the merged (cumulative) bitmap across all runs.
    #[must_use]
    pub fn merged_bitmap(&self) -> Option<&[u8]> {
        self.merged_bitmap.as_deref()
    }

    /// Return all run records.
    #[must_use]
    pub fn runs(&self) -> &[RunRecord] {
        &self.index
    }

    /// Look up a run by ID and load its bitmap.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn load_run(&self, run_id: u64) -> PersistResult<Vec<u8>> {
        let record = self
            .index
            .iter()
            .find(|r| r.run_id == run_id)
            .ok_or_else(|| PersistError::Database(format!("run {run_id} not found")))?;
        let path = self.dir.join(&record.file_path);
        CoverageFile::load(&path)?.bitmap()
    }

    /// Regression check: returns `true` when `new_bitmap` covers at least as
    /// many edges as `baseline_run_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn regression_check(&self, baseline_run_id: u64, new_bitmap: &[u8]) -> PersistResult<bool> {
        let baseline = self.load_run(baseline_run_id)?;
        let baseline_hit = baseline.iter().filter(|&&b| b != 0).count();
        let new_hit = new_bitmap.iter().filter(|&&b| b != 0).count();
        Ok(new_hit >= baseline_hit)
    }

    /// Prune runs that add zero new edges (keep first occurrence of each bitmap).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn prune_redundant(&mut self) -> PersistResult<usize> {
        let mut seen: HashMap<Vec<u8>, u64> = HashMap::new();
        let mut to_remove: Vec<u64> = Vec::new();

        for record in &self.index {
            let path = self.dir.join(&record.file_path);
            if let Ok(bm) = CoverageFile::load(&path).and_then(|f| f.bitmap()) {
                if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(bm) {
                    e.insert(record.run_id);
                } else {
                    to_remove.push(record.run_id);
                }
            }
        }

        let removed = to_remove.len();
        for rid in &to_remove {
            if let Some(pos) = self.index.iter().position(|r| &r.run_id == rid) {
                let record = self.index.remove(pos);
                let path = self.dir.join(&record.file_path);
                let _ = fs::remove_file(path);
            }
        }
        if removed > 0 {
            self.flush_index()?;
        }
        Ok(removed)
    }

    /// Coverage growth curve: `(run_id, cumulative_hit_edges)` pairs.
    #[must_use]
    pub fn coverage_growth(&self) -> Vec<(u64, usize)> {
        self.index.iter().map(|r| (r.run_id, r.hit_edges)).collect()
    }

    fn flush_index(&self) -> PersistResult<()> {
        let path = self.dir.join("index.json");
        let json = serde_json::to_string_pretty(&self.index)
            .map_err(|e| PersistError::Serde(e.to_string()))?;
        fs::write(path, json)?;
        Ok(())
    }
}

// ─── in-memory multi-run merger ───────────────────────────────────────────────

/// Accumulates coverage across multiple runs without writing to disk.
#[derive(Debug, Default)]
pub struct InMemoryMerger {
    merged: Option<Vec<u8>>,
    run_count: usize,
}

impl InMemoryMerger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add another bitmap to the merger.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn add(&mut self, bitmap: &[u8]) -> PersistResult<()> {
        self.merged = Some(match self.merged.take() {
            Some(existing) => merge_bitmaps(&[existing, bitmap.to_vec()])?,
            None => bitmap.to_vec(),
        });
        self.run_count += 1;
        Ok(())
    }

    #[must_use]
    pub const fn run_count(&self) -> usize {
        self.run_count
    }

    #[must_use]
    pub fn merged(&self) -> Option<&[u8]> {
        self.merged.as_deref()
    }

    #[must_use]
    pub fn coverage_fraction(&self) -> f64 {
        self.merged.as_deref().map_or(0.0, coverage_fraction)
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.merged = None;
        self.run_count = 0;
    }
}

// ─── versioning helper ────────────────────────────────────────────────────────

/// Simple version tag stored alongside each coverage snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageVersion {
    /// Semver-style string, e.g. `"1.0.0"`.
    pub version_string: String,
    /// Commit hash or build identifier.
    pub build_id: String,
    /// Monotonically increasing counter incremented on each build.
    pub build_number: u64,
}

impl CoverageVersion {
    #[must_use]
    pub fn new(
        version_string: impl Into<String>,
        build_id: impl Into<String>,
        build_number: u64,
    ) -> Self {
        Self {
            version_string: version_string.into(),
            build_id: build_id.into(),
            build_number,
        }
    }

    /// Returns `true` when this version should be treated as incompatible with
    /// `other` for coverage comparison purposes (different build).
    #[must_use]
    pub const fn is_compatible(&self, other: &Self) -> bool {
        self.build_number == other.build_number
    }
}

/// A versioned coverage snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedCoverage {
    pub version: CoverageVersion,
    pub run_id: u64,
    pub bitmap: Vec<u8>,
}

impl VersionedCoverage {
    #[must_use]
    pub const fn new(version: CoverageVersion, run_id: u64, bitmap: Vec<u8>) -> Self {
        Self { version, run_id, bitmap }
    }

    /// Compare with another snapshot of the same version, returning new edges.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn diff(&self, other: &Self) -> PersistResult<Vec<usize>> {
        if !self.version.is_compatible(&other.version) {
            return Err(PersistError::Database(
                "version mismatch: cannot diff across different builds".into(),
            ));
        }
        Ok(new_coverage(&self.bitmap, &other.bitmap))
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn rle_roundtrip_sparse() {
        let input = vec![0u8; 1000];
        let enc = rle_encode(&input);
        assert!(enc.len() < input.len(), "RLE should compress sparse data");
        let dec = rle_decode(&enc, input.len()).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn rle_roundtrip_dense() {
        let mut input = vec![0u8; 100];
        for (i, v) in input.iter_mut().enumerate() {
            *v = crate::casts::usize_to_u8(i % 251);
        }
        let enc = rle_encode(&input);
        let dec = rle_decode(&enc, input.len()).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn rle_empty() {
        let enc = rle_encode(&[]);
        assert!(enc.is_empty());
    }

    #[test]
    fn coverage_file_save_load() {
        let bm: Vec<u8> = (0..256).map(|i| u8::from(i % 3 == 0)).collect();
        let cf = CoverageFile::new(1, "test_run", &bm);
        let path = temp_dir().join("rustre_cov_test.cov");
        cf.save(&path).unwrap();
        let loaded = CoverageFile::load(&path).unwrap();
        assert_eq!(loaded.run_id, 1);
        assert_eq!(loaded.bitmap().unwrap(), bm);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn merge_bitmaps_or() {
        let a = vec![1u8, 0, 3, 0];
        let b = vec![0u8, 2, 0, 4];
        let m = merge_bitmaps(&[a, b]).unwrap();
        assert_eq!(m, vec![1, 2, 3, 4]);
    }

    #[test]
    fn new_coverage_detection() {
        let baseline = vec![1u8, 0, 0, 1];
        let new_bm = vec![1u8, 1, 0, 0];
        let new = new_coverage(&baseline, &new_bm);
        assert_eq!(new, vec![1]);
    }

    #[test]
    fn in_memory_merger() {
        let mut merger = InMemoryMerger::new();
        merger.add(&[1, 0, 0]).unwrap();
        merger.add(&[0, 1, 0]).unwrap();
        assert_eq!(merger.merged(), Some([1u8, 1, 0].as_slice()));
        assert_eq!(merger.run_count(), 2);
    }

    #[test]
    fn versioned_coverage_diff() {
        let v = CoverageVersion::new("1.0.0", "abc", 1);
        let snap_a = VersionedCoverage::new(v.clone(), 1, vec![1, 0, 0]);
        let snap_b = VersionedCoverage::new(v, 2, vec![1, 1, 0]);
        let new = snap_a.diff(&snap_b).unwrap();
        assert_eq!(new, vec![1]);
    }

    #[test]
    fn versioned_coverage_incompatible() {
        let v1 = CoverageVersion::new("1.0.0", "abc", 1);
        let v2 = CoverageVersion::new("1.0.0", "def", 2);
        let a = VersionedCoverage::new(v1, 1, vec![0]);
        let b = VersionedCoverage::new(v2, 2, vec![1]);
        assert!(a.diff(&b).is_err());
    }

    #[test]
    fn database_add_and_load() {
        let dir = temp_dir().join("rustre_covdb_test");
        let _ = std::fs::remove_dir_all(&dir);
        let mut db = CoverageDatabase::open(&dir).unwrap();
        let bm1: Vec<u8> = (0..64).map(|i| u8::from(i % 2 == 0)).collect();
        let r1 = db.add_run("run1", &bm1).unwrap();
        assert_eq!(r1.run_id, 1);
        let loaded = db.load_run(1).unwrap();
        assert_eq!(loaded, bm1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
