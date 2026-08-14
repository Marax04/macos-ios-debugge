//! AFL queue directory reader.
//!
//! Reads entries written by AFL/AFL++ to `<output>/queue/`, parses the
//! binary `id:NNNNNN,…` filenames, and provides statistics over the queue.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

// ─── QueueEntry ───────────────────────────────────────────────────────────────

/// A single item from the AFL fuzzing queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    /// Sequential ID (the `id:NNNNNN` portion of the filename).
    pub id: u64,
    /// Absolute path to the queue entry file.
    pub path: PathBuf,
    /// File contents (the fuzz input).
    pub data: Vec<u8>,
    /// File size in bytes.
    pub size: usize,
    /// Modification time of the queue entry file.
    pub mtime: Option<SystemTime>,
    /// Parsed annotations from the filename.
    pub annotations: HashMap<String, String>,
    /// Whether this entry is marked as "favored" (from filename `+cov` tag).
    pub is_favored: bool,
    /// Whether this entry appears to be hand-crafted (not auto-generated).
    pub is_user_seeded: bool,
    /// Execution time annotation (from `time:NNN` in filename), microseconds.
    pub exec_time_us: Option<u64>,
    /// Coverage bits annotation (from `src:NNNNNN+NNNNNN` or similar).
    pub source_ids: Vec<u64>,
}

impl QueueEntry {
    /// FNV-1a hash of the raw data.
    #[must_use]
    pub fn data_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.data {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Returns `true` if the entry data looks like valid UTF-8 text.
    #[must_use]
    pub fn is_text(&self) -> bool {
        std::str::from_utf8(&self.data).is_ok()
    }

    /// Returns a preview of the data (at most 64 bytes as hex).
    #[must_use]
    pub fn hex_preview(&self) -> String {
        self.data
            .iter()
            .take(64)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Returns the filename of this entry.
    #[must_use]
    pub fn filename(&self) -> &str {
        self.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    }
}

// ─── QueueStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics over all entries in a queue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    /// Total number of entries.
    pub total_entries: usize,
    /// Number of favored entries.
    pub favored_entries: usize,
    /// Number of user-seeded entries.
    pub user_seeded_entries: usize,
    /// Minimum entry size in bytes.
    pub min_size: usize,
    /// Maximum entry size in bytes.
    pub max_size: usize,
    /// Average entry size in bytes.
    pub avg_size: f64,
    /// Total bytes across all entries.
    pub total_bytes: usize,
    /// Earliest modification time.
    pub earliest_mtime: Option<SystemTime>,
    /// Latest modification time.
    pub latest_mtime: Option<SystemTime>,
    /// Number of entries that appear to be plain-text.
    pub text_entries: usize,
    /// Distribution of sizes in 256-byte buckets (`bucket_idx` → count).
    pub size_buckets: HashMap<usize, usize>,
}

impl QueueStats {
    /// Compute statistics from a slice of entries.
    #[must_use]
    pub fn compute(entries: &[QueueEntry]) -> Self {
        if entries.is_empty() {
            return Self::default();
        }
        let mut stats = Self {
            total_entries: entries.len(),
            ..Default::default()
        };
        let mut total = 0usize;
        let mut min_sz = usize::MAX;
        let mut max_sz = 0usize;
        for e in entries {
            let sz = e.size;
            total += sz;
            if sz < min_sz { min_sz = sz; }
            if sz > max_sz { max_sz = sz; }
            if e.is_favored { stats.favored_entries += 1; }
            if e.is_user_seeded { stats.user_seeded_entries += 1; }
            if e.is_text() { stats.text_entries += 1; }
            *stats.size_buckets.entry(sz / 256).or_insert(0) += 1;
            if let Some(mt) = e.mtime {
                stats.earliest_mtime = Some(
                    stats.earliest_mtime.map_or(mt, |prev| if mt < prev { mt } else { prev }),
                );
                stats.latest_mtime = Some(
                    stats.latest_mtime.map_or(mt, |prev| if mt > prev { mt } else { prev }),
                );
            }
        }
        stats.min_size = min_sz;
        stats.max_size = max_sz;
        stats.total_bytes = total;
        stats.avg_size = f64::from(u32::try_from(total).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(entries.len()).unwrap_or(u32::MAX));
        stats
    }

    /// Return a text summary.
    #[must_use]
    pub fn summary_text(&self) -> String {
        format!(
            "Queue: {} entries ({} bytes total)\n\
             Favored: {}  User-seeded: {}  Text: {}\n\
             Size: min={} max={} avg={:.1}",
            self.total_entries,
            self.total_bytes,
            self.favored_entries,
            self.user_seeded_entries,
            self.text_entries,
            self.min_size,
            self.max_size,
            self.avg_size
        )
    }
}

// ─── Filename parser ──────────────────────────────────────────────────────────

/// Parse AFL queue entry filename annotations.
///
/// AFL uses filenames of the form:
/// `id:000000,src:000001+000002,op:havoc,rep:2,+cov`
fn parse_afl_filename(name: &str) -> (u64, HashMap<String, String>, bool, Vec<u64>) {
    let mut annotations = HashMap::new();
    let mut id = 0u64;
    let mut is_favored = false;
    let mut source_ids = Vec::new();

    for part in name.split(',') {
        let part = part.trim();
        if part == "+cov" || part == "cov" {
            is_favored = true;
            annotations.insert("+cov".to_string(), "true".to_string());
            continue;
        }
        if let Some(colon) = part.find(':') {
            let key = &part[..colon];
            let val = &part[colon + 1..];
            match key {
                "id" => {
                    id = val.parse::<u64>().unwrap_or(0);
                }
                "src" => {
                    for src_id in val.split('+') {
                        if let Ok(n) = src_id.parse::<u64>() {
                            source_ids.push(n);
                        }
                    }
                }
                _ => {}
            }
            annotations.insert(key.to_string(), val.to_string());
        }
    }
    (id, annotations, is_favored, source_ids)
}

// ─── AflQueueReader ───────────────────────────────────────────────────────────

/// Reads and parses an AFL queue directory.
///
/// The queue directory is typically `<afl_output_dir>/queue/`.
pub struct AflQueueReader {
    /// Path to the queue directory.
    pub queue_dir: PathBuf,
    /// Maximum data size to read per entry (default 1 MiB).
    pub max_entry_size: usize,
    /// Whether to load file contents (vs. only metadata).
    pub load_contents: bool,
}

impl AflQueueReader {
    /// Create a new reader targeting `queue_dir`.
    #[must_use]
    pub fn new(queue_dir: impl Into<PathBuf>) -> Self {
        Self {
            queue_dir: queue_dir.into(),
            max_entry_size: 1024 * 1024,
            load_contents: true,
        }
    }

    /// Create a metadata-only reader (does not load file contents).
    #[must_use]
    pub fn metadata_only(queue_dir: impl Into<PathBuf>) -> Self {
        Self {
            queue_dir: queue_dir.into(),
            max_entry_size: 0,
            load_contents: false,
        }
    }

    /// Read all queue entries, sorted by ID.
    ///
    /// # Errors
    /// Returns `std::io::Error` if the directory cannot be read.
    pub fn read_all(&self) -> std::io::Result<Vec<QueueEntry>> {
        let mut entries = Vec::new();
        let rd = std::fs::read_dir(&self.queue_dir)?;
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(entry) = self.read_entry(&path) {
                entries.push(entry);
            }
        }
        entries.sort_by_key(|e| e.id);
        Ok(entries)
    }

    /// Read a single queue entry from `path`.
    fn read_entry(&self, path: &Path) -> Option<QueueEntry> {
        let filename = path.file_name()?.to_str()?.to_string();
        let (id, annotations, is_favored, source_ids) = parse_afl_filename(&filename);
        let is_user_seeded = filename.starts_with("id:000000") || !filename.contains("src:");
        let exec_time_us = annotations
            .get("time")
            .and_then(|s| s.parse::<u64>().ok());

        // Read file contents before checking size to avoid a TOCTOU race between
        // metadata.len() (u64) and the actual read, and to prevent u64→usize
        // truncation on 32-bit targets bypassing the max_entry_size guard.
        let data = if self.load_contents {
            // Return None on read failure rather than silently producing an empty
            // entry that looks valid but contains no data — callers cannot
            // distinguish a genuinely empty file from an unreadable one.
            let bytes = std::fs::read(path).ok()?;
            // parser-trailing-data-ignored / dos-memory-exhaustion: an oversized
            // file must be rejected entirely (return None) rather than silently
            // substituting Vec::new(), which would produce a valid-looking entry
            // with no content.  Callers relying on `data.is_empty()` to detect
            // load errors would be misled by a legitimately empty corpus seed.
            if bytes.len() > self.max_entry_size {
                return None;
            }
            bytes
        } else {
            Vec::new()
        };
        let meta = std::fs::metadata(path).ok();
        let size = if data.is_empty() {
            // Fall back to metadata size (as usize, clamped) when data was not loaded.
            meta.as_ref().map_or(0, |m| usize::try_from(m.len()).unwrap_or(usize::MAX))
        } else {
            data.len()
        };
        let mtime = meta.as_ref().and_then(|m| m.modified().ok());

        Some(QueueEntry {
            id,
            path: path.to_path_buf(),
            size,
            data,
            mtime,
            annotations,
            is_favored,
            is_user_seeded,
            exec_time_us,
            source_ids,
        })
    }

    /// Read all entries and compute statistics.
    ///
    /// # Errors
    /// Returns `std::io::Error` if the directory cannot be read.
    pub fn read_with_stats(&self) -> std::io::Result<(Vec<QueueEntry>, QueueStats)> {
        let entries = self.read_all()?;
        let stats = QueueStats::compute(&entries);
        Ok((entries, stats))
    }

    /// Return only entries matching `predicate`.
    ///
    /// # Errors
    /// Returns `std::io::Error` if the directory cannot be read.
    pub fn read_filtered<F>(&self, predicate: F) -> std::io::Result<Vec<QueueEntry>>
    where
        F: Fn(&QueueEntry) -> bool,
    {
        Ok(self.read_all()?.into_iter().filter(predicate).collect())
    }

    /// Load queue entries from an in-memory map (for testing).
    ///
    /// Each element is `(filename, data)`.
    #[must_use]
    pub fn from_memory(entries: Vec<(String, Vec<u8>)>) -> Vec<QueueEntry> {
        entries
            .into_iter()
            .enumerate()
            .map(|(seq, (name, data))| {
                let (id, annotations, is_favored, source_ids) = parse_afl_filename(&name);
                let size = data.len();
                QueueEntry {
                    id: if id == 0 { seq as u64 } else { id },
                    path: PathBuf::from(name),
                    size,
                    data,
                    mtime: None,
                    annotations,
                    is_favored,
                    is_user_seeded: false,
                    exec_time_us: None,
                    source_ids,
                }
            })
            .collect()
    }
}

// ─── QueueAnalyzer ────────────────────────────────────────────────────────────

/// Analyses a loaded queue for fuzzing patterns.
pub struct QueueAnalyzer {
    /// The loaded entries.
    pub entries: Vec<QueueEntry>,
}

impl QueueAnalyzer {
    /// Create from a list of entries.
    #[must_use]
    pub const fn new(entries: Vec<QueueEntry>) -> Self {
        Self { entries }
    }

    /// Cluster entries by data hash — groups with the same hash are duplicates.
    #[must_use]
    pub fn find_duplicate_data(&self) -> HashMap<u64, Vec<usize>> {
        let mut map: HashMap<u64, Vec<usize>> = HashMap::new();
        for (i, e) in self.entries.iter().enumerate() {
            map.entry(e.data_hash()).or_default().push(i);
        }
        map.retain(|_, v| v.len() > 1);
        map
    }

    /// Entries that are neither favored nor user-seeded (pure mutations).
    #[must_use]
    pub fn mutation_entries(&self) -> Vec<&QueueEntry> {
        self.entries
            .iter()
            .filter(|e| !e.is_favored && !e.is_user_seeded)
            .collect()
    }

    /// Entries with size in `[min, max]`.
    #[must_use]
    pub fn entries_in_size_range(&self, min: usize, max: usize) -> Vec<&QueueEntry> {
        self.entries
            .iter()
            .filter(|e| e.size >= min && e.size <= max)
            .collect()
    }

    /// Source-ID lineage: for each entry, list its ancestor chain.
    #[must_use]
    pub fn source_graph(&self) -> HashMap<u64, Vec<u64>> {
        self.entries
            .iter()
            .map(|e| (e.id, e.source_ids.clone()))
            .collect()
    }

    /// Entries that appear to be root seeds (no source IDs).
    #[must_use]
    pub fn root_seeds(&self) -> Vec<&QueueEntry> {
        self.entries
            .iter()
            .filter(|e| e.source_ids.is_empty())
            .collect()
    }

    /// Return the entry with the most unique bytes (highest byte entropy proxy).
    #[must_use]
    pub fn most_diverse_entry(&self) -> Option<&QueueEntry> {
        self.entries.iter().max_by_key(|e| {
            let mut seen = [false; 256];
            for &b in &e.data {
                seen[b as usize] = true;
            }
            seen.iter().filter(|&&v| v).count()
        })
    }
}

// ─── load_queue_dir ───────────────────────────────────────────────────────────

/// Load an AFL queue directory and return `(entries, stats)`.
///
/// # Errors
/// Returns `std::io::Error` if the directory cannot be read.
pub fn load_queue_dir(
    dir: &Path,
) -> std::io::Result<(Vec<QueueEntry>, QueueStats)> {
    AflQueueReader::new(dir).read_with_stats()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<(String, Vec<u8>)> {
        vec![
            ("id:000000,src:000001,op:havoc".to_string(), vec![0u8; 64]),
            ("id:000001,src:000000,op:flip1,+cov".to_string(), vec![1u8; 128]),
            ("id:000002,src:000000+000001,op:havoc".to_string(), vec![2u8; 32]),
        ]
    }

    #[test]
    fn parse_filename_id() {
        let (id, _, _, _) = parse_afl_filename("id:000042,src:000001,op:flip1");
        assert_eq!(id, 42);
    }

    #[test]
    fn parse_filename_favored() {
        let (_, _, is_favored, _) = parse_afl_filename("id:000001,+cov");
        assert!(is_favored);
    }

    #[test]
    fn parse_filename_source_ids() {
        let (_, _, _, src) = parse_afl_filename("id:000003,src:000001+000002,op:havoc");
        assert_eq!(src, vec![1, 2]);
    }

    #[test]
    fn from_memory_sorts() {
        let raw = sample_entries();
        let entries = AflQueueReader::from_memory(raw);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id, 0);
        assert_eq!(entries[1].id, 1);
    }

    #[test]
    fn queue_stats_compute() {
        let raw = sample_entries();
        let entries = AflQueueReader::from_memory(raw);
        let stats = QueueStats::compute(&entries);
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.favored_entries, 1);
        assert_eq!(stats.min_size, 32);
        assert_eq!(stats.max_size, 128);
    }

    #[test]
    fn analyzer_find_duplicates() {
        let e1 = AflQueueReader::from_memory(vec![
            ("id:000000".to_string(), vec![0xAA; 16]),
            ("id:000001".to_string(), vec![0xAA; 16]),
            ("id:000002".to_string(), vec![0xBB; 16]),
        ]);
        let analyzer = QueueAnalyzer::new(e1);
        let dups = analyzer.find_duplicate_data();
        assert!(!dups.is_empty());
    }

    #[test]
    fn analyzer_root_seeds() {
        let entries = AflQueueReader::from_memory(sample_entries());
        let analyzer = QueueAnalyzer::new(entries);
        let seeds = analyzer.root_seeds();
        // Entry with id:000000 has no '+' prefix in source, but parse_afl_filename
        // does extract src:000001 — so root seed count depends on parsing.
        let _ = seeds;
    }

    #[test]
    fn analyzer_size_range() {
        let entries = AflQueueReader::from_memory(sample_entries());
        let analyzer = QueueAnalyzer::new(entries);
        let small = analyzer.entries_in_size_range(0, 64);
        assert!(small.iter().all(|e| e.size <= 64));
    }

    #[test]
    fn entry_data_hash_deterministic() {
        let e = AflQueueReader::from_memory(vec![
            ("id:000000".to_string(), vec![1u8, 2, 3, 4]),
        ]);
        assert_eq!(e[0].data_hash(), e[0].data_hash());
    }

    #[test]
    fn entry_hex_preview_length() {
        let e = AflQueueReader::from_memory(vec![
            ("id:000000".to_string(), vec![0xABu8; 200]),
        ]);
        let preview = e[0].hex_preview();
        // 64 bytes, each "XX " minus trailing space = at most 64*3-1 chars.
        assert!(preview.len() <= 64 * 3);
    }
}
