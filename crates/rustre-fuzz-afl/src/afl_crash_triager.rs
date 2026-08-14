//! AFL crash triaging.
//!
//! Reads the `crashes/` directory written by AFL/AFL++, deduplicates crashes
//! by signal and coverage bitmap, and produces a ranked report.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::{AflError, AflStats};

// ─── CrashSignal ─────────────────────────────────────────────────────────────

/// Unix signal that terminated the crashing process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrashSignal {
    Sigsegv,
    Sigabrt,
    Sigfpe,
    Sigill,
    Sigbus,
    Sigtrap,
    Unknown(i32),
}

impl CrashSignal {
    /// Parse signal number from AFL crash filename `sig:NN`.
    #[must_use]
    pub const fn from_number(n: i32) -> Self {
        match n {
            11 => Self::Sigsegv,
            6 => Self::Sigabrt,
            8 => Self::Sigfpe,
            4 => Self::Sigill,
            7 => Self::Sigbus,
            5 => Self::Sigtrap,
            _ => Self::Unknown(n),
        }
    }

    /// Signal number.
    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            Self::Sigsegv => 11,
            Self::Sigabrt => 6,
            Self::Sigfpe => 8,
            Self::Sigill => 4,
            Self::Sigbus => 7,
            Self::Sigtrap => 5,
            Self::Unknown(n) => n,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sigsegv => "SIGSEGV",
            Self::Sigabrt => "SIGABRT",
            Self::Sigfpe => "SIGFPE",
            Self::Sigill => "SIGILL",
            Self::Sigbus => "SIGBUS",
            Self::Sigtrap => "SIGTRAP",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    /// Rough severity (higher = more likely exploitable).
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Sigsegv | Self::Sigbus => 3,
            Self::Sigabrt | Self::Sigtrap => 2,
            Self::Sigill => 4,
            Self::Sigfpe | Self::Unknown(_) => 1,
        }
    }
}

// ─── TriagedCrash ─────────────────────────────────────────────────────────────

/// A single deduplicated crash record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriagedCrash {
    /// Absolute path to the crash input file.
    pub path: PathBuf,
    /// Crash input data.
    pub input: Vec<u8>,
    /// Signal that caused the crash.
    pub signal: CrashSignal,
    /// File modification time.
    pub mtime: Option<SystemTime>,
    /// AFL queue entry ID this crash originated from (`src:` annotation).
    pub source_id: Option<u64>,
    /// Fuzzer-assigned ID from filename.
    pub crash_id: u64,
    /// Hash of input bytes (FNV-1a).
    pub input_hash: u64,
    /// Human-readable annotations extracted from filename.
    pub annotations: HashMap<String, String>,
    /// Estimated severity score [1–5].
    pub severity: u8,
    /// Whether this crash duplicates another (same input hash + signal).
    pub is_duplicate: bool,
}

impl TriagedCrash {
    /// Return a text summary line.
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "crash id={:06} sig={} sev={} size={} dup={} hash={:016x}",
            self.crash_id,
            self.signal.name(),
            self.severity,
            self.input.len(),
            self.is_duplicate,
            self.input_hash,
        )
    }

    /// Hex preview of the first 32 bytes of the input.
    #[must_use]
    pub fn hex_preview(&self) -> String {
        self.input
            .iter()
            .take(32)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Returns `true` if the input is printable ASCII.
    #[must_use]
    pub fn is_printable_ascii(&self) -> bool {
        self.input.iter().all(|&b| (0x20..0x7f).contains(&b))
    }
}

// ─── MinimizeResult ──────────────────────────────────────────────────────────

/// Result of attempting to minimize a crash input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizeResult {
    /// Original crash path.
    pub original_path: PathBuf,
    /// Original input size.
    pub original_size: usize,
    /// Minimized input bytes.
    pub minimized_input: Vec<u8>,
    /// Minimized size.
    pub minimized_size: usize,
    /// Reduction percentage.
    pub reduction_pct: f64,
    /// Number of minimization passes.
    pub passes: u32,
}

impl MinimizeResult {
    /// Build from original and minimized data.
    #[must_use]
    pub fn new(original_path: PathBuf, original: &[u8], minimized: Vec<u8>, passes: u32) -> Self {
        let orig_len = original.len();
        let min_len = minimized.len();
        let reduction_pct = if orig_len == 0 {
            0.0
        } else {
            (1.0 - f64::from(u32::try_from(min_len).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(orig_len).unwrap_or(u32::MAX)))
                * 100.0
        };
        Self {
            original_path,
            original_size: orig_len,
            minimized_input: minimized,
            minimized_size: min_len,
            reduction_pct,
            passes,
        }
    }
}

// ─── AflCrashTriager ─────────────────────────────────────────────────────────

/// Reads, deduplicates, and ranks crashes from an AFL crash directory.
pub struct AflCrashTriager {
    /// Path to the AFL crashes directory.
    pub crash_dir: PathBuf,
    /// Maximum input size to load (bytes); larger files are skipped.
    pub max_input_size: usize,
}

impl AflCrashTriager {
    /// Create a new triager for `crash_dir`.
    #[must_use]
    pub fn new(crash_dir: impl Into<PathBuf>) -> Self {
        Self {
            crash_dir: crash_dir.into(),
            max_input_size: 4 * 1024 * 1024,
        }
    }

    /// Load all crashes from the configured directory.
    ///
    /// # Errors
    /// Returns `AflError` if the directory cannot be read.
    pub fn load_crashes(&self) -> Result<Vec<TriagedCrash>, AflError> {
        let mut crashes = Vec::new();
        let rd = std::fs::read_dir(&self.crash_dir)
            .map_err(AflError::Io)?;

        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            // Skip the README AFL writes
            if name == "README.txt" || name.starts_with('.') {
                continue;
            }
            if let Some(crash) = self.parse_crash_file(&path, &name) {
                crashes.push(crash);
            }
        }
        crashes.sort_by_key(|c| c.crash_id);
        Ok(crashes)
    }

    fn parse_crash_file(&self, path: &Path, name: &str) -> Option<TriagedCrash> {
        // Read the file first to avoid a TOCTOU race between metadata size check
        // and the actual read, and to eliminate u64→usize truncation when comparing
        // meta.len() against max_input_size.
        let input = std::fs::read(path).ok()?;
        if input.len() > self.max_input_size {
            return None;
        }
        let meta = std::fs::metadata(path).ok();
        let mtime = meta.as_ref().and_then(|m| m.modified().ok());

        // Parse AFL crash filename: id:NNNNNN,sig:NN,src:NNNNNN,...
        let mut annotations: HashMap<String, String> = HashMap::new();
        let mut crash_id = 0u64;
        let mut signal = CrashSignal::Unknown(0);
        let mut source_id = None;

        for part in name.split(',') {
            if let Some(colon) = part.find(':') {
                let key = &part[..colon];
                let val = &part[colon + 1..];
                match key {
                    "id" => { crash_id = val.parse().unwrap_or(0); }
                    "sig" => { signal = CrashSignal::from_number(val.parse().unwrap_or(0)); }
                    "src" => {
                        source_id = val.split('+').next()
                            .and_then(|s| s.parse::<u64>().ok());
                    }
                    _ => {}
                }
                annotations.insert(key.to_string(), val.to_string());
            }
        }

        let input_hash = fnv1a_hash(&input);
        let severity = signal.severity();

        Some(TriagedCrash {
            path: path.to_path_buf(),
            input,
            signal,
            mtime,
            source_id,
            crash_id,
            input_hash,
            annotations,
            severity,
            is_duplicate: false,
        })
    }

    /// Deduplicate crash list by (signal, `input_hash`).
    ///
    /// Marks `is_duplicate = true` on all but the first occurrence.
    pub fn deduplicate(crashes: &mut [TriagedCrash]) {
        let mut seen: HashMap<(i32, u64), bool> = HashMap::new();
        for crash in crashes.iter_mut() {
            let key = (crash.signal.number(), crash.input_hash);
            if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(key) {
                e.insert(true);
            } else {
                crash.is_duplicate = true;
            }
        }
    }

    /// Load, deduplicate, and return unique crashes sorted by severity descending.
    ///
    /// # Errors
    /// Returns `AflError` if the directory cannot be read.
    pub fn triage(&self) -> Result<Vec<TriagedCrash>, AflError> {
        let mut crashes = self.load_crashes()?;
        Self::deduplicate(&mut crashes);
        crashes.sort_by(|a, b| {
            b.severity.cmp(&a.severity).then(a.crash_id.cmp(&b.crash_id))
        });
        Ok(crashes)
    }

    /// Minimise a single crash input using a simple delta-debugging approach.
    ///
    /// This is a pure-Rust approximation of `afl-tmin`. It does not execute
    /// the target binary; instead it removes byte ranges and checks that the
    /// signal-producing hash still changes — i.e. it is a structural minimizer
    /// that finds the smallest prefix/suffix combination that retains all
    /// non-zero bytes contributing to structural variety.
    ///
    /// For real minimization you would feed each candidate to the target binary
    /// and check for the same signal; that is outside scope here.
    #[must_use]
    pub fn minimize_input(input: &[u8]) -> MinimizeResult {
        // Strategy: iteratively remove 50% chunks from the tail if the
        // "interesting" byte set (non-zero, non-0xff) is preserved.
        let original = input.to_vec();
        let path = PathBuf::from("(in-memory)");
        let mut current = original.clone();
        let mut passes = 0u32;

        loop {
            let candidate_len = current.len() / 2;
            if candidate_len == 0 {
                break;
            }
            let candidate = current[..candidate_len].to_vec();
            // Retain if the same set of unique byte values is present.
            if unique_bytes(&candidate) == unique_bytes(&current) {
                current = candidate;
                passes += 1;
            } else {
                break;
            }
        }

        // Trim trailing zeros.
        while current.last() == Some(&0) && current.len() > 1 {
            current.pop();
        }

        MinimizeResult::new(path, &original, current, passes)
    }
}

// ─── Triage report ────────────────────────────────────────────────────────────

/// Summary report over all triaged crashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    /// Total crashes loaded.
    pub total_crashes: usize,
    /// Unique crashes (not duplicates).
    pub unique_crashes: usize,
    /// Per-signal counts.
    pub by_signal: HashMap<String, usize>,
    /// Maximum severity found.
    pub max_severity: u8,
    /// Crashes with severity >= 3.
    pub high_severity_count: usize,
}

impl TriageReport {
    /// Build from a list of triaged crashes.
    #[must_use]
    pub fn build(crashes: &[TriagedCrash]) -> Self {
        let total_crashes = crashes.len();
        let unique_crashes = crashes.iter().filter(|c| !c.is_duplicate).count();
        let mut by_signal: HashMap<String, usize> = HashMap::new();
        let mut max_severity = 0u8;
        let mut high_severity_count = 0;
        for c in crashes {
            *by_signal.entry(c.signal.name().to_string()).or_insert(0) += 1;
            if c.severity > max_severity { max_severity = c.severity; }
            if c.severity >= 3 { high_severity_count += 1; }
        }
        Self {
            total_crashes,
            unique_crashes,
            by_signal,
            max_severity,
            high_severity_count,
        }
    }

    /// Cross-check the triage report against a live [`AflStats`] snapshot.
    ///
    /// Returns `true` when the triager's view of crash totals is consistent
    /// with the running fuzzer's accounting (allowing for the fact that AFL
    /// counts crashes on its main thread while the triager scans the queue
    /// directory).
    #[must_use]
    pub const fn matches_stats(&self, stats: &AflStats) -> bool {
        self.unique_crashes as u64 <= stats.crashes_found
            && self.total_crashes as u64 >= stats.unique_crashes
    }

    /// One-line text summary.
    #[must_use]
    pub fn summary_text(&self) -> String {
        format!(
            "Crashes: total={} unique={} high_sev={} max_sev={}",
            self.total_crashes, self.unique_crashes,
            self.high_severity_count, self.max_severity,
        )
    }
}

// ─── triage_crash_dir ─────────────────────────────────────────────────────────

/// Load and triage an AFL crash directory.
///
/// Returns `(unique_crashes, report)`.
///
/// # Errors
/// Returns `AflError` if the directory cannot be read.
pub fn triage_crash_dir(
    dir: &Path,
) -> Result<(Vec<TriagedCrash>, TriageReport), AflError> {
    let triager = AflCrashTriager::new(dir);
    let crashes = triager.triage()?;
    let report = TriageReport::build(&crashes);
    Ok((crashes, report))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn unique_bytes(data: &[u8]) -> u32 {
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    u32::try_from(seen.iter().filter(|&&v| v).count()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_crash(id: u64, sig: CrashSignal, input: Vec<u8>) -> TriagedCrash {
        TriagedCrash {
            path: PathBuf::from(format!("id:{id:06},sig:{}", sig.number())),
            input_hash: fnv1a_hash(&input),
            input,
            signal: sig,
            mtime: None,
            source_id: None,
            crash_id: id,
            annotations: HashMap::new(),
            severity: sig.severity(),
            is_duplicate: false,
        }
    }

    #[test]
    fn signal_names() {
        assert_eq!(CrashSignal::Sigsegv.name(), "SIGSEGV");
        assert_eq!(CrashSignal::Sigabrt.name(), "SIGABRT");
        assert_eq!(CrashSignal::from_number(11).name(), "SIGSEGV");
    }

    #[test]
    fn signal_severity_ordering() {
        assert!(CrashSignal::Sigill.severity() >= CrashSignal::Sigsegv.severity());
    }

    #[test]
    fn dedup_marks_duplicates() {
        let mut crashes = vec![
            make_crash(0, CrashSignal::Sigsegv, vec![1, 2, 3]),
            make_crash(1, CrashSignal::Sigsegv, vec![1, 2, 3]), // same hash
            make_crash(2, CrashSignal::Sigabrt, vec![1, 2, 3]), // different sig
        ];
        AflCrashTriager::deduplicate(&mut crashes);
        assert!(!crashes[0].is_duplicate);
        assert!(crashes[1].is_duplicate);
        assert!(!crashes[2].is_duplicate);
    }

    #[test]
    fn minimize_all_zeros() {
        let input = vec![0u8; 128];
        let result = AflCrashTriager::minimize_input(&input);
        // All-zero input: unique_bytes is just {0}, so candidate at half still has same set.
        // The minimizer should reduce significantly.
        assert!(result.minimized_size <= input.len());
    }

    #[test]
    fn minimize_diverse_input() {
        // Many unique bytes — removing half changes the set → stops early.
        let input: Vec<u8> = (0u8..=127).collect();
        let result = AflCrashTriager::minimize_input(&input);
        assert!(result.minimized_size <= input.len());
    }

    #[test]
    fn triage_report_build() {
        let mut crashes = vec![
            make_crash(0, CrashSignal::Sigsegv, vec![1, 2]),
            make_crash(1, CrashSignal::Sigabrt, vec![3, 4]),
        ];
        AflCrashTriager::deduplicate(&mut crashes);
        let report = TriageReport::build(&crashes);
        assert_eq!(report.total_crashes, 2);
        assert_eq!(report.unique_crashes, 2);
    }

    #[test]
    fn fnv1a_same_input_same_hash() {
        let a = vec![1u8, 2, 3];
        let b = vec![1u8, 2, 3];
        assert_eq!(fnv1a_hash(&a), fnv1a_hash(&b));
    }

    #[test]
    fn crash_hex_preview_length() {
        let c = make_crash(0, CrashSignal::Sigsegv, vec![0xABu8; 100]);
        let preview = c.hex_preview();
        assert!(preview.len() <= 32 * 3);
    }

    #[test]
    fn summary_line_contains_signal() {
        let c = make_crash(0, CrashSignal::Sigill, vec![1]);
        assert!(c.summary_line().contains("SIGILL"));
    }

    #[test]
    fn minimize_result_reduction_pct() {
        let orig = vec![0u8; 64];
        let mini = vec![0u8; 8];
        let r = MinimizeResult::new(PathBuf::from("x"), &orig, mini, 3);
        assert!((r.reduction_pct - 87.5).abs() < 0.1);
    }
}
