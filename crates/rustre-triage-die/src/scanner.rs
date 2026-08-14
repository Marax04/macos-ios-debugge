//! High-level DIE-style scanner combining [`SignatureDb`], [`DieDetector`],
//! and heuristic PE/ELF analysis into a single easy-to-use API.
//!
//! **Layer guide** — three scanner implementations exist in this crate, each at
//! a different abstraction level:
//!
//! | Module | Type | Backend |
//! |--------|------|---------|
//! | `scanner` (this file) | [`DieScanner`] | `SignatureDb` (Matcher DSL) + legacy `DieDetector` |
//! | `die_scanner` | `die_scanner::DieScanner` | `DieRuleEngine` with EP-offset and platform flags |
//! | `lib` | `crate::DieScanner` | YAML rule DSL with full PE-condition awareness |
//!
//! Use this scanner (`scanner::DieScanner`) for the highest-coverage, production
//! scanning path.

use std::io::Read as _;
use std::path::Path;

use crate::{
    DetectKind, Detection, DieDatabase, DieDetector, DieError, DieResult, signature_db::SignatureDb,
};
use rustre_triage::FileKind;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// ScanOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Tunable knobs for [`DieScanner`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Minimum confidence (0–100) for a detection to appear in the result.
    pub min_confidence: u8,
    /// If `true`, run the legacy [`DieDetector`] (section-name based) in
    /// addition to the [`SignatureDb`] scanner.
    pub include_legacy: bool,
    /// If `true`, compute per-section entropy and emit an anomaly detection
    /// for sections with entropy > `high_entropy_threshold`.
    pub entropy_scan: bool,
    /// Entropy threshold above which a section is flagged as high-entropy.
    pub high_entropy_threshold: f64,
    /// Maximum file size in bytes that will be scanned in full. Larger files
    /// are still scanned but only the first `max_scan_bytes` bytes are used
    /// for string/byte-pattern matching.
    pub max_scan_bytes: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            min_confidence: 50,
            include_legacy: true,
            entropy_scan: true,
            high_entropy_threshold: 7.2,
            max_scan_bytes: 64 * 1024 * 1024, // 64 MiB
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanContext
// ─────────────────────────────────────────────────────────────────────────────

/// Internal context built once per scan.
struct ScanContext<'a> {
    scan_window: &'a [u8],
    file_kind: FileKind,
}

impl<'a> ScanContext<'a> {
    fn new(data: &'a [u8], opts: &ScanOptions) -> Self {
        let scan_window = if data.len() > opts.max_scan_bytes {
            &data[..opts.max_scan_bytes]
        } else {
            data
        };
        let file_kind = rustre_triage::detect_file_kind(data);
        Self {
            scan_window,
            file_kind,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DieScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Production-quality DIE-style scanner.
///
/// # Examples
/// ```rust
/// use rustre_triage_die::scanner::DieScanner;
///
/// let scanner = DieScanner::with_defaults();
/// let data = b"\x4D\x5Arustc 1.76 binary section UPX0 padding";
/// let result = scanner.scan_bytes(data).unwrap();
/// println!("{result}");
/// ```
pub struct DieScanner {
    sig_db: SignatureDb,
    legacy: DieDetector,
    opts: ScanOptions,
}

impl std::fmt::Debug for DieScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DieScanner(sigs={}, legacy_rules={}, opts={:?})",
            self.sig_db.len(),
            self.legacy_rule_count(),
            self.opts,
        )
    }
}

impl DieScanner {
    /// Create a scanner with the provided databases and options.
    #[must_use]
    pub const fn new(sig_db: SignatureDb, legacy: DieDetector, opts: ScanOptions) -> Self {
        Self {
            sig_db,
            legacy,
            opts,
        }
    }

    /// Create a scanner pre-loaded with all default signatures and rules.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(
            SignatureDb::with_defaults(),
            DieDetector::with_defaults(),
            ScanOptions::default(),
        )
    }

    /// Create with custom options but default signatures.
    #[must_use]
    pub fn with_options(opts: ScanOptions) -> Self {
        Self::new(
            SignatureDb::with_defaults(),
            DieDetector::with_defaults(),
            opts,
        )
    }

    /// Return the number of signatures in the [`SignatureDb`].
    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.sig_db.len()
    }

    fn legacy_rule_count(&self) -> usize {
        // DieDetector does not expose a public count — use Debug string.
        let dbg = format!("{:?}", self.legacy);
        // "DieDetector(N rules)" — extract N
        dbg.chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(0)
    }

    // ─── Public scan entry points ─────────────────────────────────────────────

    /// Scan a file on disk.
    ///
    /// # Errors
    /// Returns [`DieError`] on I/O or detection failure.
    pub fn scan_file(&self, path: &Path) -> Result<DieResult, DieError> {
        // Read at most `max_scan_bytes` from the file to avoid OOM on huge
        // inputs — do the cap *before* loading into memory, not after.
        let f = std::fs::File::open(path)
            .map_err(|e| DieError::DetectionFailed(e.to_string()))?;
        let cap = self.opts.max_scan_bytes;
        let mut data = Vec::with_capacity(cap.min(1024 * 1024));
        f.take(cap as u64)
            .read_to_end(&mut data)
            .map_err(|e| DieError::DetectionFailed(e.to_string()))?;
        self.scan_bytes(&data)
    }

    /// Scan a PE file (bytes already loaded).
    ///
    /// Equivalent to [`scan_bytes`] but asserts the input starts with `MZ`.
    ///
    /// # Errors
    /// Returns [`DieError`] on detection failure.
    pub fn scan_pe(&self, data: &[u8]) -> Result<DieResult, DieError> {
        if data.len() < 2 || &data[..2] != b"MZ" {
            return Err(DieError::DetectionFailed(
                "not a PE file: missing MZ header".to_owned(),
            ));
        }
        let mut result = self.run_scan(data)?;
        // PE-specific heuristics
        self.apply_pe_heuristics(data, &mut result);
        Ok(result)
    }

    /// Scan an ELF file (bytes already loaded).
    ///
    /// # Errors
    /// Returns [`DieError`] on detection failure.
    pub fn scan_elf(&self, data: &[u8]) -> Result<DieResult, DieError> {
        if data.len() < 4 || &data[..4] != b"\x7FELF" {
            return Err(DieError::DetectionFailed(
                "not an ELF file: missing ELF magic".to_owned(),
            ));
        }
        let mut result = self.run_scan(data)?;
        self.apply_elf_heuristics(data, &mut result);
        Ok(result)
    }

    /// Scan arbitrary bytes — the most general entry point.
    ///
    /// # Errors
    /// Returns [`DieError`] on detection failure.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<DieResult, DieError> {
        self.run_scan(data)
    }

    // ─── Core scan logic ──────────────────────────────────────────────────────

    fn run_scan(&self, data: &[u8]) -> Result<DieResult, DieError> {
        let ctx = ScanContext::new(data, &self.opts);
        let mut result = DieResult::new(ctx.file_kind, data.len());

        // 1. SignatureDb scan
        for sig in self.sig_db.scan(ctx.scan_window) {
            let det = sig.to_detection();
            if det.confidence >= self.opts.min_confidence {
                result.add(det);
            }
        }

        // 2. Legacy DieDetector
        if self.opts.include_legacy {
            let legacy_result = self.legacy.detect(ctx.scan_window)?;
            for det in legacy_result.detections {
                if det.confidence >= self.opts.min_confidence
                    && !result
                        .detections
                        .iter()
                        .any(|d| d.name == det.name && d.kind == det.kind)
                {
                    result.add(det);
                }
            }
        }

        // 3. Entropy scan
        if self.opts.entropy_scan {
            self.apply_entropy_heuristics(data, &mut result);
        }

        // 4. Overlay detection
        result.overlay_size = self.detect_overlay(data);

        Ok(result)
    }

    // ─── Heuristics ───────────────────────────────────────────────────────────

    fn apply_pe_heuristics(&self, data: &[u8], result: &mut DieResult) {
        // Detect digital signature (Authenticode) presence: IMAGE_DIRECTORY_ENTRY_SECURITY
        // at offset 0x98 (PE32) or 0xA8 (PE32+) in the optional header.
        // We do a lightweight check: look for "WIN_CERT" near end or PKCS7 OID.
        if data
            .windows(4)
            .any(|w| w == [0x30, 0x82, 0x00, 0x00] || w == b"\x06\x09\x60\x86")
        {
            result.is_signed = true;
        }
        // Rich header presence — strong indicator of MSVC
        if data.windows(4).any(|w| w == b"Rich")
            && !result
                .detections
                .iter()
                .any(|d| d.name == "MSVC" && d.kind == DetectKind::Compiler)
            {
                result.add(Detection {
                    kind: DetectKind::Compiler,
                    name: "MSVC".to_owned(),
                    version: None,
                    confidence: 70,
                    description: "Rich header present — MSVC linker".to_owned(),
                });
            }
    }

    fn apply_elf_heuristics(&self, data: &[u8], result: &mut DieResult) {
        // Check for Go build ID (`\xff Go build ID:` pattern)
        if data.windows(12).any(|w| w.starts_with(b"Go build ID"))
            && !result
                .detections
                .iter()
                .any(|d| d.name == "Go" && d.kind == DetectKind::Compiler)
            {
                result.add(Detection {
                    kind: DetectKind::Compiler,
                    name: "Go".to_owned(),
                    version: None,
                    confidence: 92,
                    description: "Go build ID section found".to_owned(),
                });
            }
        // UPX on ELF
        if data.windows(4).any(|w| w == b"UPX!") {
            result.add(Detection {
                kind: DetectKind::Packer,
                name: "UPX".to_owned(),
                version: None,
                confidence: 95,
                description: "UPX runtime magic in ELF binary".to_owned(),
            });
        }
    }

    fn apply_entropy_heuristics(&self, data: &[u8], result: &mut DieResult) {
        // Split into 4 KiB blocks and report if the majority are high-entropy
        if data.is_empty() {
            return;
        }
        let block_size = 4096usize;
        let total_blocks = data.chunks(block_size).count();
        let high_entropy_blocks = data
            .chunks(block_size)
            .filter(|chunk| {
                let mut freq = [0u64; 256];
                for &b in *chunk {
                    freq[b as usize] += 1;
                }
                let len = chunk.len() as f64;
                let entropy: f64 = freq.iter()
                    .filter(|&&c| c > 0)
                    .map(|&c| {
                        let p = c as f64 / len;
                        -p * p.log2()
                    })
                    .sum();
                entropy >= self.opts.high_entropy_threshold
            })
            .count();

        if total_blocks > 0 {
            let ratio = high_entropy_blocks as f64 / total_blocks as f64;
            if ratio >= 0.5 && !result.detections.iter().any(|d| d.name == "Unknown Packer") {
                result.add(Detection {
                    kind: DetectKind::Packer,
                    name: "Unknown Packer".to_owned(),
                    version: None,
                    confidence: (ratio * 80.0) as u8,
                    description: format!(
                        "Entropy scan: {high_entropy_blocks}/{} blocks exceed {:.1} bits",
                        total_blocks,
                        self.opts.high_entropy_threshold
                    ),
                });
            }
        }
    }

    /// Estimate overlay size: bytes after the last section / rational PE end.
    /// For non-PE files, returns 0.
    fn detect_overlay(&self, data: &[u8]) -> usize {
        // Minimal heuristic: if the file ends with a block of identical bytes
        // (common overlay padding), count them.
        if data.len() < 16 {
            return 0;
        }
        let tail = &data[data.len() - 512.min(data.len())..];
        let last_byte = *tail.last().unwrap();
        let padding = tail.iter().rev().take_while(|&&b| b == last_byte).count();
        // Only flag if there are >= 128 identical trailing bytes (likely padding/overlay)
        if padding >= 128 { padding } else { 0 }
    }
}

impl Default for DieScanner {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanBatch
// ─────────────────────────────────────────────────────────────────────────────

/// Batch scan result for multiple files.
#[derive(Debug, Default)]
pub struct ScanBatch {
    /// Per-file scan results: `(path, result)`.
    pub results: Vec<(std::path::PathBuf, Result<DieResult, DieError>)>,
}

impl ScanBatch {
    /// Create an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of files scanned.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.results.len()
    }

    /// Return `true` if no files were scanned.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Count of successful scans.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|(_, r)| r.is_ok()).count()
    }

    /// Count of failed scans.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.results.iter().filter(|(_, r)| r.is_err()).count()
    }

    /// All packed files (successfully scanned and `is_packed == true`).
    #[must_use]
    pub fn packed_files(&self) -> Vec<&std::path::PathBuf> {
        self.results
            .iter()
            .filter(|(_, r)| r.as_ref().map(|r| r.is_packed).unwrap_or(false))
            .map(|(p, _)| p)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BatchScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps [`DieScanner`] to scan multiple files and produce a [`ScanBatch`].
pub struct BatchScanner {
    scanner: DieScanner,
}

impl BatchScanner {
    /// Create a batch scanner with default settings.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            scanner: DieScanner::with_defaults(),
        }
    }

    /// Create a batch scanner with a custom inner scanner.
    #[must_use]
    pub const fn new(scanner: DieScanner) -> Self {
        Self { scanner }
    }

    /// Scan all paths in the provided list.
    #[must_use]
    pub fn scan_files(&self, paths: &[&Path]) -> ScanBatch {
        let mut batch = ScanBatch::new();
        for &path in paths {
            let res = self.scanner.scan_file(path);
            batch.results.push((path.to_path_buf(), res));
        }
        batch
    }

    /// Scan all files in a directory (non-recursive).
    ///
    /// # Errors
    /// Returns `std::io::Error` if the directory cannot be read.
    pub fn scan_dir(&self, dir: &Path) -> std::io::Result<ScanBatch> {
        let mut batch = ScanBatch::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let res = self.scanner.scan_file(&path);
                batch.results.push((path, res));
            }
        }
        Ok(batch)
    }
}

impl std::fmt::Debug for BatchScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BatchScanner(scanner={:?})", self.scanner)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a minimal DieDatabase from custom rules (public for callers)
// ─────────────────────────────────────────────────────────────────────────────

/// Build a [`DieDetector`] from a list of (name, kind, `pattern_bytes`) triples.
///
/// Each triple adds an "anywhere match" rule.  This is a convenience factory
/// for tests and integrations that need lightweight custom detectors.
#[must_use]
pub fn build_custom_detector(rules: &[(&str, DetectKind, &[u8])]) -> DieDetector {
    let mut db = DieDatabase::new();
    for &(name, kind, pattern) in rules {
        db.add_rule(crate::DieRule {
            name: name.to_owned(),
            kind,
            version: None,
            signature: vec![(0xFFFF_FFFF, pattern.to_vec())],
            confidence: 90,
        });
    }
    DieDetector::new(db)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe_data() -> Vec<u8> {
        let mut d = b"MZ".to_vec();
        d.extend_from_slice(&[0u8; 58]);
        d
    }

    fn make_upx_data() -> Vec<u8> {
        let mut d = make_pe_data();
        d.extend_from_slice(b"UPX0\x00UPX1\x00UPX!\x00");
        d
    }

    fn make_elf_data() -> Vec<u8> {
        let mut d = b"\x7FELF".to_vec();
        d.extend_from_slice(&[0u8; 60]);
        d
    }

    // ── DieScanner construction ────────────────────────────────────────────

    #[test]
    fn test_scanner_with_defaults_creates() {
        let s = DieScanner::with_defaults();
        assert!(s.signature_count() > 10);
    }

    #[test]
    fn test_scanner_debug() {
        let s = DieScanner::with_defaults();
        assert!(format!("{s:?}").contains("DieScanner"));
    }

    #[test]
    fn test_scanner_default() {
        let s = DieScanner::default();
        assert!(s.signature_count() > 0);
    }

    // ── scan_bytes ─────────────────────────────────────────────────────────

    #[test]
    fn test_scan_bytes_pe_mz() {
        let s = DieScanner::with_defaults();
        let result = s.scan_bytes(&make_pe_data()).unwrap();
        assert!(result.detections.iter().any(|d| d.name == "PE"));
    }

    #[test]
    fn test_scan_bytes_upx() {
        let s = DieScanner::with_defaults();
        let result = s.scan_bytes(&make_upx_data()).unwrap();
        assert!(result.is_packed, "UPX should set is_packed");
    }

    #[test]
    fn test_scan_bytes_elf() {
        let s = DieScanner::with_defaults();
        let data = make_elf_data();
        let result = s.scan_bytes(&data).unwrap();
        assert!(result.detections.iter().any(|d| d.name == "ELF"));
    }

    #[test]
    fn test_scan_bytes_rust_binary() {
        let s = DieScanner::with_defaults();
        let mut d = make_pe_data();
        d.extend_from_slice(b"panicked at 'index out of bounds'");
        let result = s.scan_bytes(&d).unwrap();
        assert!(result.detections.iter().any(|d| d.name == "Rust"));
    }

    // ── scan_pe ────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_pe_rejects_non_pe() {
        let s = DieScanner::with_defaults();
        let err = s.scan_pe(b"\x7FELF\x00\x00\x00\x00").unwrap_err();
        assert!(err.to_string().contains("MZ"));
    }

    #[test]
    fn test_scan_pe_accepts_mz() {
        let s = DieScanner::with_defaults();
        let result = s.scan_pe(&make_pe_data()).unwrap();
        assert_eq!(result.file_size, make_pe_data().len());
    }

    #[test]
    fn test_scan_pe_rich_header() {
        let s = DieScanner::with_defaults();
        let mut d = make_pe_data();
        d.extend_from_slice(b"DanS\x00\x00\x00\x00Rich");
        let result = s.scan_pe(&d).unwrap();
        assert!(result.detections.iter().any(|d| d.name == "MSVC"));
    }

    // ── scan_elf ───────────────────────────────────────────────────────────

    #[test]
    fn test_scan_elf_rejects_non_elf() {
        let s = DieScanner::with_defaults();
        let err = s.scan_elf(b"MZ\x00\x00").unwrap_err();
        assert!(err.to_string().contains("ELF"));
    }

    #[test]
    fn test_scan_elf_accepts_elf() {
        let s = DieScanner::with_defaults();
        let result = s.scan_elf(&make_elf_data()).unwrap();
        assert!(result.detections.iter().any(|d| d.name == "ELF"));
    }

    #[test]
    fn test_scan_elf_go_build_id() {
        let s = DieScanner::with_defaults();
        let mut d = make_elf_data();
        d.extend_from_slice(b"Go build ID: abc123");
        let result = s.scan_elf(&d).unwrap();
        assert!(result.detections.iter().any(|d| d.name == "Go"));
    }

    // ── ScanOptions ────────────────────────────────────────────────────────

    #[test]
    fn test_scan_options_default() {
        let o = ScanOptions::default();
        assert_eq!(o.min_confidence, 50);
        assert!(o.include_legacy);
        assert!(o.entropy_scan);
    }

    #[test]
    fn test_scanner_with_options() {
        let opts = ScanOptions {
            min_confidence: 80,
            include_legacy: false,
            entropy_scan: false,
            ..Default::default()
        };
        let s = DieScanner::with_options(opts);
        // Scan with high min_confidence — few detections
        let d = make_pe_data();
        let result = s.scan_bytes(&d).unwrap();
        // PE magic is 99% confidence → 99 >= 80 → should still appear
        assert!(result.detections.iter().any(|d| d.name == "PE"));
    }

    // ── overlay detection ──────────────────────────────────────────────────

    #[test]
    fn test_overlay_detection_none() {
        let s = DieScanner::with_defaults();
        let data = make_pe_data();
        let result = s.scan_bytes(&data).unwrap();
        assert_eq!(result.overlay_size, 0);
    }

    #[test]
    fn test_overlay_detection_padding() {
        let s = DieScanner::with_defaults();
        let mut data = make_pe_data();
        data.extend(vec![0x00u8; 256]);
        let result = s.scan_bytes(&data).unwrap();
        assert!(
            result.overlay_size >= 128,
            "overlay={}",
            result.overlay_size
        );
    }

    // ── ScanBatch / BatchScanner ───────────────────────────────────────────

    #[test]
    fn test_scan_batch_new() {
        let b = ScanBatch::new();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn test_scan_batch_counts() {
        let mut b = ScanBatch::new();
        b.results
            .push(("a.exe".into(), Ok(DieResult::new(FileKind::Pe32, 100))));
        b.results
            .push(("bad".into(), Err(DieError::DetectionFailed("fail".into()))));
        assert_eq!(b.len(), 2);
        assert_eq!(b.success_count(), 1);
        assert_eq!(b.error_count(), 1);
    }

    #[test]
    fn test_scan_batch_packed_files() {
        let mut b = ScanBatch::new();
        let mut r = DieResult::new(FileKind::Pe32, 100);
        r.is_packed = true;
        b.results.push(("packed.exe".into(), Ok(r)));
        b.results
            .push(("clean.exe".into(), Ok(DieResult::new(FileKind::Pe64, 200))));
        let packed = b.packed_files();
        assert_eq!(packed.len(), 1);
    }

    // ── build_custom_detector ─────────────────────────────────────────────

    #[test]
    fn test_build_custom_detector() {
        let det = build_custom_detector(&[("MyPacker", DetectKind::Packer, b"MYPACKER_MAGIC")]);
        let result = det.detect(b"prefix MYPACKER_MAGIC suffix").unwrap();
        assert_eq!(result.detections.len(), 1);
        assert_eq!(result.detections[0].name, "MyPacker");
    }

    // ── BatchScanner ──────────────────────────────────────────────────────

    #[test]
    fn test_batch_scanner_debug() {
        let b = BatchScanner::with_defaults();
        assert!(format!("{b:?}").contains("BatchScanner"));
    }

    #[test]
    fn test_batch_scanner_no_files() {
        let b = BatchScanner::with_defaults();
        let batch = b.scan_files(&[]);
        assert!(batch.is_empty());
    }
}
