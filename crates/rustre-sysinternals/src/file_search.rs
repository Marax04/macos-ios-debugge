//! Filesystem search engine — platform-agnostic file discovery and hashing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
pub use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::SysinternalsError;

// ─── FileResult ───────────────────────────────────────────────────────────────

/// A file found by the search engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    /// Absolute path.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Last modification time (Unix seconds).
    pub modified: u64,
    /// MD5 hash (computed on demand).
    pub md5: Option<String>,
    /// SHA-256 hash (computed on demand).
    pub sha256: Option<String>,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Whether the file is executable.
    pub is_executable: bool,
}

impl FileResult {
    /// Create from a path; reads metadata.
    ///
    /// # Errors
    /// Returns an error if the path's metadata cannot be read.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, SysinternalsError> {
        let path = path.as_ref();
        let meta = std::fs::metadata(path).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        #[cfg(unix)]
        let is_executable = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let is_executable = path
            .extension()
            .is_some_and(|e| {
                matches!(
                    e.to_str(),
                    Some("exe" | "cmd" | "bat" | "msi")
                )
            });

        Ok(Self {
            path: path.to_path_buf(),
            size: meta.len(),
            modified,
            md5: None,
            sha256: None,
            is_dir: meta.is_dir(),
            is_executable,
        })
    }

    /// File extension, lowercased.
    #[must_use]
    pub fn extension(&self) -> Option<String> {
        self.path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_lowercase)
    }

    /// File name without directory.
    #[must_use]
    pub fn file_name(&self) -> Option<String> {
        self.path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
    }

    /// CSV row: path,size,modified,md5,sha256
    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.path.display(),
            self.size,
            self.modified,
            self.md5.as_deref().unwrap_or(""),
            self.sha256.as_deref().unwrap_or(""),
        )
    }
}

// ─── SearchCriteria ───────────────────────────────────────────────────────────

/// Criteria for `FileSearchEngine::search`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchCriteria {
    /// Glob-style name pattern (e.g. `"*.exe"`, `"pass*"`).
    /// If `None`, all filenames match.
    pub name_pattern: Option<String>,
    /// Minimum file size in bytes (inclusive).
    pub min_size: Option<u64>,
    /// Maximum file size in bytes (inclusive).
    pub max_size: Option<u64>,
    /// Accept only files modified after this Unix timestamp.
    pub modified_after: Option<u64>,
    /// Accept only files modified before this Unix timestamp.
    pub modified_before: Option<u64>,
    /// Accept only files whose content contains this substring.
    pub content_contains: Option<String>,
    /// File extension filter (e.g. `"exe"` — without dot).
    pub extension: Option<String>,
    /// If `true`, skip hidden files/directories (name starts with `.`).
    pub skip_hidden: bool,
    /// If `true`, also match directories (default: files only).
    pub include_dirs: bool,
    /// Maximum depth of directory recursion.  `None` = unlimited.
    pub max_depth: Option<usize>,
    /// Minimum size for `LargeFileDetector` threshold.
    pub large_file_threshold: Option<u64>,
}

impl SearchCriteria {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_name_pattern(mut self, p: impl Into<String>) -> Self {
        self.name_pattern = Some(p.into());
        self
    }

    #[must_use]
    pub const fn with_size_range(mut self, min: Option<u64>, max: Option<u64>) -> Self {
        self.min_size = min;
        self.max_size = max;
        self
    }

    #[must_use]
    pub const fn with_modified_after(mut self, ts: u64) -> Self {
        self.modified_after = Some(ts);
        self
    }

    #[must_use]
    pub fn with_content_contains(mut self, s: impl Into<String>) -> Self {
        self.content_contains = Some(s.into());
        self
    }

    #[must_use]
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extension = Some(ext.into().to_lowercase());
        self
    }

    #[must_use]
    pub const fn with_max_depth(mut self, d: usize) -> Self {
        self.max_depth = Some(d);
        self
    }

    /// Returns `true` if a `FileResult` satisfies this criteria.
    #[must_use]
    pub fn matches(&self, result: &FileResult) -> bool {
        if !self.include_dirs && result.is_dir {
            return false;
        }
        if self.skip_hidden
            && let Some(name) = result.file_name()
                && name.starts_with('.') {
                    return false;
                }
        if let Some(ref pattern) = self.name_pattern {
            let name = result.file_name().unwrap_or_default();
            if !glob_match(pattern, &name) {
                return false;
            }
        }
        if let Some(ref ext) = self.extension {
            let file_ext = result.extension().unwrap_or_default();
            if &file_ext != ext {
                return false;
            }
        }
        if let Some(min) = self.min_size
            && result.size < min {
                return false;
            }
        if let Some(max) = self.max_size
            && result.size > max {
                return false;
            }
        if let Some(after) = self.modified_after
            && result.modified < after {
                return false;
            }
        if let Some(before) = self.modified_before
            && result.modified > before {
                return false;
            }
        true
    }
}

/// Simple glob match: `*` matches any sequence, `?` matches one char.
fn glob_match(pattern: &str, text: &str) -> bool {
    let text_lower = text.to_lowercase();
    let pattern_lower = pattern.to_lowercase();
    glob_match_inner(pattern_lower.as_bytes(), text_lower.as_bytes())
}

fn glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    // Iterative two-pointer matcher with a single backtracking checkpoint.
    // Runs in O(pattern.len() * text.len()) worst case, avoiding the
    // exponential blowup of naive recursion on patterns like `*a*a*a*b`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut match_ti: usize = 0;
    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            match_ti = ti;
            pi += 1;
        } else if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            match_ti += 1;
            ti = match_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

// ─── RecursiveWalker ─────────────────────────────────────────────────────────

/// Recursively walks a directory and emits `FileResult`s.
pub struct RecursiveWalker {
    root: PathBuf,
    criteria: SearchCriteria,
}

impl RecursiveWalker {
    #[must_use]
    pub fn new(root: impl AsRef<Path>, criteria: SearchCriteria) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            criteria,
        }
    }

    /// Walk the directory tree and return matching `FileResult`s.
    #[must_use] 
    pub fn walk(&self) -> Vec<FileResult> {
        let mut results = Vec::new();
        self.walk_dir(&self.root, 0, &mut results);
        results
    }

    fn walk_dir(&self, dir: &Path, depth: usize, results: &mut Vec<FileResult>) {
        if let Some(max) = self.criteria.max_depth
            && depth > max {
                return;
            }

        let Ok(entries) = std::fs::read_dir(dir) else { return };

        for entry in entries.flatten() {
            let path = entry.path();
            // Skip symlinks to prevent cycles and unbounded recursion.
            if entry.file_type().is_ok_and(|ft| ft.is_symlink()) {
                continue;
            }
            let Ok(result) = FileResult::from_path(&path) else { continue };

            if result.is_dir {
                // Recurse into sub-directory (apply depth limit).
                self.walk_dir(&path, depth + 1, results);
            } else if self.criteria.matches(&result) {
                // Optional content filter (only for text-like reads).
                if let Some(ref substr) = self.criteria.content_contains {
                    use std::io::{BufRead, BufReader};
                    if let Ok(file) = std::fs::File::open(&path) {
                        let reader = BufReader::new(file);
                        for line in reader.lines().map_while(Result::ok) {
                            if line.contains(substr.as_str()) {
                                results.push(result);
                                break;
                            }
                        }
                    }
                    // Skip if content check is required but failed.
                } else {
                    results.push(result);
                }
            }
        }
    }
}

// ─── FileHasher ───────────────────────────────────────────────────────────────

/// Computes MD5 and SHA-256 hashes for files.
pub struct FileHasher;

impl FileHasher {
    /// Compute the SHA-256 hex digest of a file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn sha256(path: impl AsRef<Path>) -> Result<String, SysinternalsError> {
        let data =
            std::fs::read(path.as_ref()).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        Ok(sha256_bytes(&data))
    }

    /// Compute the MD5 hex digest of a file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn md5(path: impl AsRef<Path>) -> Result<String, SysinternalsError> {
        let data =
            std::fs::read(path.as_ref()).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        Ok(md5_bytes(&data))
    }

    /// Enrich a `FileResult` with both hashes.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn enrich(result: &mut FileResult) -> Result<(), SysinternalsError> {
        let data = std::fs::read(&result.path).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        result.md5 = Some(md5_bytes(&data));
        result.sha256 = Some(sha256_bytes(&data));
        Ok(())
    }
}

/// Inline SHA-256 (duplicated from lib.rs to keep module self-contained).
fn sha256_bytes(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let kk: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut ww = [0u32; 64];
        for i in 0..16 {
            ww[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = ww[i - 15].rotate_right(7) ^ ww[i - 15].rotate_right(18) ^ (ww[i - 15] >> 3);
            let s1 = ww[i - 2].rotate_right(17) ^ ww[i - 2].rotate_right(19) ^ (ww[i - 2] >> 10);
            ww[i] = ww[i - 16]
                .wrapping_add(s0)
                .wrapping_add(ww[i - 7])
                .wrapping_add(s1);
        }
        let [mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
        for i in 0..64 {
            let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
            let ch = (ee & ff) ^ ((!ee) & gg);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(kk[i])
                .wrapping_add(ww[i]);
            let s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
            let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
            let t2 = s0.wrapping_add(maj);
            hh = gg;
            gg = ff;
            ff = ee;
            ee = dd.wrapping_add(t1);
            dd = cc;
            cc = bb;
            bb = aa;
            aa = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(aa);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee);
        h[5] = h[5].wrapping_add(ff);
        h[6] = h[6].wrapping_add(gg);
        h[7] = h[7].wrapping_add(hh);
    }
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// Inline MD5 (duplicated from lib.rs).
fn md5_bytes(data: &[u8]) -> String {
    let rot: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let kk: [u32; 64] = [
        0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613,
        0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193,
        0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d,
        0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, 0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
        0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122,
        0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
        0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, 0xf429_2244,
        0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
        0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0): (u32, u32, u32, u32) =
        (0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476);
    for chunk in msg.chunks(64) {
        let mut block = [0u32; 16];
        for i in 0..16 {
            block[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a0, b0, c0, d0);
        for i in 0usize..64 {
            let (mix, mi) = if i < 16 {
                ((bb & cc) | ((!bb) & dd), i)
            } else if i < 32 {
                ((dd & bb) | ((!dd) & cc), (5 * i + 1) % 16)
            } else if i < 48 {
                (bb ^ cc ^ dd, (3 * i + 5) % 16)
            } else {
                (cc ^ (bb | (!dd)), (7 * i) % 16)
            };
            let mix = mix.wrapping_add(aa).wrapping_add(kk[i]).wrapping_add(block[mi]);
            aa = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(mix.rotate_left(rot[i]));
        }
        a0 = a0.wrapping_add(aa);
        b0 = b0.wrapping_add(bb);
        c0 = c0.wrapping_add(cc);
        d0 = d0.wrapping_add(dd);
    }
    let res = [
        a0.to_le_bytes(),
        b0.to_le_bytes(),
        c0.to_le_bytes(),
        d0.to_le_bytes(),
    ]
    .concat();
    res.iter().fold(String::new(), |mut acc, bb| { use std::fmt::Write; let _ = write!(acc, "{bb:02x}"); acc })
}

// ─── LargeFileDetector ────────────────────────────────────────────────────────

/// Detects unusually large files in a directory tree.
pub struct LargeFileDetector {
    threshold_bytes: u64,
}

impl LargeFileDetector {
    #[must_use]
    pub const fn new(threshold_bytes: u64) -> Self {
        Self { threshold_bytes }
    }

    /// Default: files larger than 100 MB.
    #[must_use]
    pub const fn default_threshold() -> Self {
        Self::new(100 * 1024 * 1024)
    }

    /// Scan a directory tree for files exceeding the threshold.
    pub fn scan(&self, root: impl AsRef<Path>) -> Vec<FileResult> {
        let criteria = SearchCriteria::new().with_size_range(Some(self.threshold_bytes), None);
        RecursiveWalker::new(root, criteria).walk()
    }

    /// Filter a pre-existing list of `FileResult`s.
    #[must_use]
    pub fn filter<'a>(&self, results: &'a [FileResult]) -> Vec<&'a FileResult> {
        results
            .iter()
            .filter(|r| r.size >= self.threshold_bytes)
            .collect()
    }

    /// Human-readable size string (KB/MB/GB).
    #[must_use]
    pub fn human_size(bytes: u64) -> String {
        if bytes >= 1024 * 1024 * 1024 {
            let whole = bytes / (1024 * 1024 * 1024);
            let frac = (bytes % (1024 * 1024 * 1024)) * 10 / (1024 * 1024 * 1024);
            format!("{whole}.{frac} GB")
        } else if bytes >= 1024 * 1024 {
            let whole = bytes / (1024 * 1024);
            let frac = (bytes % (1024 * 1024)) * 10 / (1024 * 1024);
            format!("{whole}.{frac} MB")
        } else if bytes >= 1024 {
            let whole = bytes / 1024;
            let frac = (bytes % 1024) * 10 / 1024;
            format!("{whole}.{frac} KB")
        } else {
            format!("{bytes} B")
        }
    }
}

// ─── FileSearchEngine ─────────────────────────────────────────────────────────

/// High-level filesystem search engine.
pub struct FileSearchEngine {
    default_criteria: SearchCriteria,
}

impl FileSearchEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_criteria: SearchCriteria::new(),
        }
    }

    #[must_use]
    pub const fn with_criteria(criteria: SearchCriteria) -> Self {
        Self {
            default_criteria: criteria,
        }
    }

    /// Search a directory tree using this engine's default criteria.
    pub fn search(&self, root: impl AsRef<Path>) -> Vec<FileResult> {
        RecursiveWalker::new(root, self.default_criteria.clone()).walk()
    }

    /// Search using explicit criteria (overrides default).
    pub fn search_with(&self, root: impl AsRef<Path>, criteria: SearchCriteria) -> Vec<FileResult> {
        RecursiveWalker::new(root, criteria).walk()
    }

    /// Find duplicate files (by SHA-256) under a directory.
    pub fn find_duplicates(&self, root: impl AsRef<Path>) -> HashMap<String, Vec<PathBuf>> {
        let results = RecursiveWalker::new(root, SearchCriteria::new()).walk();
        let mut by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for mut r in results {
            if matches!(FileHasher::enrich(&mut r), Ok(()))
                && let Some(hash) = r.sha256 {
                    by_hash.entry(hash).or_default().push(r.path);
                }
        }
        by_hash.retain(|_, v| v.len() > 1);
        by_hash
    }

    /// Find files matching a name pattern in a directory tree.
    pub fn find_by_name(
        &self,
        root: impl AsRef<Path>,
        pattern: impl AsRef<str>,
    ) -> Vec<FileResult> {
        let criteria = SearchCriteria::new().with_name_pattern(pattern.as_ref());
        RecursiveWalker::new(root, criteria).walk()
    }
}

impl Default for FileSearchEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── glob_match ────────────────────────────────────────────────────────────

    #[test]
    fn glob_star_matches_all() {
        assert!(glob_match("*", "anything.exe"));
        assert!(glob_match("*.exe", "program.exe"));
        assert!(!glob_match("*.exe", "program.dll"));
    }

    #[test]
    fn glob_question_matches_single_char() {
        assert!(glob_match("?.txt", "a.txt"));
        assert!(!glob_match("?.txt", "ab.txt"));
    }

    #[test]
    fn glob_literal_match() {
        assert!(glob_match("hello.txt", "hello.txt"));
        assert!(glob_match("Hello.TXT", "HELLO.txt")); // case insensitive
        assert!(!glob_match("hello.txt", "world.txt"));
    }

    #[test]
    fn glob_prefix_star() {
        assert!(glob_match("*test*", "my_test_file.rs"));
        assert!(!glob_match("*test*", "production.rs"));
    }

    // ── SearchCriteria::matches ───────────────────────────────────────────────

    fn fake_result(name: &str, size: u64, modified: u64, is_dir: bool) -> FileResult {
        FileResult {
            path: PathBuf::from(name),
            size,
            modified,
            md5: None,
            sha256: None,
            is_dir,
            is_executable: false,
        }
    }

    #[test]
    fn criteria_size_range() {
        let c = SearchCriteria::new().with_size_range(Some(100), Some(500));
        assert!(c.matches(&fake_result("f", 100, 0, false)));
        assert!(c.matches(&fake_result("f", 500, 0, false)));
        assert!(!c.matches(&fake_result("f", 99, 0, false)));
        assert!(!c.matches(&fake_result("f", 501, 0, false)));
    }

    #[test]
    fn criteria_name_pattern() {
        let c = SearchCriteria::new().with_name_pattern("*.txt");
        assert!(c.matches(&fake_result("notes.txt", 10, 0, false)));
        assert!(!c.matches(&fake_result("notes.exe", 10, 0, false)));
    }

    #[test]
    fn criteria_extension_filter() {
        let c = SearchCriteria::new().with_extension("exe");
        assert!(c.matches(&fake_result("prog.exe", 10, 0, false)));
        assert!(!c.matches(&fake_result("prog.dll", 10, 0, false)));
    }

    #[test]
    fn criteria_modified_after() {
        let c = SearchCriteria::new().with_modified_after(1_000);
        assert!(c.matches(&fake_result("f", 10, 2_000, false)));
        assert!(!c.matches(&fake_result("f", 10, 500, false)));
    }

    #[test]
    fn criteria_dirs_excluded_by_default() {
        let c = SearchCriteria::new();
        assert!(!c.matches(&fake_result("dir", 0, 0, true)));
    }

    #[test]
    fn criteria_dirs_included_when_flag_set() {
        let mut c = SearchCriteria::new();
        c.include_dirs = true;
        assert!(c.matches(&fake_result("dir", 0, 0, true)));
    }

    #[test]
    fn criteria_skip_hidden() {
        let mut c = SearchCriteria::new();
        c.skip_hidden = true;
        assert!(!c.matches(&fake_result(".hidden", 10, 0, false)));
        assert!(c.matches(&fake_result("visible.txt", 10, 0, false)));
    }

    // ── FileResult helpers ────────────────────────────────────────────────────

    #[test]
    fn file_result_csv_row() {
        let r = fake_result("test.txt", 100, 1_700_000_000, false);
        let csv = r.to_csv_row();
        assert!(csv.contains("test.txt"));
        assert!(csv.contains("100"));
    }

    #[test]
    fn file_result_extension() {
        let r = fake_result("program.exe", 100, 0, false);
        assert_eq!(r.extension(), Some("exe".to_string()));
    }

    #[test]
    fn file_result_file_name() {
        let r = fake_result("subdir/program.exe", 100, 0, false);
        assert_eq!(r.file_name(), Some("program.exe".to_string()));
    }

    // ── RecursiveWalker ───────────────────────────────────────────────────────

    #[test]
    fn walker_empty_dir_returns_empty() {
        // Walk a path that doesn't exist — should return empty without panicking.
        let criteria = SearchCriteria::new();
        let results = RecursiveWalker::new(
            std::path::Path::new("/nonexistent_rustre_test_path_xyz"),
            criteria,
        )
        .walk();
        assert!(results.is_empty());
    }

    #[test]
    fn walker_current_dir_returns_files() {
        // Walk the temp directory (always exists) — just verify it doesn't panic.
        let criteria = SearchCriteria::new().with_max_depth(0);
        let _results = RecursiveWalker::new(std::env::temp_dir(), criteria).walk();
        // No assertion needed — just checking it doesn't panic.
    }

    #[test]
    fn walker_respects_extension_filter_on_fake_results() {
        // Test extension filtering using the criteria matcher directly.
        let c = SearchCriteria::new().with_extension("txt");
        let txt = fake_result("notes.txt", 10, 0, false);
        let exe = fake_result("prog.exe", 10, 0, false);
        assert!(c.matches(&txt));
        assert!(!c.matches(&exe));
    }

    // ── Hashing ───────────────────────────────────────────────────────────────

    #[test]
    fn sha256_known_value() {
        // SHA-256 of empty string
        let hash = sha256_bytes(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn md5_known_value() {
        // MD5 of empty string
        let hash = md5_bytes(b"");
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn sha256_hello_world() {
        let hash = sha256_bytes(b"hello world");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── LargeFileDetector ─────────────────────────────────────────────────────

    #[test]
    fn large_file_detector_filter() {
        let results = vec![
            fake_result("small.bin", 100, 0, false),
            fake_result("large.bin", 200 * 1024 * 1024, 0, false),
        ];
        let detector = LargeFileDetector::new(100 * 1024 * 1024);
        let large = detector.filter(&results);
        assert_eq!(large.len(), 1);
        assert!(large[0].path.to_str().unwrap().contains("large"));
    }

    #[test]
    fn large_file_human_size() {
        assert_eq!(LargeFileDetector::human_size(1023), "1023 B");
        assert_eq!(LargeFileDetector::human_size(1024), "1.0 KB");
        assert!(LargeFileDetector::human_size(2 * 1024 * 1024).contains("MB"));
        assert!(LargeFileDetector::human_size(2 * 1024 * 1024 * 1024).contains("GB"));
    }

    // ── FileSearchEngine ──────────────────────────────────────────────────────

    #[test]
    fn search_engine_default_constructs() {
        let _engine = FileSearchEngine::new();
        let _engine2 = FileSearchEngine::with_criteria(SearchCriteria::new().with_extension("rs"));
    }

    #[test]
    fn search_engine_find_by_name_empty_dir() {
        let engine = FileSearchEngine::new();
        let results = engine.find_by_name(
            std::path::Path::new("/nonexistent_rustre_path_xyz"),
            "*.txt",
        );
        assert!(results.is_empty());
    }
}
