//! Export utilities for writing a virtual `MemFsNode` tree to disk.
//!
//! Provides configurable export of a [`crate::MemFsNode`] tree to a real
//! directory, with per-file size limits, overwrite control, and optional
//! JSON metadata sidecar files.

use std::path::{Path, PathBuf};

use crate::{MemFsError, MemFsNode};

// ─── ExportOptions ────────────────────────────────────────────────────────────

/// Configuration for an export operation.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Root directory on disk to write into.
    pub base_dir: PathBuf,
    /// Whether to create directories that have no file children.
    pub include_empty_dirs: bool,
    /// Maximum size of any single file to write. Files larger than this are
    /// skipped and recorded in [`ExportResult::skipped`].
    pub max_file_size: usize,
    /// Whether to overwrite existing files. If `false`, existing files are
    /// skipped and counted in [`ExportResult::skipped`].
    pub overwrite: bool,
    /// If `true`, create a `_metadata.json` in each directory listing its
    /// children (name → "file" | "dir").
    pub write_json_metadata: bool,
}

impl ExportOptions {
    /// Create options with sensible defaults.
    #[must_use]
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
            include_empty_dirs: true,
            max_file_size: 256 * 1024 * 1024, // 256 MB
            overwrite: true,
            write_json_metadata: false,
        }
    }

    /// Disable writing empty directories.
    #[must_use]
    pub const fn without_empty_dirs(mut self) -> Self {
        self.include_empty_dirs = false;
        self
    }

    /// Set the maximum file size (bytes).
    #[must_use]
    pub const fn with_max_file_size(mut self, bytes: usize) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Refuse to overwrite existing files.
    #[must_use]
    pub const fn no_overwrite(mut self) -> Self {
        self.overwrite = false;
        self
    }

    /// Enable JSON metadata sidecar files.
    #[must_use]
    pub const fn with_json_metadata(mut self) -> Self {
        self.write_json_metadata = true;
        self
    }
}

// ─── ExportResult ─────────────────────────────────────────────────────────────

/// Statistics and error list from a completed export operation.
#[derive(Debug, Default, Clone)]
pub struct ExportResult {
    /// Number of files successfully written.
    pub files_written: usize,
    /// Number of directories created.
    pub dirs_created: usize,
    /// Total bytes written to disk.
    pub bytes_written: u64,
    /// Number of files skipped (too large or overwrite=false).
    pub skipped: usize,
    /// Non-fatal errors (file-level I/O failures, etc.).
    pub errors: Vec<String>,
}

impl ExportResult {
    /// Returns `true` if no non-fatal errors occurred.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }

    /// Total items processed (files written + skipped + dirs).
    #[must_use]
    pub const fn total_items(&self) -> usize {
        self.files_written + self.skipped + self.dirs_created
    }
}

// ─── export_memfs ─────────────────────────────────────────────────────────────

/// Recursively export a [`MemFsNode`] tree to `opts.base_dir` on disk.
///
/// # Errors
/// Returns [`MemFsError::Io`] if the base directory cannot be created.
/// File-level errors are collected into [`ExportResult::errors`] rather than
/// aborting the entire export.
pub fn export_memfs(root: &MemFsNode, opts: &ExportOptions) -> Result<ExportResult, MemFsError> {
    let mut result = ExportResult::default();
    export_node(root, &opts.base_dir, opts, &mut result)?;
    Ok(result)
}

fn export_node(
    node: &MemFsNode,
    path: &Path,
    opts: &ExportOptions,
    result: &mut ExportResult,
) -> Result<(), MemFsError> {
    match node {
        MemFsNode::Directory(children) => {
            // Determine whether we should create this directory at all
            let has_file_content = dir_has_files(node);
            if !has_file_content && !opts.include_empty_dirs {
                return Ok(());
            }

            std::fs::create_dir_all(path)?;
            result.dirs_created += 1;

            // Optionally write _metadata.json
            if opts.write_json_metadata {
                let meta = build_metadata_json(children);
                let meta_path = path.join("_metadata.json");
                if let Err(e) = std::fs::write(&meta_path, meta.as_bytes()) {
                    result
                        .errors
                        .push(format!("failed to write {}: {e}", meta_path.display()));
                } else {
                    result.files_written += 1;
                    result.bytes_written += meta.len() as u64;
                }
            }

            for (name, child) in children {
                let child_path = path.join(sanitize_path_component(name));
                export_node(child, &child_path, opts, result)?;
            }
        }

        MemFsNode::File(data) => {
            export_file_data(data.as_slice(), path, opts, result);
        }

        MemFsNode::LazyFile(func) => {
            let data = func();
            export_file_data(&data, path, opts, result);
        }
    }
    Ok(())
}

fn export_file_data(data: &[u8], path: &Path, opts: &ExportOptions, result: &mut ExportResult) {
    // Size check
    if data.len() > opts.max_file_size {
        result.skipped += 1;
        result.errors.push(format!(
            "skipped {} ({} bytes > max {})",
            path.display(),
            data.len(),
            opts.max_file_size
        ));
        return;
    }

    // Overwrite check
    if !opts.overwrite && path.exists() {
        result.skipped += 1;
        return;
    }

    // Ensure parent directory exists
    if let Some(parent) = path.parent() && !parent.exists() && let Err(e) = std::fs::create_dir_all(parent) {
        result.errors.push(format!(
            "cannot create parent dir {}: {e}",
            parent.display()
        ));
        return;
    }

    match std::fs::write(path, data) {
        Ok(()) => {
            result.files_written += 1;
            result.bytes_written += data.len() as u64;
        }
        Err(e) => {
            result
                .errors
                .push(format!("write error {}: {e}", path.display()));
        }
    }
}

/// Returns `true` if the directory subtree contains at least one file.
fn dir_has_files(node: &MemFsNode) -> bool {
    match node {
        MemFsNode::File(_) | MemFsNode::LazyFile(_) => true,
        MemFsNode::Directory(children) => children.iter().any(|(_, c)| dir_has_files(c)),
    }
}

/// Build a minimal `_metadata.json` for a directory's children.
fn build_metadata_json(children: &[(String, MemFsNode)]) -> String {
    let mut entries: Vec<String> = children
        .iter()
        .map(|(name, child)| {
            let kind = if child.is_dir() { "dir" } else { "file" };
            format!("  \"{}\": \"{}\"", json_escape(name), kind)
        })
        .collect();
    entries.sort(); // deterministic output
    format!("{{\n{}\n}}", entries.join(",\n"))
}

/// Minimal JSON string escaping (backslash and double-quote only).
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Replace path-separator characters and dot-dot sequences in a node name so
/// they cannot escape the export directory.
///
/// Specifically:
/// - Forward slash and backslash are replaced with `_`.
/// - A name that is purely dots (`.` or `..`) is replaced with `_` to prevent
///   directory traversal via `PathBuf::join("..")`.
/// - Null bytes are replaced with `_`.
fn sanitize_path_component(name: &str) -> String {
    // First replace separator characters and null bytes.
    let sanitized: String = name
        .chars()
        .map(|c| if c == '/' || c == '\\' || c == '\0' { '_' } else { c })
        .collect();
    // Guard against pure-dot names (".", "..") after the above substitution.
    if sanitized.chars().all(|c| c == '.') {
        return "_".to_string();
    }
    sanitized
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Helper builders ──────────────────────────────────────────────────────

    fn make_tree() -> MemFsNode {
        MemFsNode::Directory(vec![
            (
                "subdir".to_string(),
                MemFsNode::Directory(vec![
                    ("file_a.txt".to_string(), MemFsNode::File(b"hello".to_vec())),
                    ("file_b.bin".to_string(), MemFsNode::File(b"world".to_vec())),
                ]),
            ),
            (
                "top_file.txt".to_string(),
                MemFsNode::File(b"top-level content".to_vec()),
            ),
        ])
    }

    fn temp_dir(suffix: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("rustre_export_test_{suffix}"));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    // ─── Basic export ─────────────────────────────────────────────────────────

    #[test]
    fn export_creates_files() {
        let root = make_tree();
        let dir = temp_dir("basic");
        let opts = ExportOptions::new(&dir);
        let result = export_memfs(&root, &opts).unwrap();
        assert!(dir.join("top_file.txt").exists());
        assert!(dir.join("subdir").join("file_a.txt").exists());
        assert!(result.files_written >= 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_bytes_written() {
        let root = make_tree();
        let dir = temp_dir("bytes");
        let opts = ExportOptions::new(&dir);
        let result = export_memfs(&root, &opts).unwrap();
        // "hello" + "world" + "top-level content" = 5+5+17 = 27
        assert_eq!(result.bytes_written, 27);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_dirs_created() {
        let root = make_tree();
        let dir = temp_dir("dirs");
        let opts = ExportOptions::new(&dir);
        let result = export_memfs(&root, &opts).unwrap();
        // root dir + subdir = at least 2
        assert!(result.dirs_created >= 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── Size limit ───────────────────────────────────────────────────────────

    #[test]
    fn export_skips_oversized_files() {
        let root = MemFsNode::Directory(vec![
            ("big.bin".to_string(), MemFsNode::File(vec![0u8; 100])),
            ("small.txt".to_string(), MemFsNode::File(b"ok".to_vec())),
        ]);
        let dir = temp_dir("size");
        let opts = ExportOptions::new(&dir).with_max_file_size(50);
        let result = export_memfs(&root, &opts).unwrap();
        assert_eq!(result.skipped, 1);
        assert!(!dir.join("big.bin").exists());
        assert!(dir.join("small.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── Overwrite ────────────────────────────────────────────────────────────

    #[test]
    fn export_no_overwrite_skips_existing() {
        let dir = temp_dir("overwrite");
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("file.txt");
        std::fs::write(&existing, b"original").unwrap();

        let root = MemFsNode::Directory(vec![(
            "file.txt".to_string(),
            MemFsNode::File(b"new content".to_vec()),
        )]);
        let opts = ExportOptions::new(&dir).no_overwrite();
        let result = export_memfs(&root, &opts).unwrap();
        assert_eq!(result.skipped, 1);
        // Original content should be unchanged
        let content = std::fs::read(&existing).unwrap();
        assert_eq!(content, b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── JSON metadata ────────────────────────────────────────────────────────

    #[test]
    fn export_json_metadata_created() {
        let root = make_tree();
        let dir = temp_dir("meta");
        let opts = ExportOptions::new(&dir).with_json_metadata();
        let result = export_memfs(&root, &opts).unwrap();
        assert!(dir.join("_metadata.json").exists());
        assert!(result.files_written >= 3); // 2 real + at least 1 metadata
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_json_metadata_content() {
        let root = make_tree();
        let dir = temp_dir("meta2");
        let opts = ExportOptions::new(&dir).with_json_metadata();
        export_memfs(&root, &opts).unwrap();
        let meta = std::fs::read_to_string(dir.join("_metadata.json")).unwrap();
        assert!(meta.contains("subdir"));
        assert!(meta.contains("top_file.txt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── Empty dirs ───────────────────────────────────────────────────────────

    #[test]
    fn export_empty_dir_skipped_when_disabled() {
        let root = MemFsNode::Directory(vec![
            ("emptydir".to_string(), MemFsNode::Directory(vec![])),
            ("file.txt".to_string(), MemFsNode::File(b"data".to_vec())),
        ]);
        let dir = temp_dir("emptydir");
        let opts = ExportOptions::new(&dir).without_empty_dirs();
        export_memfs(&root, &opts).unwrap();
        assert!(!dir.join("emptydir").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_empty_dir_included_by_default() {
        let root =
            MemFsNode::Directory(vec![("emptydir".to_string(), MemFsNode::Directory(vec![]))]);
        let dir = temp_dir("emptydir2");
        let opts = ExportOptions::new(&dir);
        export_memfs(&root, &opts).unwrap();
        assert!(dir.join("emptydir").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── LazyFile ─────────────────────────────────────────────────────────────

    #[test]
    fn export_lazy_file() {
        let root = MemFsNode::Directory(vec![(
            "lazy.txt".to_string(),
            MemFsNode::LazyFile(Box::new(|| b"computed".to_vec())),
        )]);
        let dir = temp_dir("lazy");
        let opts = ExportOptions::new(&dir);
        let result = export_memfs(&root, &opts).unwrap();
        assert_eq!(result.files_written, 1);
        let content = std::fs::read(dir.join("lazy.txt")).unwrap();
        assert_eq!(content, b"computed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── ExportResult helpers ─────────────────────────────────────────────────

    #[test]
    fn export_result_is_clean() {
        let r = ExportResult::default();
        assert!(r.is_clean());
    }

    #[test]
    fn export_result_total_items() {
        let r = ExportResult {
            files_written: 3,
            dirs_created: 2,
            bytes_written: 100,
            skipped: 1,
            errors: vec![],
        };
        assert_eq!(r.total_items(), 6);
    }

    // ─── sanitize_path_component ──────────────────────────────────────────────

    #[test]
    fn sanitize_no_slashes() {
        assert_eq!(sanitize_path_component("file.txt"), "file.txt");
    }

    #[test]
    fn sanitize_forward_slash() {
        let s = sanitize_path_component("a/b");
        assert!(!s.contains('/'));
        assert!(s.contains('_'));
    }

    #[test]
    fn sanitize_backslash() {
        let s = sanitize_path_component("a\\b");
        assert!(!s.contains('\\'));
    }

    // ─── ExportOptions builder ────────────────────────────────────────────────

    #[test]
    fn opts_defaults() {
        let opts = ExportOptions::new("/tmp/test");
        assert!(opts.include_empty_dirs);
        assert!(opts.overwrite);
        assert!(!opts.write_json_metadata);
    }

    #[test]
    fn opts_builder_chain() {
        let opts = ExportOptions::new("/tmp/test")
            .without_empty_dirs()
            .with_max_file_size(1024)
            .no_overwrite()
            .with_json_metadata();
        assert!(!opts.include_empty_dirs);
        assert_eq!(opts.max_file_size, 1024);
        assert!(!opts.overwrite);
        assert!(opts.write_json_metadata);
    }
}
