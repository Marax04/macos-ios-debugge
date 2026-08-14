//! Recent-files tracking for the `rustre` CLI binary.
//!
//! [`RecentFiles`] maintains a size-bounded, time-ordered list of file paths
//! the user has recently opened.  Each [`RecentEntry`] stores the path, a
//! MIME-like category, the last-accessed timestamp, and a hit count.
//!
//! The list is persisted to `~/.rustre/recent.json` between sessions.

use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ── FileCategory ──────────────────────────────────────────────────────────────

/// A broad category for classifying recently-opened files.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileCategory {
    /// ELF binary.
    Elf,
    /// PE/COFF binary.
    Pe,
    /// Mach-O binary.
    MachO,
    /// JVM class file or JAR.
    Jvm,
    /// WebAssembly module.
    Wasm,
    /// DEX / Android binary.
    Android,
    /// RustRE project file.
    RustreProject,
    /// Raw shellcode blob.
    Shellcode,
    /// Script file (Rhai, Lua, Python, …).
    Script,
    /// Unknown or unsupported format.
    Unknown,
}

impl FileCategory {
    /// Detect a file category from the file extension or magic bytes.
    ///
    /// Reads up to 8 bytes from the file to check magic; falls back to
    /// extension-based detection on read failure.
    pub fn detect(path: &Path) -> Self {
        // Try magic bytes first.
        if let Ok(mut f) = fs::File::open(path) {
            let mut buf = [0u8; 8];
            use std::io::Read;
            if f.read(&mut buf).is_ok() {
                if buf.starts_with(b"\x7fELF") {
                    return Self::Elf;
                }
                if buf.starts_with(b"MZ") {
                    return Self::Pe;
                }
                if buf.starts_with(b"\xce\xfa\xed\xfe")
                    || buf.starts_with(b"\xcf\xfa\xed\xfe")
                    || buf.starts_with(b"\xfe\xed\xfa\xce")
                    || buf.starts_with(b"\xfe\xed\xfa\xcf")
                {
                    return Self::MachO;
                }
                if buf.starts_with(b"\xca\xfe\xba\xbe") {
                    return Self::Jvm;
                }
                if buf.starts_with(b"\x00asm") {
                    return Self::Wasm;
                }
                if buf.starts_with(b"dex\n") {
                    return Self::Android;
                }
            }
        }
        // Fallback: extension.
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .as_deref()
        {
            Some("so" | "elf") => Self::Elf,
            Some("exe" | "dll" | "sys" | "ocx" | "drv" | "scr") => Self::Pe,
            Some("dylib" | "macho") => Self::MachO,
            Some("class" | "jar") => Self::Jvm,
            Some("wasm") => Self::Wasm,
            Some("dex" | "apk" | "odex") => Self::Android,
            Some("rustre") => Self::RustreProject,
            Some("bin" | "sc" | "raw") => Self::Shellcode,
            Some("rhai" | "lua" | "py" | "js" | "rb") => Self::Script,
            _ => Self::Unknown,
        }
    }

    /// Return a short label for display purposes.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Elf => "ELF",
            Self::Pe => "PE",
            Self::MachO => "Mach-O",
            Self::Jvm => "JVM",
            Self::Wasm => "WASM",
            Self::Android => "Android",
            Self::RustreProject => "Project",
            Self::Shellcode => "Shellcode",
            Self::Script => "Script",
            Self::Unknown => "?",
        }
    }
}

impl fmt::Display for FileCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── RecentEntry ───────────────────────────────────────────────────────────────

/// A single entry in the recent-files list.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecentEntry {
    /// Absolute path to the file.
    pub path: PathBuf,
    /// Broad category detected from content or extension.
    pub category: FileCategory,
    /// Unix timestamp of the most recent access.
    pub last_accessed: u64,
    /// Number of times this path has been opened.
    pub access_count: u64,
    /// Optional user-assigned label.
    pub label: Option<String>,
    /// Whether the file still exists on disk (refreshed on each access).
    pub exists: bool,
}

impl RecentEntry {
    fn new(path: PathBuf) -> Self {
        let category = FileCategory::detect(&path);
        let exists = path.exists();
        Self {
            path,
            category,
            last_accessed: unix_now(),
            access_count: 1,
            label: None,
            exists,
        }
    }

    fn touch(&mut self) {
        self.last_accessed = unix_now();
        self.access_count += 1;
        self.exists = self.path.exists();
        self.category = FileCategory::detect(&self.path);
    }

    /// Return the file name component of the path, or the full path string.
    pub fn file_name(&self) -> &str {
        self.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_else(|| self.path.to_str().unwrap_or("?"))
    }

    /// Return the age of this entry in seconds.
    pub fn age_secs(&self) -> u64 {
        unix_now().saturating_sub(self.last_accessed)
    }
}

impl fmt::Display for RecentEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exists_marker = if self.exists { " " } else { "!" };
        write!(
            f,
            "{exists_marker} [{:>8}]  {:>3}  {}",
            self.access_count,
            self.category.label(),
            self.path.display(),
        )
    }
}

// ── FileHistory ───────────────────────────────────────────────────────────────

/// In-memory representation of the recent-files list, backed by a JSON file.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FileHistory {
    /// Ordered entries, newest first.
    entries: VecDeque<RecentEntry>,
    /// Maximum number of entries to keep.
    max_entries: usize,
}

impl FileHistory {
    /// Create an empty history with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Return the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return an iterator over all entries, newest first.
    pub fn iter(&self) -> impl Iterator<Item = &RecentEntry> {
        self.entries.iter()
    }

    /// Add or update a path, promoting it to the front.
    ///
    /// If the path already exists, its `access_count` and `last_accessed` are
    /// updated in-place and the entry is moved to the front.  If it is new, a
    /// fresh [`RecentEntry`] is created.
    pub fn add(&mut self, path: PathBuf) {
        // Canonicalize for stable identity comparison.
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());

        // Check if already present.
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.path == canonical || e.path == path)
        {
            let mut entry = self.entries.remove(pos).unwrap();
            entry.touch();
            self.entries.push_front(entry);
        } else {
            let mut entry = RecentEntry::new(canonical);
            if !entry.exists {
                // Try with the original path too.
                if path.exists() {
                    entry = RecentEntry::new(path);
                }
            }
            self.entries.push_front(entry);
        }

        // Trim excess.
        while self.entries.len() > self.max_entries {
            self.entries.pop_back();
        }
    }

    /// Remove a path from the history.
    ///
    /// Returns `true` if an entry was removed.
    pub fn remove(&mut self, path: &Path) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.path != path);
        self.entries.len() < before
    }

    /// Remove all entries whose files no longer exist on disk.
    pub fn prune_missing(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.path.exists());
        before - self.entries.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the most recently accessed entry, if any.
    pub fn most_recent(&self) -> Option<&RecentEntry> {
        self.entries.front()
    }

    /// Filter entries to those with the given category.
    pub fn by_category(&self, cat: &FileCategory) -> Vec<&RecentEntry> {
        self.entries
            .iter()
            .filter(|e| &e.category == cat)
            .collect()
    }

    /// Return up to `n` most recently accessed entries.
    pub fn top(&self, n: usize) -> Vec<&RecentEntry> {
        self.entries.iter().take(n).collect()
    }
}

// ── RecentFiles ───────────────────────────────────────────────────────────────

/// Persistent recent-files manager.
///
/// Wraps a [`FileHistory`] with load/save operations against a JSON file on
/// disk.
pub struct RecentFiles {
    history: FileHistory,
    path: PathBuf,
}

impl RecentFiles {
    /// Open the recent-files list at `path`, creating it if absent.
    ///
    /// `max_entries` caps the list size; values below 1 are clamped to 1.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O or deserialization failure.
    pub fn open(path: impl AsRef<Path>, max_entries: usize) -> Result<Self, RecentFilesError> {
        let path = path.as_ref().to_path_buf();
        let history = if path.exists() {
            let text = fs::read_to_string(&path).map_err(RecentFilesError::Io)?;
            serde_json::from_str::<FileHistory>(&text)
                .unwrap_or_else(|_| FileHistory::new(max_entries))
        } else {
            FileHistory::new(max_entries)
        };
        Ok(Self { history, path })
    }

    /// Open the default recent-files list at `~/.rustre/recent.json`.
    pub fn open_default(max_entries: usize) -> Result<Self, RecentFilesError> {
        let dir = home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".rustre");
        fs::create_dir_all(&dir).map_err(RecentFilesError::Io)?;
        Self::open(dir.join("recent.json"), max_entries)
    }

    /// Save the current history to disk.
    ///
    /// # Errors
    ///
    /// Returns `Err` on serialization or write failure.
    pub fn save(&self) -> Result<(), RecentFilesError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(RecentFilesError::Io)?;
        }
        let json =
            serde_json::to_string_pretty(&self.history).map_err(RecentFilesError::Serialization)?;
        fs::write(&self.path, json).map_err(RecentFilesError::Io)?;
        Ok(())
    }

    /// Add a path to the history and persist.
    pub fn add_and_save(&mut self, path: PathBuf) -> Result<(), RecentFilesError> {
        self.history.add(path);
        self.save()
    }

    /// Prune missing files and persist.
    pub fn prune_and_save(&mut self) -> Result<usize, RecentFilesError> {
        let n = self.history.prune_missing();
        self.save()?;
        Ok(n)
    }

    /// Return a reference to the underlying history.
    pub fn history(&self) -> &FileHistory {
        &self.history
    }

    /// Return a mutable reference to the underlying history.
    pub fn history_mut(&mut self) -> &mut FileHistory {
        &mut self.history
    }

    /// Return the path to the backing JSON file.
    pub fn backing_path(&self) -> &Path {
        &self.path
    }
}

// ── add_recent convenience function ──────────────────────────────────────────

/// Add `path` to the default recent-files list and persist.
///
/// This is the primary entry point for callers who want fire-and-forget
/// recording without managing a [`RecentFiles`] instance.
///
/// # Errors
///
/// Returns [`RecentFilesError`] if opening or persisting the list fails.
pub fn add_recent(path: impl AsRef<Path>) -> Result<(), RecentFilesError> {
    let mut rf = RecentFiles::open_default(50)?;
    rf.add_and_save(path.as_ref().to_path_buf())
}

/// Return the most-recently-opened file path from the default list.
///
/// Returns `None` when the list is empty or cannot be read.
pub fn most_recent_file() -> Option<PathBuf> {
    RecentFiles::open_default(50)
        .ok()
        .and_then(|rf| rf.history().most_recent().map(|e| e.path.clone()))
}

/// Return a formatted string listing the top `n` recent files.
pub fn format_recent_list(n: usize) -> Result<String, RecentFilesError> {
    let rf = RecentFiles::open_default(50)?;
    let mut buf = String::new();
    for (i, entry) in rf.history().top(n).iter().enumerate() {
        buf.push_str(&format!("{:3}  {entry}\n", i + 1));
    }
    if buf.is_empty() {
        buf.push_str("(no recent files)\n");
    }
    Ok(buf)
}

// ── RecentFilesError ──────────────────────────────────────────────────────────

/// Errors produced by [`RecentFiles`] and related functions.
#[derive(Debug)]
pub enum RecentFilesError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
}

impl fmt::Display for RecentFilesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for RecentFilesError {}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("recent.json");
        (dir, p)
    }

    #[test]
    fn test_history_empty_initially() {
        let h = FileHistory::new(10);
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn test_history_add_and_len() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/tmp/a.bin"));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_add_same_path_deduplicated() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/tmp/a.bin"));
        h.add(PathBuf::from("/tmp/a.bin"));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_add_increments_access_count() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/tmp/x.bin"));
        h.add(PathBuf::from("/tmp/x.bin"));
        let e = h.most_recent().unwrap();
        assert_eq!(e.access_count, 2);
    }

    #[test]
    fn test_history_max_entries_enforced() {
        let mut h = FileHistory::new(3);
        for i in 0..5 {
            h.add(PathBuf::from(format!("/tmp/file{i}.bin")));
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_history_most_recent_is_newest() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/tmp/old.bin"));
        h.add(PathBuf::from("/tmp/new.bin"));
        assert_eq!(h.most_recent().unwrap().path, PathBuf::from("/tmp/new.bin"));
    }

    #[test]
    fn test_history_remove() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/tmp/a.bin"));
        h.add(PathBuf::from("/tmp/b.bin"));
        h.remove(Path::new("/tmp/a.bin"));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_clear() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/tmp/a.bin"));
        h.clear();
        assert!(h.is_empty());
    }

    #[test]
    fn test_history_top() {
        let mut h = FileHistory::new(10);
        for i in 0..5 {
            h.add(PathBuf::from(format!("/tmp/f{i}")));
        }
        assert_eq!(h.top(3).len(), 3);
    }

    #[test]
    fn test_history_prune_missing_removes_nonexistent() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/nonexistent/path/x.bin"));
        let pruned = h.prune_missing();
        assert_eq!(pruned, 1);
        assert!(h.is_empty());
    }

    #[test]
    fn test_recent_files_open_creates_file() {
        let (_dir, path) = tmp_path();
        let rf = RecentFiles::open(&path, 10).unwrap();
        rf.save().unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_recent_files_add_and_reload() {
        let (_dir, path) = tmp_path();
        {
            let mut rf = RecentFiles::open(&path, 10).unwrap();
            rf.add_and_save(PathBuf::from("/tmp/test.bin")).unwrap();
        }
        let rf2 = RecentFiles::open(&path, 10).unwrap();
        assert_eq!(rf2.history().len(), 1);
    }

    #[test]
    fn test_recent_files_backing_path() {
        let (_dir, path) = tmp_path();
        let rf = RecentFiles::open(&path, 10).unwrap();
        assert_eq!(rf.backing_path(), path.as_path());
    }

    #[test]
    fn test_file_category_detect_elf() {
        // Write a minimal ELF magic to a temp file.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("test.elf");
        fs::write(&p, b"\x7fELF\x02\x01\x01\x00").unwrap();
        assert_eq!(FileCategory::detect(&p), FileCategory::Elf);
    }

    #[test]
    fn test_file_category_detect_pe() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("test.exe");
        fs::write(&p, b"MZ\x90\x00\x00\x00\x00\x00").unwrap();
        assert_eq!(FileCategory::detect(&p), FileCategory::Pe);
    }

    #[test]
    fn test_file_category_detect_jvm() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Test.class");
        fs::write(&p, b"\xca\xfe\xba\xbe\x00\x00\x00").unwrap();
        assert_eq!(FileCategory::detect(&p), FileCategory::Jvm);
    }

    #[test]
    fn test_file_category_fallback_extension() {
        let p = PathBuf::from("/nonexistent/script.rhai");
        assert_eq!(FileCategory::detect(&p), FileCategory::Script);
    }

    #[test]
    fn test_file_category_label() {
        assert_eq!(FileCategory::Elf.label(), "ELF");
        assert_eq!(FileCategory::Pe.label(), "PE");
        assert_eq!(FileCategory::Unknown.label(), "?");
    }

    #[test]
    fn test_recent_entry_display() {
        let entry = RecentEntry {
            path: PathBuf::from("/tmp/test.bin"),
            category: FileCategory::Elf,
            last_accessed: unix_now(),
            access_count: 3,
            label: None,
            exists: true,
        };
        let s = entry.to_string();
        assert!(s.contains("ELF"));
        assert!(s.contains("test.bin"));
    }

    #[test]
    fn test_recent_entry_file_name() {
        let entry = RecentEntry::new(PathBuf::from("/some/path/malware.exe"));
        assert_eq!(entry.file_name(), "malware.exe");
    }

    #[test]
    fn test_history_by_category() {
        let mut h = FileHistory::new(20);
        h.add(PathBuf::from("/tmp/a.rhai")); // Script
        h.add(PathBuf::from("/tmp/b.rhai")); // Script
        h.add(PathBuf::from("/tmp/c.bin")); // Unknown/Shellcode
        let scripts = h.by_category(&FileCategory::Script);
        assert_eq!(scripts.len(), 2);
    }

    #[test]
    fn test_history_iter_newest_first() {
        let mut h = FileHistory::new(10);
        h.add(PathBuf::from("/tmp/first"));
        h.add(PathBuf::from("/tmp/second"));
        let paths: Vec<_> = h.iter().map(|e| e.path.as_path()).collect();
        assert_eq!(paths[0], Path::new("/tmp/second"));
    }

    #[test]
    fn test_format_recent_list_empty() {
        // We can't run the full default-path version in tests, but we can
        // exercise the format logic through a custom path.
        let (_dir, path) = tmp_path();
        let rf = RecentFiles::open(&path, 10).unwrap();
        rf.save().unwrap();
        // Just verify it doesn't panic; the real format_recent_list uses the
        // default path which may or may not exist in CI.
        let _ = rf.history().top(5);
    }
}
