//! Virtual file system for sandbox environments.
//!
//! Provides an in-memory VFS that intercepts guest file operations,
//! records accesses, optionally redirects paths, and enforces access policies.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::{bail, Result};

// ---------------------------------------------------------------------------
// Access control
// ---------------------------------------------------------------------------

/// Permission bits for virtual file system entries (stored as a Unix mode `u16`).
///
/// Bit layout (lower 9 bits, same as POSIX `st_mode & 0o777`):
/// `0o400`=`owner_read`, `0o200`=`owner_write`, `0o100`=`owner_exec`,
/// `0o040`=`group_read`, `0o020`=`group_write`, `0o010`=`group_exec`,
/// `0o004`=`other_read`, `0o002`=`other_write`, `0o001`=`other_exec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VfsPermissions {
    /// Unix mode bits (lower 9 bits = rwxrwxrwx).
    pub bits: u16,
}

impl VfsPermissions {
    /// Construct from raw Unix mode bits.
    #[must_use]
    pub const fn from_mode(bits: u16) -> Self { Self { bits } }

    // ── Individual bit accessors ──────────────────────────────────────────
    #[must_use] pub const fn owner_read(&self)  -> bool { self.bits & 0o400 != 0 }
    #[must_use] pub const fn owner_write(&self) -> bool { self.bits & 0o200 != 0 }
    #[must_use] pub const fn owner_exec(&self)  -> bool { self.bits & 0o100 != 0 }
    #[must_use] pub const fn group_read(&self)  -> bool { self.bits & 0o040 != 0 }
    #[must_use] pub const fn group_write(&self) -> bool { self.bits & 0o020 != 0 }
    #[must_use] pub const fn group_exec(&self)  -> bool { self.bits & 0o010 != 0 }
    #[must_use] pub const fn other_read(&self)  -> bool { self.bits & 0o004 != 0 }
    #[must_use] pub const fn other_write(&self) -> bool { self.bits & 0o002 != 0 }
    #[must_use] pub const fn other_exec(&self)  -> bool { self.bits & 0o001 != 0 }

    /// Owner read/write, no execute; group/other read-only (`0o644`).
    #[must_use]
    pub const fn regular_file() -> Self { Self::from_mode(0o644) }

    /// Owner rwx, group/other r-x (`0o755`).
    #[must_use]
    pub const fn executable() -> Self { Self::from_mode(0o755) }

    /// Directory default rwxr-xr-x (`0o755`).
    #[must_use]
    pub const fn directory() -> Self { Self::from_mode(0o755) }

    /// No permissions (`0o000`).
    #[must_use]
    pub const fn none() -> Self { Self::from_mode(0o000) }

    #[must_use] pub const fn can_read(&self)  -> bool { self.owner_read() }
    #[must_use] pub const fn can_write(&self) -> bool { self.owner_write() }
    #[must_use] pub const fn can_exec(&self)  -> bool { self.owner_exec() }

    /// Unix mode bits as a `u16`.
    #[must_use]
    pub const fn unix_mode(&self) -> u16 { self.bits }
}

// ---------------------------------------------------------------------------
// VirtualFile
// ---------------------------------------------------------------------------

/// A virtual file stored in the VFS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualFile {
    /// Absolute path within the VFS.
    pub path: PathBuf,
    /// File content.
    pub content: Vec<u8>,
    /// File permissions.
    pub permissions: VfsPermissions,
    /// UNIX timestamp of creation.
    pub created_at: u64,
    /// UNIX timestamp of last modification.
    pub modified_at: u64,
    /// UNIX timestamp of last access.
    pub accessed_at: u64,
    /// Whether this file is a symlink.
    pub is_symlink: bool,
    /// If symlink, the target path.
    pub symlink_target: Option<PathBuf>,
    /// User-defined tags.
    pub tags: Vec<String>,
}

impl VirtualFile {
    /// Create a new regular virtual file with given content.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, content: Vec<u8>) -> Self {
        let now = current_timestamp();
        Self {
            path: path.into(),
            content,
            permissions: VfsPermissions::regular_file(),
            created_at:  now,
            modified_at: now,
            accessed_at: now,
            is_symlink:  false,
            symlink_target: None,
            tags: Vec::new(),
        }
    }

    /// Create a symlink entry.
    #[must_use]
    pub fn symlink(path: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        let now = current_timestamp();
        Self {
            path: path.into(),
            content: Vec::new(),
            permissions: VfsPermissions::regular_file(),
            created_at: now,
            modified_at: now,
            accessed_at: now,
            is_symlink: true,
            symlink_target: Some(target.into()),
            tags: Vec::new(),
        }
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> usize { self.content.len() }

    /// Return `true` if the file is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool { self.permissions.can_exec() }

    /// Touch the modification timestamp.
    pub fn touch_modified(&mut self) { self.modified_at = current_timestamp(); }

    /// Touch the access timestamp.
    pub fn touch_accessed(&mut self) { self.accessed_at = current_timestamp(); }
}

// ---------------------------------------------------------------------------
// VirtualDir
// ---------------------------------------------------------------------------

/// A virtual directory entry in the VFS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualDir {
    /// Absolute path within the VFS.
    pub path: PathBuf,
    /// Directory permissions.
    pub permissions: VfsPermissions,
    /// UNIX timestamp of creation.
    pub created_at: u64,
    /// Children (relative names of files and subdirectories).
    pub children: Vec<String>,
    /// User-defined tags.
    pub tags: Vec<String>,
}

impl VirtualDir {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            permissions: VfsPermissions::directory(),
            created_at: current_timestamp(),
            children: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Add a child entry by name.
    pub fn add_child(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.children.contains(&name) {
            self.children.push(name);
        }
    }

    /// Remove a child entry by name.
    pub fn remove_child(&mut self, name: &str) -> bool {
        if let Some(pos) = self.children.iter().position(|n| n == name) {
            self.children.remove(pos);
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// File access log
// ---------------------------------------------------------------------------

/// The kind of file operation recorded in the access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOp {
    Open,
    Read,
    Write,
    Delete,
    Stat,
    Rename,
    Chmod,
    Mkdir,
    Rmdir,
    Symlink,
    Readdir,
}

/// A single file access record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessRecord {
    pub timestamp: u64,
    pub pid: Option<u32>,
    pub op: FileOp,
    pub path: PathBuf,
    pub bytes: Option<usize>,
    pub result: AccessResult,
}

/// The result of a file access attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessResult {
    Success,
    Denied,
    NotFound,
    Error,
}

// ---------------------------------------------------------------------------
// FileInterceptor
// ---------------------------------------------------------------------------

/// Decides what to do when a file operation is intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterceptAction {
    /// Allow the operation.
    Allow,
    /// Deny the operation and return an error.
    Deny,
    /// Redirect to a different path (the actual path is stored separately).
    Redirect,
    /// Shadow-copy: allow read from the real VFS, capture writes separately.
    Shadow,
}

/// A rule that intercepts file operations matching a path prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    /// Path prefix to match.
    pub prefix: PathBuf,
    /// Operations to intercept (empty = all).
    pub ops: Vec<FileOp>,
    /// Action to take.
    pub action: InterceptAction,
    /// Redirect target path (only relevant when `action == Redirect`).
    pub redirect_to: Option<PathBuf>,
    /// Priority (higher wins).
    pub priority: i32,
}

impl InterceptRule {
    #[must_use]
    pub fn new(
        prefix: impl Into<PathBuf>,
        action: InterceptAction,
    ) -> Self {
        Self {
            prefix: prefix.into(),
            ops: Vec::new(),
            action,
            redirect_to: None,
            priority: 0,
        }
    }

    #[must_use]
    pub fn for_ops(mut self, ops: Vec<FileOp>) -> Self { self.ops = ops; self }
    #[must_use]
    pub const fn with_priority(mut self, p: i32) -> Self { self.priority = p; self }
    #[must_use]
    pub fn redirect_to(mut self, path: impl Into<PathBuf>) -> Self {
        self.action = InterceptAction::Redirect;
        self.redirect_to = Some(path.into());
        self
    }

    fn matches_path(&self, path: &Path) -> bool {
        path.starts_with(&self.prefix)
    }

    fn matches_op(&self, op: FileOp) -> bool {
        self.ops.is_empty() || self.ops.contains(&op)
    }

    fn matches(&self, path: &Path, op: FileOp) -> bool {
        self.matches_path(path) && self.matches_op(op)
    }
}

/// Evaluates intercept rules and records file accesses.
pub struct FileInterceptor {
    rules: Vec<InterceptRule>,
    log: Vec<FileAccessRecord>,
}

impl FileInterceptor {
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new(), log: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: InterceptRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Evaluate rules for a (path, op) pair.
    #[must_use] 
    pub fn evaluate(&self, path: &Path, op: FileOp) -> (InterceptAction, Option<PathBuf>) {
        for rule in &self.rules {
            if rule.matches(path, op) {
                return (rule.action, rule.redirect_to.clone());
            }
        }
        (InterceptAction::Allow, None)
    }

    /// Record a file access.
    pub fn record(&mut self, pid: Option<u32>, op: FileOp, path: PathBuf, bytes: Option<usize>, result: AccessResult) {
        self.log.push(FileAccessRecord {
            timestamp: current_timestamp(),
            pid,
            op,
            path,
            bytes,
            result,
        });
    }

    /// Return all records for a given path.
    #[must_use]
    pub fn records_for_path(&self, path: &Path) -> Vec<&FileAccessRecord> {
        self.log.iter().filter(|r| r.path == path).collect()
    }

    /// Return all denied access records.
    #[must_use]
    pub fn denied_records(&self) -> Vec<&FileAccessRecord> {
        self.log.iter().filter(|r| r.result == AccessResult::Denied).collect()
    }

    /// Return all write records.
    #[must_use]
    pub fn write_records(&self) -> Vec<&FileAccessRecord> {
        self.log.iter().filter(|r| r.op == FileOp::Write).collect()
    }

    #[must_use]
    pub fn all_records(&self) -> &[FileAccessRecord] {
        &self.log
    }

    #[must_use]
    pub const fn record_count(&self) -> usize { self.log.len() }
}

impl Default for FileInterceptor {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// VmFileSystem
// ---------------------------------------------------------------------------

/// An in-memory virtual file system for sandbox VM environments.
///
/// Stores files and directories, resolves symlinks, applies intercept rules,
/// and records all guest file accesses.
pub struct VmFileSystem {
    files: RwLock<HashMap<PathBuf, VirtualFile>>,
    dirs:  RwLock<HashMap<PathBuf, VirtualDir>>,
    interceptor: RwLock<FileInterceptor>,
    read_only: bool,
}

impl VmFileSystem {
    /// Create an empty, writable VFS.
    #[must_use]
    pub fn new() -> Self {
        let mut vfs = Self {
            files: RwLock::new(HashMap::new()),
            dirs:  RwLock::new(HashMap::new()),
            interceptor: RwLock::new(FileInterceptor::new()),
            read_only: false,
        };
        // Create root.
        vfs.dirs.write().insert(PathBuf::from("/"), VirtualDir::new("/"));
        // Explicit writable mode (uses `&mut self`).
        vfs.set_read_only(false);
        vfs
    }

    /// Set the writable / read-only flag. `&mut self` so callers can flip
    /// the mode at construction time without going through a `RwLock`.
    pub const fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    /// Wrap this VFS in an `Arc` so it can be shared across sandbox handlers.
    #[must_use]
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Create a read-only VFS snapshot.
    #[must_use] 
    pub fn new_readonly() -> Self {
        let mut vfs = Self::new();
        vfs.read_only = true;
        vfs
    }

    // -----------------------------------------------------------------------
    // Intercept rules
    // -----------------------------------------------------------------------

    pub fn add_intercept_rule(&self, rule: InterceptRule) {
        self.interceptor.write().add_rule(rule);
    }

    // -----------------------------------------------------------------------
    // Directory operations
    // -----------------------------------------------------------------------

    /// Create a directory (and all intermediate directories).
    ///
    /// # Errors
    /// Returns an error if the path is intercepted with `Deny`, or if an I/O
    /// error occurs during directory creation.
    pub fn mkdir_p(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = normalize_path(path.as_ref());
        let (action, _) = self.interceptor.read().evaluate(&path, FileOp::Mkdir);
        if action == InterceptAction::Deny {
            self.interceptor.write().record(None, FileOp::Mkdir, path, None, AccessResult::Denied);
            bail!("mkdir denied: permission denied");
        }
        {
            let mut dirs = self.dirs.write();
            let mut current = PathBuf::from("/");
            for component in path.components().skip(1) {
                current.push(component);
                dirs.entry(current.clone()).or_insert_with(|| VirtualDir::new(current.clone()));
            }
        }
        self.interceptor.write().record(None, FileOp::Mkdir, path, None, AccessResult::Success);
        Ok(())
    }

    /// List directory entries.
    ///
    /// # Errors
    /// Returns an error if the path is intercepted with `Deny`, or if `path` is not a directory.
    pub fn readdir(&self, path: impl AsRef<Path>) -> Result<Vec<String>> {
        let path = normalize_path(path.as_ref());
        let (action, _) = self.interceptor.read().evaluate(&path, FileOp::Readdir);
        if action == InterceptAction::Deny {
            self.interceptor.write().record(None, FileOp::Readdir, path, None, AccessResult::Denied);
            bail!("readdir denied");
        }
        if !self.dirs.read().contains_key(&path) {
            bail!("not a directory: {}", path.display());
        }
        let dir_entries: Vec<String> = self.dirs.read().keys()
            .filter(|p| p.parent() == Some(&path) && *p != &path)
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        let file_entries: Vec<String> = self.files.read().keys()
            .filter(|p| p.parent() == Some(&path))
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        let mut entries = dir_entries;
        entries.extend(file_entries);
        entries.sort();
        Ok(entries)
    }

    /// Return `true` if path is a known directory.
    #[must_use]
    pub fn is_dir(&self, path: impl AsRef<Path>) -> bool {
        let path = normalize_path(path.as_ref());
        self.dirs.read().contains_key(&path)
    }

    // -----------------------------------------------------------------------
    // File operations
    // -----------------------------------------------------------------------

    /// Write (create or overwrite) a virtual file.
    ///
    /// # Errors
    /// Returns an error if the VFS is read-only, the path is intercepted with `Deny`,
    /// or a parent directory cannot be created.
    pub fn write_file(&self, path: impl AsRef<Path>, content: Vec<u8>) -> Result<()> {
        if self.read_only { bail!("VFS is read-only"); }
        let path = normalize_path(path.as_ref());
        let (action, redirect) = self.interceptor.read().evaluate(&path, FileOp::Write);
        let effective_path = match action {
            InterceptAction::Deny => {
                self.interceptor.write().record(None, FileOp::Write, path, None, AccessResult::Denied);
                bail!("write denied");
            }
            InterceptAction::Redirect => redirect.unwrap_or_else(|| path.clone()),
            _ => path.clone(),
        };

        // Ensure parent directories exist.
        if let Some(parent) = effective_path.parent() {
            self.mkdir_p(parent)?;
        }
        let len = content.len();
        let mut file = VirtualFile::new(effective_path.clone(), content);
        // If file exists, preserve creation time.
        let prior_created = self.files.read().get(&effective_path).map(|f| f.created_at);
        if let Some(ts) = prior_created {
            file.created_at = ts;
        }
        self.files.write().insert(effective_path, file);
        self.interceptor.write().record(None, FileOp::Write, path, Some(len), AccessResult::Success);
        Ok(())
    }

    /// Read a virtual file's content.
    ///
    /// # Errors
    /// Returns an error if the path is intercepted with `Deny`, or if the file does not exist.
    pub fn read_file(&self, path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let path = normalize_path(path.as_ref());
        let (action, redirect) = self.interceptor.read().evaluate(&path, FileOp::Read);
        let effective_path = match action {
            InterceptAction::Deny => {
                self.interceptor.write().record(None, FileOp::Read, path, None, AccessResult::Denied);
                bail!("read denied");
            }
            InterceptAction::Redirect => redirect.unwrap_or_else(|| path.clone()),
            _ => path.clone(),
        };

        // Resolve symlinks (one level).
        let effective_path = self.resolve_symlink(&effective_path);
        let mut files = self.files.write();
        if let Some(f) = files.get_mut(&effective_path) {
            f.touch_accessed();
            let content = f.content.clone();
            let len = content.len();
            self.interceptor.write().record(None, FileOp::Read, path, Some(len), AccessResult::Success);
            Ok(content)
        } else {
            self.interceptor.write().record(None, FileOp::Read, path, None, AccessResult::NotFound);
            bail!("file not found: {}", effective_path.display())
        }
    }

    /// Delete a virtual file.
    ///
    /// # Errors
    /// Returns an error if the VFS is read-only, the path is intercepted with `Deny`,
    /// or the file does not exist.
    pub fn delete_file(&self, path: impl AsRef<Path>) -> Result<()> {
        if self.read_only { bail!("VFS is read-only"); }
        let path = normalize_path(path.as_ref());
        let (action, _) = self.interceptor.read().evaluate(&path, FileOp::Delete);
        if action == InterceptAction::Deny {
            self.interceptor.write().record(None, FileOp::Delete, path, None, AccessResult::Denied);
            bail!("delete denied");
        }
        let removed = self.files.write().remove(&path).is_some();
        let result = if removed { AccessResult::Success } else { AccessResult::NotFound };
        self.interceptor.write().record(None, FileOp::Delete, path, None, result);
        if !removed { bail!("file not found"); }
        Ok(())
    }

    /// Rename/move a file.
    ///
    /// # Errors
    /// Returns an error if the VFS is read-only, or if the source file does not exist.
    pub fn rename_file(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
        if self.read_only { bail!("VFS is read-only"); }
        let from = normalize_path(from.as_ref());
        let to   = normalize_path(to.as_ref());
        let mut f = self.files.write().remove(&from)
            .ok_or_else(|| anyhow::anyhow!("file not found: {}", from.display()))?;
        f.path = to.clone();
        f.touch_modified();
        self.files.write().insert(to, f);
        Ok(())
    }

    /// Return file metadata (stat-like).
    ///
    /// # Errors
    /// Returns an error if the path is intercepted with `Deny`, or if the path does not exist.
    pub fn stat(&self, path: impl AsRef<Path>) -> Result<FileStat> {
        let path = normalize_path(path.as_ref());
        let (action, _) = self.interceptor.read().evaluate(&path, FileOp::Stat);
        if action == InterceptAction::Deny {
            self.interceptor.write().record(None, FileOp::Stat, path, None, AccessResult::Denied);
            bail!("stat denied");
        }
        if let Some(f) = self.files.read().get(&path) {
            return Ok(FileStat {
                path: f.path.clone(),
                size: u64::try_from(f.size()).unwrap_or(u64::MAX),
                is_dir: false,
                is_symlink: f.is_symlink,
                permissions: f.permissions,
                created_at: f.created_at,
                modified_at: f.modified_at,
            });
        }
        if let Some(d) = self.dirs.read().get(&path) {
            return Ok(FileStat {
                path: d.path.clone(),
                size: 0,
                is_dir: true,
                is_symlink: false,
                permissions: d.permissions,
                created_at: d.created_at,
                modified_at: d.created_at,
            });
        }
        bail!("not found: {}", path.display())
    }

    /// Return `true` if path exists (file or directory).
    #[must_use]
    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        let path = normalize_path(path.as_ref());
        self.files.read().contains_key(&path) || self.dirs.read().contains_key(&path)
    }

    /// Create a symlink.
    ///
    /// # Errors
    /// Returns an error if the VFS is read-only.
    pub fn symlink(&self, link: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<()> {
        if self.read_only { bail!("VFS is read-only"); }
        let link   = normalize_path(link.as_ref());
        let target = normalize_path(target.as_ref());
        let f = VirtualFile::symlink(link.clone(), target);
        self.files.write().insert(link, f);
        Ok(())
    }

    /// Return the total number of files in the VFS.
    #[must_use]
    pub fn file_count(&self) -> usize { self.files.read().len() }

    /// Return the total number of directories in the VFS.
    #[must_use]
    pub fn dir_count(&self) -> usize { self.dirs.read().len() }

    /// Return all file paths.
    #[must_use]
    pub fn all_file_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self.files.read().keys().cloned().collect();
        paths.sort();
        paths
    }

    /// Snapshot all files as a list of (path, content) pairs.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>)> {
        self.files.read().iter()
            .map(|(p, f)| (p.clone(), f.content.clone()))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Intercept log
    // -----------------------------------------------------------------------

    /// Return all recorded file access records.
    #[must_use]
    pub fn access_log(&self) -> Vec<FileAccessRecord> {
        self.interceptor.read().all_records().to_vec()
    }

    /// Return write records (files written by the guest).
    #[must_use]
    pub fn written_files(&self) -> Vec<PathBuf> {
        self.interceptor.read()
            .write_records()
            .iter()
            .map(|r| r.path.clone())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn resolve_symlink(&self, path: &PathBuf) -> PathBuf {
        let target = self.files.read().get(path)
            .filter(|f| f.is_symlink)
            .and_then(|f| f.symlink_target.clone());
        target.unwrap_or_else(|| path.clone())
    }
}

impl Default for VmFileSystem {
    fn default() -> Self { Self::new() }
}

/// Stat-like structure for VFS entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStat {
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub permissions: VfsPermissions,
    pub created_at: u64,
    pub modified_at: u64,
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn normalize_path(path: &Path) -> PathBuf {
    // Prepend "/" if relative.
    if path.is_relative() {
        PathBuf::from("/").join(path)
    } else {
        path.to_path_buf()
    }
}

// ---------------------------------------------------------------------------
// Preset VFS layouts
// ---------------------------------------------------------------------------

/// Populate a VFS with a minimal Linux root filesystem skeleton.
///
/// # Errors
/// Propagates errors from [`VmFileSystem::mkdir_p`] or [`VmFileSystem::write_file`].
pub fn linux_root_skeleton(vfs: &VmFileSystem) -> Result<()> {
    for dir in &["/bin", "/etc", "/home", "/lib", "/lib64", "/proc",
                 "/sys", "/tmp", "/usr", "/usr/bin", "/usr/lib",
                 "/var", "/var/log", "/dev"] {
        vfs.mkdir_p(dir)?;
    }
    vfs.write_file("/etc/hostname", b"sandbox".to_vec())?;
    vfs.write_file("/etc/os-release", b"NAME=\"Sandbox\"\nID=sandbox\n".to_vec())?;
    vfs.write_file("/etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n".to_vec())?;
    vfs.write_file("/proc/version", b"Linux version 5.15.0 (sandbox)\n".to_vec())?;
    Ok(())
}

/// Populate a VFS with a minimal Windows-like layout.
///
/// # Errors
/// Propagates errors from [`VmFileSystem::mkdir_p`] or [`VmFileSystem::write_file`].
pub fn windows_root_skeleton(vfs: &VmFileSystem) -> Result<()> {
    for dir in &["/Windows", "/Windows/System32", "/Windows/SysWOW64",
                 "/Users", "/Users/user", "/ProgramFiles", "/Temp"] {
        vfs.mkdir_p(dir)?;
    }
    vfs.write_file("/Windows/System32/kernel32.dll", b"MZ\x00\x00".to_vec())?;
    vfs.write_file("/Windows/System32/ntdll.dll", b"MZ\x00\x00".to_vec())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vfs_write_read_roundtrip() {
        let vfs = VmFileSystem::new();
        vfs.write_file("/tmp/hello.txt", b"hello world".to_vec()).unwrap();
        let content = vfs.read_file("/tmp/hello.txt").unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn vfs_file_not_found() {
        let vfs = VmFileSystem::new();
        assert!(vfs.read_file("/nonexistent").is_err());
    }

    #[test]
    fn vfs_mkdir_and_readdir() {
        let vfs = VmFileSystem::new();
        vfs.mkdir_p("/a/b/c").unwrap();
        assert!(vfs.is_dir("/a/b/c"));
        let entries = vfs.readdir("/a/b").unwrap();
        assert!(entries.contains(&"c".to_string()));
    }

    #[test]
    fn vfs_delete_file() {
        let vfs = VmFileSystem::new();
        vfs.write_file("/tmp/del.txt", b"bye".to_vec()).unwrap();
        assert!(vfs.exists("/tmp/del.txt"));
        vfs.delete_file("/tmp/del.txt").unwrap();
        assert!(!vfs.exists("/tmp/del.txt"));
    }

    #[test]
    fn vfs_rename_file() {
        let vfs = VmFileSystem::new();
        vfs.write_file("/tmp/a.txt", b"data".to_vec()).unwrap();
        vfs.rename_file("/tmp/a.txt", "/tmp/b.txt").unwrap();
        assert!(!vfs.exists("/tmp/a.txt"));
        assert!(vfs.exists("/tmp/b.txt"));
    }

    #[test]
    fn vfs_intercept_deny() {
        let vfs = VmFileSystem::new();
        vfs.add_intercept_rule(
            InterceptRule::new("/etc", InterceptAction::Deny)
                .for_ops(vec![FileOp::Write])
        );
        let result = vfs.write_file("/etc/passwd", b"evil".to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn vfs_access_log_records_writes() {
        let vfs = VmFileSystem::new();
        vfs.write_file("/tmp/log.txt", b"data".to_vec()).unwrap();
        let log = vfs.access_log();
        assert!(!log.is_empty());
        assert!(log.iter().any(|r| r.op == FileOp::Write));
    }

    #[test]
    fn vfs_stat_file() {
        let vfs = VmFileSystem::new();
        vfs.write_file("/tmp/stat.txt", b"hello".to_vec()).unwrap();
        let stat = vfs.stat("/tmp/stat.txt").unwrap();
        assert_eq!(stat.size, 5);
        assert!(!stat.is_dir);
    }

    #[test]
    fn vfs_read_only_rejects_write() {
        let vfs = VmFileSystem::new_readonly();
        assert!(vfs.write_file("/tmp/x.txt", b"x".to_vec()).is_err());
    }

    #[test]
    fn permissions_unix_mode() {
        let p = VfsPermissions::regular_file();
        // owner rw, group r, other r
        assert_eq!(p.unix_mode(), 0o644);
    }

    #[test]
    fn linux_skeleton_creates_etc() {
        let vfs = VmFileSystem::new();
        linux_root_skeleton(&vfs).unwrap();
        assert!(vfs.is_dir("/etc"));
        assert!(vfs.exists("/etc/hostname"));
    }

    #[test]
    fn symlink_resolution() {
        let vfs = VmFileSystem::new();
        vfs.write_file("/real.txt", b"real content".to_vec()).unwrap();
        vfs.symlink("/link.txt", "/real.txt").unwrap();
        let content = vfs.read_file("/link.txt").unwrap();
        assert_eq!(content, b"real content");
    }
}
