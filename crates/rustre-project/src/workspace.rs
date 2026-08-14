//! `workspace.rs` — Multi-project workspace management for RustRE.
//!
//! A [`Workspace`] is the top-level container that manages multiple
//! [`Project`] instances simultaneously, remembers recently opened projects,
//! and serialises workspace state to a `.rustre-workspace` JSON index file.
//!
//! Typical use:
//! ```ignore
//! let mut ws = Workspace::open_or_create("/home/user/my-workspace")?;
//! let project = ws.open_project("/home/user/firmware.elf")?;
//! ws.switch_to(&project_id)?;
//! ws.save_index()?;
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::project_serializer::{
    ProjectSerializer, SerializeOptions, SerializedProject,
};
use crate::{Project, ProjectError};

// ── Constants ─────────────────────────────────────────────────────────────────

pub const WORKSPACE_INDEX_FILE: &str = ".rustre-workspace";
pub const DEFAULT_MAX_RECENT: usize = 20;
pub const DEFAULT_ANALYSIS_DEPTH: u32 = 3;
pub const WORKSPACE_FORMAT_VERSION: u32 = 1;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("project not found in workspace: {0}")]
    ProjectNotFound(String),
    #[error("project already open: {0}")]
    ProjectAlreadyOpen(String),
    #[error("no active project")]
    NoActiveProject,
    #[error("workspace index corrupt: {0}")]
    CorruptIndex(#[source] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("project error: {0}")]
    Project(#[from] ProjectError),
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("archive error: {0}")]
    Archive(String),
}

pub type Result<T> = std::result::Result<T, WorkspaceError>;

// ── WorkspaceMetadata ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMetadata {
    pub name: String,
    pub description: Option<String>,
    pub created_at: u64,
    pub last_opened: u64,
    pub format_version: u32,
    pub author: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl WorkspaceMetadata {
    pub fn new(name: impl Into<String>) -> Self {
        let now = unix_now();
        Self {
            name: name.into(),
            description: None,
            created_at: now,
            last_opened: now,
            format_version: WORKSPACE_FORMAT_VERSION,
            author: None,
            tags: Vec::new(),
        }
    }
}

// ── WorkspaceConfig ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    /// Maximum number of recent projects to keep in the list.
    #[serde(default = "default_max_recent")]
    pub max_recent: usize,
    /// Default analysis depth for recursive call-graph analysis.
    #[serde(default = "default_analysis_depth")]
    pub default_analysis_depth: u32,
    /// Whether to restore open projects on workspace open.
    #[serde(default = "default_true")]
    pub restore_on_open: bool,
    /// Whether to auto-save the workspace index on every project open/close.
    #[serde(default = "default_true")]
    pub auto_save_index: bool,
    /// Per-project overrides: project_path → config key-value pairs.
    #[serde(default)]
    pub project_overrides: HashMap<String, HashMap<String, String>>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            max_recent: DEFAULT_MAX_RECENT,
            default_analysis_depth: DEFAULT_ANALYSIS_DEPTH,
            restore_on_open: true,
            auto_save_index: true,
            project_overrides: HashMap::new(),
        }
    }
}

fn default_max_recent() -> usize {
    DEFAULT_MAX_RECENT
}
fn default_analysis_depth() -> u32 {
    DEFAULT_ANALYSIS_DEPTH
}
fn default_true() -> bool {
    true
}

// ── RecentProject ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentProject {
    /// Canonical path to the project root directory.
    pub path: String,
    /// Human-readable project name.
    pub name: String,
    /// Unix timestamp of last open.
    pub last_opened: u64,
    /// Binary format detected at last open (e.g. "PE", "ELF").
    pub format: Option<String>,
    /// Architecture detected at last open (e.g. "x86_64").
    pub arch: Option<String>,
    /// Whether this project is currently open.
    pub is_pinned: bool,
}

impl RecentProject {
    pub fn new(path: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: name.into(),
            last_opened: unix_now(),
            format: None,
            arch: None,
            is_pinned: false,
        }
    }

    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = Some(arch.into());
        self
    }
    #[must_use] 
     
    pub fn pin(mut self) -> Self {
        self.is_pinned = true;
        self
    }
    pub fn touch(&mut self) {
        self.last_opened = unix_now();
    }
}

// ── WorkspaceIndex ────────────────────────────────────────────────────────────

/// The on-disk representation of workspace state (`.rustre-workspace`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceIndex {
    pub metadata: WorkspaceMetadata,
    pub config: WorkspaceConfig,
    pub recent_projects: Vec<RecentProject>,
    pub active_project_path: Option<String>,
}

impl WorkspaceIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            metadata: WorkspaceMetadata::new(name),
            config: WorkspaceConfig::default(),
            recent_projects: Vec::new(),
            active_project_path: None,
        }
    }

    pub fn to_json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(s: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self.to_json().map_err(WorkspaceError::CorruptIndex)?;
        std::fs::write(path, json).map_err(WorkspaceError::Io)
    }

    pub fn read_from(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(WorkspaceError::Io)?;
        Self::from_json(&raw).map_err(WorkspaceError::CorruptIndex)
    }

    /// Trim recent list to `max_recent`, keeping pinned items and most-recent.
    pub fn trim_recent(&mut self) {
        let max = self.config.max_recent;
        if self.recent_projects.len() <= max {
            return;
        }
        // Keep pinned items plus most-recent unpinned up to max.
        self.recent_projects.sort_by(|a, b| {
            b.is_pinned
                .cmp(&a.is_pinned)
                .then(b.last_opened.cmp(&a.last_opened))
        });
        self.recent_projects.truncate(max);
    }

    /// Add or update a recent project entry.
    pub fn record_open(&mut self, path: &str, name: &str) {
        if let Some(r) = self.recent_projects.iter_mut().find(|r| r.path == path) {
            r.name = name.to_string();
            r.touch();
        } else {
            self.recent_projects.push(RecentProject::new(path, name));
        }
        self.trim_recent();
    }
}

// ── Workspace ─────────────────────────────────────────────────────────────────

/// Multi-project workspace: manages open [`Project`]s and workspace state.
pub struct Workspace {
    /// Root directory of the workspace (where `.rustre-workspace` lives).
    root: PathBuf,
    /// Persisted workspace state.
    index: WorkspaceIndex,
    /// Open projects keyed by canonical path string.
    open_projects: HashMap<String, Arc<Mutex<Project>>>,
    /// The currently active project path (for single-focus workflows).
    active_path: Option<String>,
}

impl Workspace {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create a new workspace at `root` (directory must exist).
    pub fn create(name: impl Into<String>, root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let index = WorkspaceIndex::new(name);
        let ws = Self {
            root: root,
            index,
            open_projects: HashMap::new(),
            active_path: None,
        };
        ws.save_index()?;
        Ok(ws)
    }

    /// Open an existing workspace from `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let index_path = root.join(WORKSPACE_INDEX_FILE);
        let mut index = if index_path.exists() {
            WorkspaceIndex::read_from(&index_path)?
        } else {
            WorkspaceIndex::new("unnamed")
        };
        index.metadata.last_opened = unix_now();
        let active_path = index.active_project_path.clone();
        Ok(Self {
            root,
            index,
            open_projects: HashMap::new(),
            active_path,
        })
    }

    /// Open a workspace if the index file exists; otherwise create a fresh one.
    pub fn open_or_create(name: impl Into<String>, root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let index_path = root.join(WORKSPACE_INDEX_FILE);
        if index_path.exists() {
            Self::open(&root)
        } else {
            Self::create(name, &root)
        }
    }

    // ── Index I/O ─────────────────────────────────────────────────────────────

    /// Persist the workspace index to disk.
    pub fn save_index(&self) -> Result<()> {
        let path = self.root.join(WORKSPACE_INDEX_FILE);
        self.index.write_to(path)
    }

    // ── Project management ────────────────────────────────────────────────────

    /// Open a project at `project_root` and register it in the workspace.
    /// Returns the shared `Arc<Mutex<Project>>`.
    pub fn open_project(&mut self, project_root: impl AsRef<Path>) -> Result<Arc<Mutex<Project>>> {
        let canonical = project_root.as_ref().canonicalize()?;
        let key = canonical.to_string_lossy().into_owned();

        if let Some(existing) = self.open_projects.get(&key) {
            return Ok(Arc::clone(existing));
        }

        let project = Project::open(&canonical)?;
        let name = project.name().to_string();
        let arc = Arc::new(Mutex::new(project));
        self.open_projects.insert(key.clone(), Arc::clone(&arc));
        self.index.record_open(&key, &name);
        if self.active_path.is_none() {
            self.active_path = Some(key.clone());
        }

        if self.index.config.auto_save_index {
            let _ = self.save_index();
        }
        Ok(arc)
    }

    /// Create a new project inside the workspace and open it.
    pub fn create_project(
        &mut self,
        name: &str,
        project_root: impl AsRef<Path>,
    ) -> Result<Arc<Mutex<Project>>> {
        let raw = project_root.as_ref().to_path_buf();
        if let Some(parent) = raw.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::create_dir_all(&raw).ok();
        let canonical = raw.canonicalize().unwrap_or(raw);
        let key = canonical.to_string_lossy().into_owned();

        if self.open_projects.contains_key(&key) {
            return Err(WorkspaceError::ProjectAlreadyOpen(key));
        }

        let project = Project::new(name, &canonical)?;
        let arc = Arc::new(Mutex::new(project));
        self.open_projects.insert(key.clone(), Arc::clone(&arc));
        self.index.record_open(&key, name);
        if self.active_path.is_none() {
            self.active_path = Some(key.clone());
        }

        if self.index.config.auto_save_index {
            let _ = self.save_index();
        }
        Ok(arc)
    }

    /// Close (unload) a project by its canonical path key.
    /// Does NOT delete the project on disk.
    pub fn close_project(&mut self, key: &str) -> Result<bool> {
        if self.open_projects.remove(key).is_none() {
            return Ok(false);
        }
        // If this was the active project, pick the next one.
        if self.active_path.as_deref() == Some(key) {
            self.active_path = self.open_projects.keys().next().cloned();
        }
        if self.index.config.auto_save_index {
            let _ = self.save_index();
        }
        Ok(true)
    }

    /// Switch the active project to the one at `key`.
    pub fn switch_to(&mut self, key: &str) -> Result<Arc<Mutex<Project>>> {
        let arc = self
            .open_projects
            .get(key)
            .ok_or_else(|| WorkspaceError::ProjectNotFound(key.to_string()))?;
        self.active_path = Some(key.to_string());
        Ok(Arc::clone(arc))
    }

    /// Get the currently active project, if any.
    pub fn active_project(&self) -> Option<Arc<Mutex<Project>>> {
        self.active_path
            .as_ref()
            .and_then(|k| self.open_projects.get(k))
            .map(Arc::clone)
    }

    /// Get a project by key.
    pub fn get_project(&self, key: &str) -> Option<Arc<Mutex<Project>>> {
        self.open_projects.get(key).map(Arc::clone)
    }

    // ── Introspection ────────────────────────────────────────────────────────

    #[must_use]
    pub fn open_project_keys(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.open_projects.keys().cloned().collect();
        keys.sort();
        keys
    }

    #[must_use]
    pub fn open_project_count(&self) -> usize {
        self.open_projects.len()
    }

    #[must_use]
    pub fn recent_projects(&self) -> &[RecentProject] {
        &self.index.recent_projects
    }

    #[must_use]
    pub fn metadata(&self) -> &WorkspaceMetadata {
        &self.index.metadata
    }
    pub fn metadata_mut(&mut self) -> &mut WorkspaceMetadata {
        &mut self.index.metadata
    }
    #[must_use]
    pub fn config(&self) -> &WorkspaceConfig {
        &self.index.config
    }
    pub fn config_mut(&mut self) -> &mut WorkspaceConfig {
        &mut self.index.config
    }
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    #[must_use]
    pub fn active_path(&self) -> Option<&str> {
        self.active_path.as_deref()
    }

    // ── Save all ─────────────────────────────────────────────────────────────

    /// Save all open projects and the workspace index.
    #[must_use] 
    pub fn save_all(&self) -> Vec<(String, std::result::Result<(), crate::ProjectError>)> {
        let results = self
            .open_projects
            .iter()
            .map(|(key, arc)| {
                let r = arc
                    .lock()
                    .map_err(|_| crate::ProjectError::LockPoisoned)
                    .and_then(|p| p.save());
                (key.clone(), r)
            })
            .collect();
        let _ = self.save_index();
        results
    }

    // ── Export workspace archive ──────────────────────────────────────────────

    /// Export the workspace index and a manifest of all open project paths to
    /// a single JSON archive file.  Binary data is NOT included; this is a
    /// lightweight "relocate workspace" manifest.
    pub fn export_archive(&self, dest: impl AsRef<Path>) -> Result<()> {
        #[derive(Serialize)]
        struct Archive<'a> {
            index: &'a WorkspaceIndex,
            open_project_keys: Vec<String>,
            exported_at: u64,
        }
        let archive = Archive {
            index: &self.index,
            open_project_keys: self.open_project_keys(),
            exported_at: unix_now(),
        };
        let json = serde_json::to_string_pretty(&archive).map_err(WorkspaceError::CorruptIndex)?;
        std::fs::write(dest, json).map_err(WorkspaceError::Io)
    }

    /// Import a workspace archive, merging recent projects into the current
    /// workspace index.
    pub fn import_archive(&mut self, src: impl AsRef<Path>) -> Result<usize> {
        #[derive(Deserialize)]
        struct Archive {
            index: WorkspaceIndex,
        }
        let raw = std::fs::read_to_string(src).map_err(WorkspaceError::Io)?;
        let archive: Archive = serde_json::from_str(&raw).map_err(WorkspaceError::CorruptIndex)?;
        let mut imported = 0;
        for rp in archive.index.recent_projects {
            // Only add if not already present
            if !self.index.recent_projects.iter().any(|r| r.path == rp.path) {
                self.index.recent_projects.push(rp);
                imported += 1;
            }
        }
        self.index.trim_recent();
        Ok(imported)
    }

    // ── Recent project management ─────────────────────────────────────────────

    /// Manually add a recent project entry (e.g. for a project that was opened
    /// outside this workspace instance).
    pub fn add_recent(&mut self, path: impl Into<String>, name: impl Into<String>) {
        self.index.record_open(&path.into(), &name.into());
    }

    /// Remove a path from the recent list.
    pub fn remove_recent(&mut self, path: &str) -> bool {
        let before = self.index.recent_projects.len();
        self.index.recent_projects.retain(|r| r.path != path);
        self.index.recent_projects.len() != before
    }

    /// Clear all non-pinned recent entries.
    pub fn clear_unpinned_recent(&mut self) {
        self.index.recent_projects.retain(|r| r.is_pinned);
    }

    /// Pin a recent project so it won't be evicted by `trim_recent`.
    pub fn pin_recent(&mut self, path: &str) -> bool {
        if let Some(r) = self
            .index
            .recent_projects
            .iter_mut()
            .find(|r| r.path == path)
        {
            r.is_pinned = true;
            return true;
        }
        false
    }
}

// ── Workspace snapshot (full serialisation) ──────────────────────────────────

/// Current format version for [`WorkspaceSnapshot`].
///
/// Bumped whenever the on-disk JSON layout changes in a non-additive way.
pub const WORKSPACE_SNAPSHOT_VERSION: u32 = 1;

/// A reference to a binary belonging to a project (path + sha256), captured
/// so the snapshot can describe what was loaded without bundling binary
/// payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceBinaryRef {
    /// Project key (canonical path string) the binary lives under.
    pub project_key: String,
    /// SHA-256 of the binary (as stored in the project DB).
    pub sha256: String,
    /// On-disk path of the binary (may not exist on the importing host).
    pub path: String,
    /// Format string, e.g. "ELF" / "PE".
    pub format: String,
    /// Architecture string, e.g. "x86_64".
    pub arch: String,
}

/// Per-project record inside a [`WorkspaceSnapshot`].
///
/// Bundles the full analysis state ([`SerializedProject`]) together with the
/// project key (canonical path string) the snapshot belonged to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceProjectEntry {
    /// Canonical path string of the project root at export time.
    pub project_key: String,
    /// Human-readable project name.
    pub project_name: String,
    /// Was this the active project at export time?
    pub was_active: bool,
    /// Full serialised analysis state for the project.
    pub data: SerializedProject,
}

/// Free-form knowledge snapshot blob bundled with the workspace.
///
/// Used to carry user-provided "knowledge base" data (text, JSON, etc.) that
/// the host application wants to round-trip with the workspace.  Opaque from
/// the workspace's perspective.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnowledgeSnapshot {
    /// Schema or producer tag, e.g. `"rustre-knowledge/v1"`.
    pub schema: Option<String>,
    /// Arbitrary key/value entries.
    pub entries: HashMap<String, String>,
    /// Free-form blobs keyed by filename.
    #[serde(default)]
    pub blobs: HashMap<String, Vec<u8>>,
}

/// The full, self-contained workspace serialisation.
///
/// Captures:
/// - the [`WorkspaceIndex`] (metadata, config, recent list, active project),
/// - every binary reference across the open projects,
/// - the complete analysis state ([`SerializedProject`]) for each open
///   project, including functions / comments / xrefs / symbols / bookmarks /
///   patches / triage / notes / scripts,
/// - an optional [`KnowledgeSnapshot`] for host-application knowledge data,
/// - workspace-wide settings (currently identical to
///   [`WorkspaceConfig`] but represented separately so future-proofing
///   doesn't break the snapshot format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    /// Snapshot format version — see [`WORKSPACE_SNAPSHOT_VERSION`].
    pub format_version: u32,
    /// Unix timestamp of export.
    pub exported_at: u64,
    /// The workspace index (metadata, config, recent projects, active key).
    pub index: WorkspaceIndex,
    /// Per-project full analysis snapshots.
    pub projects: Vec<WorkspaceProjectEntry>,
    /// Flat list of all binary references across all projects.
    pub binary_refs: Vec<WorkspaceBinaryRef>,
    /// Optional knowledge-base snapshot supplied by the host application.
    pub knowledge: Option<KnowledgeSnapshot>,
    /// Workspace-wide settings.
    pub settings: WorkspaceConfig,
}

impl WorkspaceSnapshot {
    /// Serialise to a pretty-printed JSON string.
    pub fn to_json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Parse from a JSON string.
    pub fn from_json(s: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Write the snapshot to a file path as JSON.
    pub fn write_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self
            .to_json()
            .map_err(WorkspaceError::CorruptIndex)?;
        std::fs::write(path, json).map_err(WorkspaceError::Io)
    }

    /// Read a snapshot from a JSON file path.
    pub fn read_from(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(WorkspaceError::Io)?;
        Self::from_json(&raw).map_err(WorkspaceError::CorruptIndex)
    }

    /// Total number of projects in this snapshot.
    #[must_use]
    pub fn project_count(&self) -> usize {
        self.projects.len()
    }

    /// Total number of binary references across all projects.
    #[must_use] 
    pub fn binary_ref_count(&self) -> usize {
        self.binary_refs.len()
    }

    /// Sum of functions across all bundled projects.
    #[must_use] 
    pub fn total_functions(&self) -> usize {
        self.projects.iter().map(|p| p.data.total_functions()).sum()
    }
}

impl Workspace {
    /// Export a full workspace snapshot, including per-project analysis state.
    ///
    /// Walks every currently-open project, runs [`ProjectSerializer`] with
    /// the supplied [`SerializeOptions`] to capture all its analysis data,
    /// builds the flat binary reference list, and packs everything into a
    /// [`WorkspaceSnapshot`] alongside the workspace index and settings.
    ///
    /// `knowledge` is an optional host-supplied blob to bundle.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::LockPoisoned`] if any open project lock is
    /// poisoned, [`WorkspaceError::Project`] if a project query fails.
    pub fn build_snapshot(
        &self,
        options: SerializeOptions,
        knowledge: Option<KnowledgeSnapshot>,
    ) -> Result<WorkspaceSnapshot> {
        let mut projects: Vec<WorkspaceProjectEntry> = Vec::with_capacity(self.open_projects.len());
        let mut binary_refs: Vec<WorkspaceBinaryRef> = Vec::new();

        for (key, arc) in &self.open_projects {
            let guard = arc.lock().map_err(|_| WorkspaceError::LockPoisoned)?;
            let data = ProjectSerializer::new(&guard, options.clone()).serialize()?;

            for bin in &data.binaries {
                binary_refs.push(WorkspaceBinaryRef {
                    project_key: key.clone(),
                    sha256: bin.entry.sha256.clone(),
                    path: bin.entry.path.clone(),
                    format: bin.entry.format.clone(),
                    arch: bin.entry.arch.clone(),
                });
            }

            let was_active = self.active_path.as_deref() == Some(key.as_str());
            projects.push(WorkspaceProjectEntry {
                project_key: key.clone(),
                project_name: guard.name().to_owned(),
                was_active,
                data,
            });
        }

        Ok(WorkspaceSnapshot {
            format_version: WORKSPACE_SNAPSHOT_VERSION,
            exported_at: unix_now(),
            index: self.index.clone(),
            projects,
            binary_refs,
            knowledge,
            settings: self.index.config.clone(),
        })
    }

    /// Export a full workspace snapshot to `dest` as a single JSON file.
    ///
    /// Convenience wrapper around [`Workspace::build_snapshot`].
    pub fn export_snapshot(
        &self,
        dest: impl AsRef<Path>,
        options: SerializeOptions,
        knowledge: Option<KnowledgeSnapshot>,
    ) -> Result<WorkspaceSnapshot> {
        let snap = self.build_snapshot(options, knowledge)?;
        snap.write_to(dest)?;
        Ok(snap)
    }

    /// Import a previously-exported [`WorkspaceSnapshot`].
    ///
    /// Behaviour:
    /// - Workspace metadata is merged: description / tags from the snapshot
    ///   take precedence only when the current workspace metadata is empty.
    /// - Workspace [`WorkspaceConfig`] (`settings`) is replaced.
    /// - Recent-projects are merged (no duplicates by path).
    /// - For each project in the snapshot whose project_key directory exists
    ///   on disk, the project is opened (or created if missing) and its
    ///   analysis state is replayed via the public DB writer API
    ///   (functions / comments / xrefs / symbols / bookmarks / patches /
    ///   triage / notes / scripts).
    /// - The active project is restored if one of the imported projects was
    ///   marked active at export time.
    /// - The optional knowledge blob is returned to the caller — the
    ///   workspace itself has no opinion on how to persist it.
    ///
    /// Returns a [`WorkspaceImportReport`] describing what was imported.
    pub fn import_snapshot(
        &mut self,
        snapshot: WorkspaceSnapshot,
    ) -> Result<WorkspaceImportReport> {
        // ── Settings ──
        self.index.config = snapshot.settings.clone();

        // ── Metadata merge ──
        if self.index.metadata.description.is_none() {
            self.index.metadata.description = snapshot.index.metadata.description.clone();
        }
        if self.index.metadata.author.is_none() {
            self.index.metadata.author = snapshot.index.metadata.author.clone();
        }
        for tag in &snapshot.index.metadata.tags {
            if !self.index.metadata.tags.contains(tag) {
                self.index.metadata.tags.push(tag.clone());
            }
        }

        // ── Recent projects ──
        let mut merged_recent = 0usize;
        for rp in &snapshot.index.recent_projects {
            if !self.index.recent_projects.iter().any(|r| r.path == rp.path) {
                self.index.recent_projects.push(rp.clone());
                merged_recent += 1;
            }
        }
        self.index.trim_recent();

        // ── Per-project replay ──
        let mut imported_projects = 0usize;
        let mut skipped_projects: Vec<String> = Vec::new();
        let mut total_functions = 0usize;
        let mut total_xrefs = 0usize;
        let mut total_symbols = 0usize;
        let mut total_bookmarks = 0usize;
        let mut total_patches = 0usize;
        let mut total_triage = 0usize;
        let mut total_notes = 0usize;
        let mut total_scripts = 0usize;
        let mut new_active: Option<String> = None;

        for entry in snapshot.projects {
            let project_path = Path::new(&entry.project_key);
            // The project directory must exist (or be creatable) on the
            // importing host.  Skip otherwise.
            if !project_path.exists() {
                skipped_projects.push(entry.project_key.clone());
                continue;
            }

            // Open the project if a DB already exists, otherwise create a new
            // one at that path so we have somewhere to replay the analysis.
            let project_arc = match self.open_project(project_path) {
                Ok(a) => a,
                Err(_) => self.create_project(&entry.project_name, project_path)?,
            };

            {
                let project = project_arc
                    .lock()
                    .map_err(|_| WorkspaceError::LockPoisoned)?;

                for bin in &entry.data.binaries {
                    // Register the binary by re-adding from its on-disk path
                    // when possible; otherwise we still need an id under
                    // which to replay annotations.  We fall back to looking
                    // up an existing binary by sha256.
                    let bin_path = Path::new(&bin.entry.path);
                    let added = if bin_path.exists() {
                        project.add_binary_from_path(bin_path).ok()
                    } else {
                        None
                    };
                    let resolved_id: Option<u64> = if let Some(b) = added {
                        Some(b.id)
                    } else {
                        project
                            .list_binaries()
                            .into_iter()
                            .find(|b| b.sha256 == bin.entry.sha256)
                            .map(|b| b.id)
                    };

                    let Some(binary_id) = resolved_id else {
                        continue;
                    };

                    for f in &bin.functions {
                        if project
                            .add_function_record(binary_id, f.addr, &f.name)
                            .is_ok()
                        {
                            total_functions += 1;
                        }
                    }
                    for c in &bin.comments {
                        if project
                            .add_comment_record(binary_id, c.addr, &c.body)
                            .is_ok()
                        {
                            // counted via comment replay; tracked implicitly
                        }
                    }
                    for x in &bin.xrefs {
                        if project
                            .add_xref_record(binary_id, x.from_addr, x.to_addr, &x.kind)
                            .is_ok()
                        {
                            total_xrefs += 1;
                        }
                    }
                    for s in &bin.symbols {
                        if project
                            .add_symbol(binary_id, s.addr, &s.name, &s.symbol_type, &s.source)
                            .is_ok()
                        {
                            total_symbols += 1;
                        }
                    }
                    for b in &bin.bookmarks {
                        if project
                            .add_bookmark(binary_id, b.addr, &b.label, &b.color)
                            .is_ok()
                        {
                            total_bookmarks += 1;
                        }
                    }
                    for p in &bin.patches {
                        if project
                            .add_patch(
                                binary_id,
                                p.addr,
                                &p.original_bytes,
                                &p.patched_bytes,
                                &p.description,
                            )
                            .is_ok()
                        {
                            total_patches += 1;
                        }
                    }
                    for t in &bin.triage {
                        if project
                            .upsert_triage_result(
                                binary_id, &t.scanner, &t.verdict, t.score, &t.details,
                            )
                            .is_ok()
                        {
                            total_triage += 1;
                        }
                    }
                }

                for n in &entry.data.notes {
                    if project.save_note(&n.title, &n.body).is_ok() {
                        total_notes += 1;
                    }
                }
                for s in &entry.data.scripts {
                    if project.save_script(&s.name, &s.language, &s.body).is_ok() {
                        total_scripts += 1;
                    }
                }
            }

            if entry.was_active {
                new_active = Some(entry.project_key.clone());
            }
            imported_projects += 1;
        }

        if let Some(k) = new_active
            && self.open_projects.contains_key(&k) {
                self.active_path = Some(k);
            }

        if self.index.config.auto_save_index {
            let _ = self.save_index();
        }

        Ok(WorkspaceImportReport {
            format_version: snapshot.format_version,
            imported_projects,
            skipped_projects,
            merged_recent_entries: merged_recent,
            binary_refs_in_snapshot: snapshot.binary_refs.len(),
            total_functions,
            total_xrefs,
            total_symbols,
            total_bookmarks,
            total_patches,
            total_triage,
            total_notes,
            total_scripts,
            knowledge: snapshot.knowledge,
        })
    }

    /// Read a workspace snapshot from `src` and import it.
    pub fn import_snapshot_from(
        &mut self,
        src: impl AsRef<Path>,
    ) -> Result<WorkspaceImportReport> {
        let snap = WorkspaceSnapshot::read_from(src)?;
        self.import_snapshot(snap)
    }
}

/// Summary of an [`Workspace::import_snapshot`] call.
#[derive(Debug, Clone)]
pub struct WorkspaceImportReport {
    /// Snapshot format version that was imported.
    pub format_version: u32,
    /// Number of projects whose data was replayed.
    pub imported_projects: usize,
    /// Project keys that were skipped because the project directory did not
    /// exist on the importing host.
    pub skipped_projects: Vec<String>,
    /// Number of recent-project entries that were merged in.
    pub merged_recent_entries: usize,
    /// Number of binary references the snapshot contained.
    pub binary_refs_in_snapshot: usize,
    pub total_functions: usize,
    pub total_xrefs: usize,
    pub total_symbols: usize,
    pub total_bookmarks: usize,
    pub total_patches: usize,
    pub total_triage: usize,
    pub total_notes: usize,
    pub total_scripts: usize,
    /// The knowledge blob carried by the snapshot, if any — caller decides
    /// how to persist it.
    pub knowledge: Option<KnowledgeSnapshot>,
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // ── WorkspaceMetadata ─────────────────────────────────────────────────────

    #[test]
    fn metadata_name() {
        let m = WorkspaceMetadata::new("ws");
        assert_eq!(m.name, "ws");
    }
    #[test]
    fn metadata_format_version() {
        assert_eq!(
            WorkspaceMetadata::new("x").format_version,
            WORKSPACE_FORMAT_VERSION
        );
    }
    #[test]
    fn metadata_created_nonzero() {
        assert!(WorkspaceMetadata::new("x").created_at > 0);
    }

    // ── WorkspaceConfig ───────────────────────────────────────────────────────

    #[test]
    fn config_max_recent() {
        assert_eq!(WorkspaceConfig::default().max_recent, DEFAULT_MAX_RECENT);
    }
    #[test]
    fn config_depth() {
        assert_eq!(
            WorkspaceConfig::default().default_analysis_depth,
            DEFAULT_ANALYSIS_DEPTH
        );
    }
    #[test]
    fn config_restore_on_open() {
        assert!(WorkspaceConfig::default().restore_on_open);
    }

    // ── RecentProject ─────────────────────────────────────────────────────────

    #[test]
    fn recent_project_new() {
        let r = RecentProject::new("/tmp/p", "myp");
        assert_eq!(r.path, "/tmp/p");
        assert_eq!(r.name, "myp");
    }
    #[test]
    fn recent_project_builders() {
        let r = RecentProject::new("/p", "n")
            .with_format("ELF")
            .with_arch("x86_64")
            .pin();
        assert_eq!(r.format.as_deref(), Some("ELF"));
        assert_eq!(r.arch.as_deref(), Some("x86_64"));
        assert!(r.is_pinned);
    }
    #[test]
    fn recent_project_touch() {
        let mut r = RecentProject::new("/p", "n");
        let old = r.last_opened;
        r.touch();
        assert!(r.last_opened >= old);
    }

    // ── WorkspaceIndex ────────────────────────────────────────────────────────

    #[test]
    fn index_json_roundtrip() {
        let mut idx = WorkspaceIndex::new("test-ws");
        idx.recent_projects.push(RecentProject::new("/a/b", "b"));
        let json = idx.to_json().unwrap();
        let idx2 = WorkspaceIndex::from_json(&json).unwrap();
        assert_eq!(idx2.metadata.name, "test-ws");
        assert_eq!(idx2.recent_projects.len(), 1);
    }
    #[test]
    fn index_trim_recent() {
        let mut idx = WorkspaceIndex::new("ws");
        idx.config.max_recent = 3;
        for i in 0..5u32 {
            idx.recent_projects
                .push(RecentProject::new(format!("/p/{i}"), format!("p{i}")));
        }
        idx.trim_recent();
        assert_eq!(idx.recent_projects.len(), 3);
    }
    #[test]
    fn index_trim_keeps_pinned() {
        let mut idx = WorkspaceIndex::new("ws");
        idx.config.max_recent = 2;
        idx.recent_projects
            .push(RecentProject::new("/pin", "pinned").pin());
        for i in 0..3u32 {
            idx.recent_projects
                .push(RecentProject::new(format!("/p/{i}"), format!("{i}")));
        }
        idx.trim_recent();
        assert!(idx.recent_projects.iter().any(|r| r.path == "/pin"));
    }
    #[test]
    fn index_record_open_dedup() {
        let mut idx = WorkspaceIndex::new("ws");
        idx.record_open("/p", "name");
        idx.record_open("/p", "name2");
        assert_eq!(idx.recent_projects.len(), 1);
        assert_eq!(idx.recent_projects[0].name, "name2");
    }
    #[test]
    fn index_write_read() {
        let d = tmp();
        let path = d.path().join("idx.json");
        let idx = WorkspaceIndex::new("persist");
        idx.write_to(&path).unwrap();
        let idx2 = WorkspaceIndex::read_from(&path).unwrap();
        assert_eq!(idx2.metadata.name, "persist");
    }

    // ── Workspace::create ─────────────────────────────────────────────────────

    #[test]
    fn workspace_create() {
        let d = tmp();
        let ws = Workspace::create("test-ws", d.path()).unwrap();
        assert!(d.path().join(WORKSPACE_INDEX_FILE).exists());
        assert_eq!(ws.metadata().name, "test-ws");
    }
    #[test]
    fn workspace_open_after_create() {
        let d = tmp();
        Workspace::create("test-ws", d.path()).unwrap();
        let ws2 = Workspace::open(d.path()).unwrap();
        assert_eq!(ws2.metadata().name, "test-ws");
    }
    #[test]
    fn workspace_open_or_create_no_index() {
        let d = tmp();
        let ws = Workspace::open_or_create("new", d.path()).unwrap();
        assert_eq!(ws.metadata().name, "new");
    }
    #[test]
    fn workspace_open_or_create_existing() {
        let d = tmp();
        Workspace::create("existing", d.path()).unwrap();
        let ws = Workspace::open_or_create("ignored", d.path()).unwrap();
        assert_eq!(ws.metadata().name, "existing");
    }

    // ── Project management ────────────────────────────────────────────────────

    #[test]
    fn workspace_create_and_open_project() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let proj_dir = d.path().join("project1");
        std::fs::create_dir_all(&proj_dir).unwrap();
        let _arc = ws.create_project("proj1", &proj_dir).unwrap();
        assert_eq!(ws.open_project_count(), 1);
    }
    #[test]
    fn workspace_open_project() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let proj_dir = d.path().join("proj");
        std::fs::create_dir_all(&proj_dir).unwrap();
        // Create project first then open it via workspace
        Project::new("p", &proj_dir).unwrap();
        let _arc = ws.open_project(&proj_dir).unwrap();
        assert_eq!(ws.open_project_count(), 1);
    }
    #[test]
    fn workspace_open_project_twice_same_arc() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let proj_dir = d.path().join("p2");
        std::fs::create_dir_all(&proj_dir).unwrap();
        Project::new("p", &proj_dir).unwrap();
        let a = ws.open_project(&proj_dir).unwrap();
        let b = ws.open_project(&proj_dir).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }
    #[test]
    fn workspace_close_project() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let proj_dir = d.path().join("p3");
        std::fs::create_dir_all(&proj_dir).unwrap();
        ws.create_project("p", &proj_dir).unwrap();
        let key = ws.open_project_keys()[0].clone();
        assert!(ws.close_project(&key).unwrap());
        assert_eq!(ws.open_project_count(), 0);
    }
    #[test]
    fn workspace_close_nonexistent() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        assert!(!ws.close_project("/nope").unwrap());
    }
    #[test]
    fn workspace_switch_active() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let p1 = d.path().join("p1");
        let p2 = d.path().join("p2");
        std::fs::create_dir_all(&p1).unwrap();
        std::fs::create_dir_all(&p2).unwrap();
        ws.create_project("p1", &p1).unwrap();
        ws.create_project("p2", &p2).unwrap();
        let k2 = ws
            .open_project_keys()
            .into_iter()
            .find(|k| k.ends_with("p2"))
            .unwrap();
        ws.switch_to(&k2).unwrap();
        assert!(ws.active_path().unwrap().ends_with("p2"));
    }
    #[test]
    fn workspace_active_project_none_initially() {
        let d = tmp();
        let ws = Workspace::create("ws", d.path()).unwrap();
        assert!(ws.active_project().is_none());
    }
    #[test]
    fn workspace_active_project_after_create() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let pdir = d.path().join("pa");
        std::fs::create_dir_all(&pdir).unwrap();
        ws.create_project("pa", &pdir).unwrap();
        assert!(ws.active_project().is_some());
    }
    #[test]
    fn workspace_get_project() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let pdir = d.path().join("gp");
        std::fs::create_dir_all(&pdir).unwrap();
        ws.create_project("gp", &pdir).unwrap();
        let key = ws.open_project_keys()[0].clone();
        assert!(ws.get_project(&key).is_some());
        assert!(ws.get_project("nope").is_none());
    }

    // ── Recent management ─────────────────────────────────────────────────────

    #[test]
    fn workspace_add_remove_recent() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.add_recent("/some/path", "some-name");
        assert_eq!(ws.recent_projects().len(), 1);
        assert!(ws.remove_recent("/some/path"));
        assert_eq!(ws.recent_projects().len(), 0);
    }
    #[test]
    fn workspace_clear_unpinned() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.add_recent("/a", "a");
        ws.add_recent("/b", "b");
        ws.pin_recent("/a");
        ws.clear_unpinned_recent();
        assert_eq!(ws.recent_projects().len(), 1);
        assert_eq!(ws.recent_projects()[0].path, "/a");
    }
    #[test]
    fn workspace_pin_recent() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.add_recent("/p", "p");
        assert!(ws.pin_recent("/p"));
        assert!(ws.recent_projects()[0].is_pinned);
    }

    // ── Save / export ─────────────────────────────────────────────────────────

    #[test]
    fn workspace_save_index() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.metadata_mut().description = Some("desc".into());
        ws.save_index().unwrap();
        let ws2 = Workspace::open(d.path()).unwrap();
        assert_eq!(ws2.metadata().description.as_deref(), Some("desc"));
    }
    #[test]
    fn workspace_export_import_archive() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.add_recent("/proj/a", "a-proj");
        let archive = d.path().join("archive.json");
        ws.export_archive(&archive).unwrap();

        let d2 = tmp();
        let mut ws2 = Workspace::create("ws2", d2.path()).unwrap();
        let count = ws2.import_archive(&archive).unwrap();
        assert_eq!(count, 1);
        assert_eq!(ws2.recent_projects().len(), 1);
    }
    #[test]
    fn workspace_export_import_no_dupes() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.add_recent("/x", "x");
        let archive = d.path().join("a.json");
        ws.export_archive(&archive).unwrap();

        let d2 = tmp();
        let mut ws2 = Workspace::create("ws2", d2.path()).unwrap();
        ws2.add_recent("/x", "x"); // already present
        let count = ws2.import_archive(&archive).unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn workspace_save_all() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let pdir = d.path().join("sa");
        std::fs::create_dir_all(&pdir).unwrap();
        ws.create_project("sa", &pdir).unwrap();
        let results = ws.save_all();
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn constants() {
        assert_eq!(DEFAULT_MAX_RECENT, 20);
        assert_eq!(DEFAULT_ANALYSIS_DEPTH, 3);
        assert_eq!(WORKSPACE_FORMAT_VERSION, 1);
        assert_eq!(WORKSPACE_INDEX_FILE, ".rustre-workspace");
        assert_eq!(WORKSPACE_SNAPSHOT_VERSION, 1);
    }

    // ── Workspace snapshot (full serialisation) ───────────────────────────────

    #[test]
    fn snapshot_json_roundtrip_empty() {
        let d = tmp();
        let ws = Workspace::create("snap-ws", d.path()).unwrap();
        let snap = ws
            .build_snapshot(SerializeOptions::default(), None)
            .unwrap();
        assert_eq!(snap.format_version, WORKSPACE_SNAPSHOT_VERSION);
        let json = snap.to_json().unwrap();
        let snap2 = WorkspaceSnapshot::from_json(&json).unwrap();
        assert_eq!(snap2.index.metadata.name, "snap-ws");
        assert_eq!(snap2.projects.len(), 0);
        assert_eq!(snap2.binary_refs.len(), 0);
    }

    #[test]
    fn snapshot_captures_open_project() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let pdir = d.path().join("p_snap");
        std::fs::create_dir_all(&pdir).unwrap();
        let arc = ws.create_project("p_snap", &pdir).unwrap();
        {
            let p = arc.lock().unwrap();
            p.save_note("snap note", "body").unwrap();
            p.save_script("a.rhai", "rhai", "1+1").unwrap();
        }

        let snap = ws
            .build_snapshot(SerializeOptions::default(), None)
            .unwrap();
        assert_eq!(snap.projects.len(), 1);
        let entry = &snap.projects[0];
        assert_eq!(entry.project_name, "p_snap");
        assert_eq!(entry.data.notes.len(), 1);
        assert_eq!(entry.data.scripts.len(), 1);
        assert!(entry.was_active);
    }

    #[test]
    fn snapshot_export_and_reimport_settings() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.config_mut().max_recent = 7;
        ws.config_mut().default_analysis_depth = 9;
        let snap_path = d.path().join("snap.json");
        ws.export_snapshot(&snap_path, SerializeOptions::default(), None)
            .unwrap();

        let d2 = tmp();
        let mut ws2 = Workspace::create("ws2", d2.path()).unwrap();
        let report = ws2.import_snapshot_from(&snap_path).unwrap();
        assert_eq!(report.format_version, WORKSPACE_SNAPSHOT_VERSION);
        assert_eq!(ws2.config().max_recent, 7);
        assert_eq!(ws2.config().default_analysis_depth, 9);
    }

    #[test]
    fn snapshot_import_merges_recent() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        ws.add_recent("/recent/a", "a");
        ws.add_recent("/recent/b", "b");
        let snap_path = d.path().join("rec.json");
        ws.export_snapshot(&snap_path, SerializeOptions::default(), None)
            .unwrap();

        let d2 = tmp();
        let mut ws2 = Workspace::create("ws2", d2.path()).unwrap();
        ws2.add_recent("/recent/a", "a"); // duplicate
        let report = ws2.import_snapshot_from(&snap_path).unwrap();
        // /recent/a is duplicate; /recent/b is new.
        assert_eq!(report.merged_recent_entries, 1);
        assert!(ws2.recent_projects().iter().any(|r| r.path == "/recent/b"));
    }

    #[test]
    fn snapshot_import_replays_project_state() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let pdir = d.path().join("replay_p");
        std::fs::create_dir_all(&pdir).unwrap();
        let arc = ws.create_project("replay_p", &pdir).unwrap();
        {
            let p = arc.lock().unwrap();
            p.save_note("hello", "world").unwrap();
        }

        let snap_path = d.path().join("rep.json");
        ws.export_snapshot(&snap_path, SerializeOptions::default(), None)
            .unwrap();

        // Fresh workspace, but the project directory still exists on disk so
        // import can replay into it.  We close the project first to clear
        // the auxiliary state in the original ws.
        let key = ws.open_project_keys()[0].clone();
        ws.close_project(&key).unwrap();

        let d2 = tmp();
        let mut ws2 = Workspace::create("ws2", d2.path()).unwrap();
        let report = ws2.import_snapshot_from(&snap_path).unwrap();
        assert_eq!(report.imported_projects, 1);
        assert!(report.total_notes >= 1);
    }

    #[test]
    fn snapshot_skips_missing_project_dir() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        // Reference a project that doesn't exist on disk.
        let fake = WorkspaceProjectEntry {
            project_key: "/definitely/not/a/path/abcxyz".into(),
            project_name: "ghost".into(),
            was_active: false,
            data: SerializedProject {
                format_version: 1,
                name: "ghost".into(),
                serialized_at: 0,
                project_root: None,
                binaries: vec![],
                notes: vec![],
                scripts: vec![],
                extra: HashMap::new(),
            },
        };
        let snap = WorkspaceSnapshot {
            format_version: WORKSPACE_SNAPSHOT_VERSION,
            exported_at: 0,
            index: ws.index.clone(),
            projects: vec![fake],
            binary_refs: vec![],
            knowledge: None,
            settings: ws.config().clone(),
        };
        let report = ws.import_snapshot(snap).unwrap();
        assert_eq!(report.imported_projects, 0);
        assert_eq!(report.skipped_projects.len(), 1);
    }

    #[test]
    fn snapshot_carries_knowledge_blob() {
        let d = tmp();
        let ws = Workspace::create("ws", d.path()).unwrap();
        let mut k = KnowledgeSnapshot::default();
        k.schema = Some("rustre-knowledge/v1".into());
        k.entries.insert("topic".into(), "rev-eng".into());
        k.blobs.insert("readme.md".into(), b"hello".to_vec());
        let snap = ws
            .build_snapshot(SerializeOptions::default(), Some(k))
            .unwrap();
        assert!(snap.knowledge.is_some());
        let kk = snap.knowledge.as_ref().unwrap();
        assert_eq!(kk.entries.get("topic").map(String::as_str), Some("rev-eng"));
        assert_eq!(kk.blobs.get("readme.md").map(Vec::as_slice), Some(&b"hello"[..]));
    }

    #[test]
    fn snapshot_binary_ref_count_is_zero_when_no_binaries() {
        let d = tmp();
        let mut ws = Workspace::create("ws", d.path()).unwrap();
        let pdir = d.path().join("nobin");
        std::fs::create_dir_all(&pdir).unwrap();
        ws.create_project("nobin", &pdir).unwrap();
        let snap = ws
            .build_snapshot(SerializeOptions::default(), None)
            .unwrap();
        assert_eq!(snap.binary_ref_count(), 0);
    }

    #[test]
    fn snapshot_write_and_read_from_disk() {
        let d = tmp();
        let ws = Workspace::create("disk-ws", d.path()).unwrap();
        let snap = ws
            .build_snapshot(SerializeOptions::default(), None)
            .unwrap();
        let dst = d.path().join("snap_disk.json");
        snap.write_to(&dst).unwrap();
        let snap2 = WorkspaceSnapshot::read_from(&dst).unwrap();
        assert_eq!(snap2.index.metadata.name, "disk-ws");
        assert_eq!(snap2.format_version, WORKSPACE_SNAPSHOT_VERSION);
    }
}
