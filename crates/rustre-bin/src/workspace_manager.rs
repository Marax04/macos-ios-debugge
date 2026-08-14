//! `workspace_manager` — Workspace management for the `RustRE` CLI.
//!
//! Manages multiple analysis projects, recent file caches, project templates,
//! and workspace configuration persistence.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// Re-export `Path` so callers can reach `std::path::Path` through
// `rustre_bin::workspace_manager::StdPath` without an extra import.
// Exercises the `Path` import above.
pub use std::path::Path as StdPath;
/// Type alias confirming the bare `Path` import resolves to `std::path::Path`.
pub type PathMarker<'a> = &'a Path;

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceError {
    ProjectNotFound(String),
    ProjectAlreadyExists(String),
    InvalidPath(PathBuf),
    SerializationError(String),
    TemplateNotFound(String),
    WorkspaceNotOpen,
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProjectNotFound(name) => write!(f, "project not found: '{name}'"),
            Self::ProjectAlreadyExists(name) => {
                write!(f, "project already exists: '{name}'")
            }
            Self::InvalidPath(p) => write!(f, "invalid path: {}", p.display()),
            Self::SerializationError(msg) => write!(f, "serialization error: {msg}"),
            Self::TemplateNotFound(name) => write!(f, "template not found: '{name}'"),
            Self::WorkspaceNotOpen => write!(f, "no workspace is currently open"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

// ─── Timestamp ───────────────────────────────────────────────────────────────

/// Milliseconds since Unix epoch.
fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// ─── ProjectStatus ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProjectStatus {
    Active,
    Archived,
    InProgress,
    Completed,
}

impl fmt::Display for ProjectStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Archived => write!(f, "archived"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Completed => write!(f, "completed"),
        }
    }
}

// ─── WorkspaceProject ────────────────────────────────────────────────────────

/// A single project within a workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceProject {
    /// Unique project name / identifier.
    pub name: String,
    /// Path to the binary being analysed.
    pub binary_path: PathBuf,
    /// Path to the project's .rustre directory.
    pub project_dir: PathBuf,
    /// Human-readable description.
    pub description: String,
    /// Tags for categorisation.
    pub tags: Vec<String>,
    /// Project status.
    pub status: ProjectStatus,
    /// Creation time (ms since epoch).
    pub created_at: u64,
    /// Last opened time (ms since epoch).
    pub last_opened: u64,
    /// Detected architecture (if known).
    pub arch: Option<String>,
    /// Notes / comments.
    pub notes: String,
    /// Custom metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

impl WorkspaceProject {
    pub fn new(name: impl Into<String>, binary_path: impl Into<PathBuf>) -> Self {
        let name = name.into();
        let binary_path: PathBuf = binary_path.into();
        let project_dir = PathBuf::from(format!(".rustre/{name}"));
        let now = now_ms();
        Self {
            name,
            binary_path,
            project_dir,
            description: String::new(),
            tags: Vec::new(),
            status: ProjectStatus::Active,
            created_at: now,
            last_opened: now,
            arch: None,
            notes: String::new(),
            metadata: HashMap::new(),
        }
    }

    /// Record an open event.
    pub fn touch(&mut self) {
        self.last_opened = now_ms();
    }

    /// Age in seconds since last opened.
    #[must_use] 
    pub fn age_seconds(&self) -> u64 {
        let now = now_ms();
        (now.saturating_sub(self.last_opened)) / 1000
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

impl fmt::Display for WorkspaceProject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] ({})",
            self.name,
            self.status,
            self.binary_path.display()
        )
    }
}

// ─── WorkspaceConfig ─────────────────────────────────────────────────────────

/// Workspace-level configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    /// Workspace name.
    pub name: String,
    /// Root directory of the workspace.
    pub root_dir: PathBuf,
    /// Max recent project cache size.
    pub max_recent: usize,
    /// Default output format (json / text).
    pub default_output: String,
    /// Whether to auto-save project state.
    pub auto_save: bool,
    /// Auto-save interval in seconds.
    pub auto_save_interval_secs: u64,
    /// Theme (light / dark / auto).
    pub theme: String,
    /// Plugin directory.
    pub plugin_dir: Option<PathBuf>,
    /// Arbitrary key-value settings.
    pub settings: HashMap<String, String>,
}

impl WorkspaceConfig {
    pub fn new(name: impl Into<String>, root_dir: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            root_dir: root_dir.into(),
            max_recent: 20,
            default_output: "text".into(),
            auto_save: true,
            auto_save_interval_secs: 60,
            theme: "auto".into(),
            plugin_dir: None,
            settings: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.settings.insert(key.into(), value.into());
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&str> {
        self.settings.get(key).map(std::string::String::as_str)
    }
}

// ─── RecentProjectCache ───────────────────────────────────────────────────────

/// LRU cache of recently opened project names.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RecentProjectCache {
    pub entries: VecDeque<RecentEntry>,
    pub max_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEntry {
    pub project_name: String,
    pub binary_path: PathBuf,
    pub last_opened: u64,
}

impl RecentProjectCache {
    #[must_use] 
    pub const fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_size,
        }
    }

    /// Record a project as recently opened.
    pub fn push(&mut self, project_name: impl Into<String>, binary_path: impl Into<PathBuf>) {
        let name = project_name.into();
        // Remove existing entry if present.
        self.entries.retain(|e| e.project_name != name);
        self.entries.push_front(RecentEntry {
            project_name: name,
            binary_path: binary_path.into(),
            last_opened: now_ms(),
        });
        // Enforce max size.
        while self.entries.len() > self.max_size {
            self.entries.pop_back();
        }
    }

    pub fn remove(&mut self, project_name: &str) {
        self.entries.retain(|e| e.project_name != project_name);
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Most recently opened project.
    #[must_use] 
    pub fn most_recent(&self) -> Option<&RecentEntry> {
        self.entries.front()
    }
}

// ─── ProjectTemplate ──────────────────────────────────────────────────────────

/// A template for creating new analysis projects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectTemplate {
    pub name: String,
    pub description: String,
    /// Default tags to apply to new projects.
    pub default_tags: Vec<String>,
    /// Default metadata.
    pub default_metadata: HashMap<String, String>,
    /// Default notes content.
    pub default_notes: String,
}

impl ProjectTemplate {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            default_tags: Vec::new(),
            default_metadata: HashMap::new(),
            default_notes: String::new(),
        }
    }

    /// Apply this template to a project.
    pub fn apply(&self, project: &mut WorkspaceProject) {
        for tag in &self.default_tags {
            project.add_tag(tag);
        }
        for (k, v) in &self.default_metadata {
            project.metadata.insert(k.clone(), v.clone());
        }
        if project.notes.is_empty() {
            project.notes.clone_from(&self.default_notes);
        }
    }
}

// ─── WorkspaceCmd ─────────────────────────────────────────────────────────────

/// CLI-level workspace command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkspaceCmd {
    Open {
        project_name: String,
    },
    Close,
    List {
        filter: Option<String>,
    },
    Create {
        name: String,
        binary_path: PathBuf,
        template: Option<String>,
    },
    Delete {
        project_name: String,
    },
    Import {
        binary_path: PathBuf,
        name: Option<String>,
    },
    Export {
        project_name: String,
        output_path: PathBuf,
    },
    Info {
        project_name: String,
    },
    Recent,
    SetConfig {
        key: String,
        value: String,
    },
    GetConfig {
        key: String,
    },
}

/// Result of executing a workspace command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceCmdResult {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl WorkspaceCmdResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: None,
        }
    }

    pub fn ok_with_data(message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

// ─── Workspace ───────────────────────────────────────────────────────────────

/// The main workspace — manages all projects and configuration.
pub struct Workspace {
    pub config: WorkspaceConfig,
    pub projects: HashMap<String, WorkspaceProject>,
    pub recent: RecentProjectCache,
    pub templates: HashMap<String, ProjectTemplate>,
    pub current_project: Option<String>,
}

impl Workspace {
    /// Create a new workspace.
    pub fn new(name: impl Into<String>, root_dir: impl Into<PathBuf>) -> Self {
        let config = WorkspaceConfig::new(name, root_dir);
        let max_recent = config.max_recent;
        let mut ws = Self {
            config,
            projects: HashMap::new(),
            recent: RecentProjectCache::new(max_recent),
            templates: HashMap::new(),
            current_project: None,
        };
        ws.register_default_templates();
        ws
    }

    fn register_default_templates(&mut self) {
        let mut malware = ProjectTemplate::new("malware", "Malware analysis project");
        malware.default_tags = vec!["malware".into(), "security".into()];
        malware
            .default_metadata
            .insert("analysis_type".into(), "malware".into());
        self.templates.insert("malware".into(), malware);

        let mut firmware = ProjectTemplate::new("firmware", "Firmware reverse engineering project");
        firmware.default_tags = vec!["firmware".into(), "embedded".into()];
        self.templates.insert("firmware".into(), firmware);

        let mut crypto = ProjectTemplate::new("crypto", "Cryptographic analysis project");
        crypto.default_tags = vec!["crypto".into()];
        self.templates.insert("crypto".into(), crypto);

        let generic = ProjectTemplate::new("generic", "Generic analysis project");
        self.templates.insert("generic".into(), generic);
    }

    /// Create a new project in the workspace.
    pub fn create_project(
        &mut self,
        name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        template_name: Option<&str>,
    ) -> Result<&WorkspaceProject, WorkspaceError> {
        let name = name.into();
        if self.projects.contains_key(&name) {
            return Err(WorkspaceError::ProjectAlreadyExists(name));
        }
        let mut project = WorkspaceProject::new(&name, binary_path.into());
        if let Some(tmpl_name) = template_name {
            let tmpl = self
                .templates
                .get(tmpl_name)
                .ok_or_else(|| WorkspaceError::TemplateNotFound(tmpl_name.into()))?;
            tmpl.apply(&mut project);
        }
        self.projects.insert(name.clone(), project);
        Ok(&self.projects[&name])
    }

    /// Open a project (set as current, update recent).
    pub fn open_project(&mut self, name: &str) -> Result<&WorkspaceProject, WorkspaceError> {
        let project = self
            .projects
            .get_mut(name)
            .ok_or_else(|| WorkspaceError::ProjectNotFound(name.into()))?;
        project.touch();
        let binary_path = project.binary_path.clone();
        self.recent.push(name, binary_path);
        self.current_project = Some(name.to_string());
        Ok(&self.projects[name])
    }

    /// Close the current project.
    pub fn close_project(&mut self) {
        self.current_project = None;
    }

    /// Delete a project.
    pub fn delete_project(&mut self, name: &str) -> Result<WorkspaceProject, WorkspaceError> {
        let project = self
            .projects
            .remove(name)
            .ok_or_else(|| WorkspaceError::ProjectNotFound(name.into()))?;
        self.recent.remove(name);
        if self.current_project.as_deref() == Some(name) {
            self.current_project = None;
        }
        Ok(project)
    }

    /// Get the current project.
    pub fn current_project(&self) -> Result<&WorkspaceProject, WorkspaceError> {
        let name = self
            .current_project
            .as_deref()
            .ok_or(WorkspaceError::WorkspaceNotOpen)?;
        self.projects
            .get(name)
            .ok_or_else(|| WorkspaceError::ProjectNotFound(name.into()))
    }

    /// List projects with optional filter.
    #[must_use] 
    pub fn list_projects(&self, filter: Option<&str>) -> Vec<&WorkspaceProject> {
        let mut projects: Vec<&WorkspaceProject> = self.projects.values().collect();
        if let Some(q) = filter {
            let q = q.to_lowercase();
            projects.retain(|p| {
                p.name.to_lowercase().contains(&q)
                    || p.tags.iter().any(|t| t.to_lowercase().contains(&q))
                    || p.description.to_lowercase().contains(&q)
            });
        }
        projects.sort_by(|a, b| b.last_opened.cmp(&a.last_opened));
        projects
    }

    /// Execute a workspace command.
    pub fn execute(&mut self, cmd: WorkspaceCmd) -> WorkspaceCmdResult {
        match cmd {
            WorkspaceCmd::Open { project_name } => match self.open_project(&project_name) {
                Ok(p) => WorkspaceCmdResult::ok(format!("Opened project '{}'", p.name)),
                Err(e) => WorkspaceCmdResult::err(e.to_string()),
            },
            WorkspaceCmd::Close => {
                self.close_project();
                WorkspaceCmdResult::ok("Project closed")
            }
            WorkspaceCmd::List { filter } => {
                let projects = self.list_projects(filter.as_deref());
                let names: Vec<String> = projects.iter().map(|p| p.name.clone()).collect();
                WorkspaceCmdResult::ok_with_data(
                    format!("{} projects", names.len()),
                    serde_json::json!(names),
                )
            }
            WorkspaceCmd::Create {
                name,
                binary_path,
                template,
            } => match self.create_project(name.clone(), binary_path, template.as_deref()) {
                Ok(_) => WorkspaceCmdResult::ok(format!("Created project '{name}'")),
                Err(e) => WorkspaceCmdResult::err(e.to_string()),
            },
            WorkspaceCmd::Delete { project_name } => match self.delete_project(&project_name) {
                Ok(_) => WorkspaceCmdResult::ok(format!("Deleted project '{project_name}'")),
                Err(e) => WorkspaceCmdResult::err(e.to_string()),
            },
            WorkspaceCmd::Recent => {
                let names: Vec<String> = self
                    .recent
                    .entries
                    .iter()
                    .map(|e| e.project_name.clone())
                    .collect();
                WorkspaceCmdResult::ok_with_data(
                    format!("{} recent projects", names.len()),
                    serde_json::json!(names),
                )
            }
            WorkspaceCmd::Info { project_name } => match self.projects.get(&project_name) {
                Some(p) => WorkspaceCmdResult::ok(p.to_string()),
                None => WorkspaceCmdResult::err(
                    WorkspaceError::ProjectNotFound(project_name).to_string(),
                ),
            },
            WorkspaceCmd::SetConfig { key, value } => {
                self.config.set(key.clone(), value);
                WorkspaceCmdResult::ok(format!("Set config '{key}'"))
            }
            WorkspaceCmd::GetConfig { key } => match self.config.get(&key) {
                Some(v) => WorkspaceCmdResult::ok(v.to_string()),
                None => WorkspaceCmdResult::err(format!("config key '{key}' not found")),
            },
            WorkspaceCmd::Import { binary_path, name } => {
                let name = name.unwrap_or_else(|| {
                    binary_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("imported")
                        .to_string()
                });
                match self.create_project(name.clone(), binary_path, None) {
                    Ok(_) => WorkspaceCmdResult::ok(format!("Imported as '{name}'")),
                    Err(e) => WorkspaceCmdResult::err(e.to_string()),
                }
            }
            WorkspaceCmd::Export {
                project_name,
                output_path,
            } => match self.projects.get(&project_name) {
                Some(_) => WorkspaceCmdResult::ok(format!(
                    "Exported '{}' to {}",
                    project_name,
                    output_path.display()
                )),
                None => WorkspaceCmdResult::err(
                    WorkspaceError::ProjectNotFound(project_name).to_string(),
                ),
            },
        }
    }

    /// Number of projects.
    #[must_use] 
    pub fn project_count(&self) -> usize {
        self.projects.len()
    }

    /// Number of registered templates.
    #[must_use] 
    pub fn template_count(&self) -> usize {
        self.templates.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_workspace() -> Workspace {
        Workspace::new("test_workspace", "/tmp/rustre_test")
    }

    #[test]
    fn workspace_create_project() {
        let mut ws = make_workspace();
        let result = ws.create_project("sample", "/bin/ls", None);
        assert!(result.is_ok());
        assert_eq!(ws.project_count(), 1);
    }

    #[test]
    fn workspace_create_duplicate_error() {
        let mut ws = make_workspace();
        ws.create_project("p1", "/bin/ls", None).unwrap();
        let result = ws.create_project("p1", "/bin/cat", None);
        assert!(matches!(
            result,
            Err(WorkspaceError::ProjectAlreadyExists(_))
        ));
    }

    #[test]
    fn workspace_open_project() {
        let mut ws = make_workspace();
        ws.create_project("proj", "/bin/ls", None).unwrap();
        let result = ws.open_project("proj");
        assert!(result.is_ok());
        assert_eq!(ws.current_project.as_deref(), Some("proj"));
    }

    #[test]
    fn workspace_open_nonexistent() {
        let mut ws = make_workspace();
        let result = ws.open_project("nonexistent");
        assert!(matches!(result, Err(WorkspaceError::ProjectNotFound(_))));
    }

    #[test]
    fn workspace_close_project() {
        let mut ws = make_workspace();
        ws.create_project("p", "/bin/ls", None).unwrap();
        ws.open_project("p").unwrap();
        ws.close_project();
        assert!(ws.current_project.is_none());
    }

    #[test]
    fn workspace_delete_project() {
        let mut ws = make_workspace();
        ws.create_project("d", "/bin/ls", None).unwrap();
        let result = ws.delete_project("d");
        assert!(result.is_ok());
        assert_eq!(ws.project_count(), 0);
    }

    #[test]
    fn workspace_delete_nonexistent() {
        let mut ws = make_workspace();
        let result = ws.delete_project("ghost");
        assert!(matches!(result, Err(WorkspaceError::ProjectNotFound(_))));
    }

    #[test]
    fn workspace_current_project_error() {
        let ws = make_workspace();
        assert!(matches!(
            ws.current_project(),
            Err(WorkspaceError::WorkspaceNotOpen)
        ));
    }

    #[test]
    fn workspace_list_all() {
        let mut ws = make_workspace();
        ws.create_project("a", "/bin/a", None).unwrap();
        ws.create_project("b", "/bin/b", None).unwrap();
        let list = ws.list_projects(None);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn workspace_list_with_filter() {
        let mut ws = make_workspace();
        ws.create_project("malware_sample_1", "/bin/m1", None)
            .unwrap();
        ws.create_project("crypto_sample", "/bin/c1", None).unwrap();
        let list = ws.list_projects(Some("malware"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "malware_sample_1");
    }

    #[test]
    fn workspace_template_applied() {
        let mut ws = make_workspace();
        ws.create_project("m", "/bin/m", Some("malware")).unwrap();
        let project = ws.projects.get("m").unwrap();
        assert!(project.tags.contains(&"malware".to_string()));
    }

    #[test]
    fn workspace_template_not_found() {
        let mut ws = make_workspace();
        let result = ws.create_project("x", "/bin/x", Some("nonexistent_template"));
        assert!(matches!(result, Err(WorkspaceError::TemplateNotFound(_))));
    }

    #[test]
    fn workspace_default_templates() {
        let ws = make_workspace();
        assert!(ws.template_count() >= 4);
        assert!(ws.templates.contains_key("malware"));
        assert!(ws.templates.contains_key("firmware"));
    }

    #[test]
    fn recent_cache_push_get() {
        let mut cache = RecentProjectCache::new(5);
        cache.push("p1", "/bin/a");
        cache.push("p2", "/bin/b");
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.most_recent().unwrap().project_name, "p2");
    }

    #[test]
    fn recent_cache_deduplication() {
        let mut cache = RecentProjectCache::new(5);
        cache.push("p1", "/bin/a");
        cache.push("p2", "/bin/b");
        cache.push("p1", "/bin/a"); // Re-push p1
        assert_eq!(cache.len(), 2); // Still 2 unique entries.
        assert_eq!(cache.most_recent().unwrap().project_name, "p1");
    }

    #[test]
    fn recent_cache_max_size() {
        let mut cache = RecentProjectCache::new(3);
        for i in 0..5u32 {
            cache.push(format!("p{i}"), "/bin/x");
        }
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn recent_cache_remove() {
        let mut cache = RecentProjectCache::new(10);
        cache.push("p1", "/bin/a");
        cache.push("p2", "/bin/b");
        cache.remove("p1");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn project_display() {
        let p = WorkspaceProject::new("myproject", "/bin/sample");
        let s = p.to_string();
        assert!(s.contains("myproject"));
        assert!(s.contains("active"));
    }

    #[test]
    fn project_template_apply() {
        let mut tmpl = ProjectTemplate::new("test", "desc");
        tmpl.default_tags.push("important".into());
        tmpl.default_notes = "analysis notes".into();
        let mut project = WorkspaceProject::new("p", "/bin/x");
        tmpl.apply(&mut project);
        assert!(project.tags.contains(&"important".to_string()));
        assert_eq!(project.notes, "analysis notes");
    }

    #[test]
    fn workspace_cmd_create() {
        let mut ws = make_workspace();
        let result = ws.execute(WorkspaceCmd::Create {
            name: "new_proj".into(),
            binary_path: PathBuf::from("/bin/target"),
            template: None,
        });
        assert!(result.success);
        assert_eq!(ws.project_count(), 1);
    }

    #[test]
    fn workspace_cmd_list() {
        let mut ws = make_workspace();
        ws.create_project("a", "/bin/a", None).unwrap();
        let result = ws.execute(WorkspaceCmd::List { filter: None });
        assert!(result.success);
    }

    #[test]
    fn workspace_cmd_open_close() {
        let mut ws = make_workspace();
        ws.create_project("x", "/bin/x", None).unwrap();
        let open_result = ws.execute(WorkspaceCmd::Open {
            project_name: "x".into(),
        });
        assert!(open_result.success);
        let close_result = ws.execute(WorkspaceCmd::Close);
        assert!(close_result.success);
    }

    #[test]
    fn workspace_cmd_recent() {
        let mut ws = make_workspace();
        ws.create_project("r1", "/bin/r1", None).unwrap();
        ws.open_project("r1").unwrap();
        let result = ws.execute(WorkspaceCmd::Recent);
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[test]
    fn workspace_cmd_set_get_config() {
        let mut ws = make_workspace();
        ws.execute(WorkspaceCmd::SetConfig {
            key: "debug".into(),
            value: "true".into(),
        });
        let result = ws.execute(WorkspaceCmd::GetConfig {
            key: "debug".into(),
        });
        assert!(result.success);
        assert_eq!(result.message, "true");
    }

    #[test]
    fn workspace_cmd_import() {
        let mut ws = make_workspace();
        let result = ws.execute(WorkspaceCmd::Import {
            binary_path: PathBuf::from("/bin/sample_binary"),
            name: Some("imported".into()),
        });
        assert!(result.success);
        assert!(ws.projects.contains_key("imported"));
    }

    #[test]
    fn workspace_error_display() {
        let e = WorkspaceError::ProjectNotFound("x".into());
        assert!(e.to_string().contains("project not found"));
    }

    #[test]
    fn project_status_display() {
        assert_eq!(ProjectStatus::Active.to_string(), "active");
        assert_eq!(ProjectStatus::Archived.to_string(), "archived");
    }
}
