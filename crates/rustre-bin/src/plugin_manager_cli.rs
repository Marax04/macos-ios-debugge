//! `plugin_manager_cli` — CLI commands for plugin management.
//!
//! Provides list/install/remove/enable/disable/update/info operations for
//! `RustRE` plugins.  All I/O is done through a plain `OutputCtx`-style writer
//! so this module has zero GUI dependencies.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by plugin CLI operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginCliError {
    NotFound(String),
    AlreadyInstalled(String),
    IncompatibleVersion { plugin: String, required: String, actual: String },
    MissingDependency { plugin: String, dep: String },
    Io(String),
    Parse(String),
    RepoError(String),
}

impl fmt::Display for PluginCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "plugin not found: {n}"),
            Self::AlreadyInstalled(n) => write!(f, "plugin already installed: {n}"),
            Self::IncompatibleVersion { plugin, required, actual } =>
                write!(f, "{plugin}: requires API {required}, platform provides {actual}"),
            Self::MissingDependency { plugin, dep } =>
                write!(f, "{plugin}: missing dependency '{dep}'"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Parse(e) => write!(f, "manifest parse error: {e}"),
            Self::RepoError(e) => write!(f, "repository error: {e}"),
        }
    }
}

// ── Manifest ──────────────────────────────────────────────────────────────────

/// Semantic version (major.minor.patch).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    /// Parse a `"major.minor.patch"` string.
    ///
    /// # Errors
    /// Returns `PluginCliError::Parse` on malformed input.
    pub fn parse(s: &str) -> Result<Self, PluginCliError> {
        let parts: Vec<&str> = s.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(PluginCliError::Parse(format!("bad semver '{s}'")));
        }
        let parse_part = |p: &str| {
            p.parse::<u32>()
                .map_err(|_| PluginCliError::Parse(format!("bad semver component '{p}'")))
        };
        Ok(Self {
            major: parse_part(parts[0])?,
            minor: parse_part(parts[1])?,
            patch: parse_part(parts[2])?,
        })
    }

    /// Return `true` if this version is API-compatible with `required` (same major).
    #[must_use]
    pub const fn compatible_with(&self, required: &Self) -> bool {
        if self.major != required.major {
            return false;
        }
        if self.minor > required.minor {
            return true;
        }
        if self.minor < required.minor {
            return false;
        }
        self.patch >= required.patch
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Plugin lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    Enabled,
    Disabled,
    Error,
    Unknown,
}

impl PluginStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Enabled  => "enabled",
            Self::Disabled => "disabled",
            Self::Error    => "error",
            Self::Unknown  => "unknown",
        }
    }
}

impl fmt::Display for PluginStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Full plugin manifest parsed from `plugin.toml`.
#[derive(Debug, Clone)]
pub struct PluginManifest {
    /// Unique plugin identifier (e.g. `rustre.yara`).
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Plugin version.
    pub version: SemVer,
    /// Minimum platform API version required.
    pub api_version: SemVer,
    /// Author name/email.
    pub author: String,
    /// One-line description.
    pub description: String,
    /// Homepage or repository URL.
    pub homepage: Option<String>,
    /// SPDX licence identifier.
    pub license: Option<String>,
    /// IDs of required plugins.
    pub dependencies: Vec<String>,
    /// Optional IDs of suggested plugins.
    pub optional_deps: Vec<String>,
    /// Entry-point shared-library path relative to the plugin root.
    pub entry: String,
    /// Arbitrary metadata tags.
    pub tags: Vec<String>,
    /// Timestamps (UNIX seconds).
    pub installed_at: Option<u64>,
    /// Current runtime status (set after load).
    pub status: PluginStatus,
}

impl PluginManifest {
    /// Parse a minimal `key = value` TOML-like manifest text.
    ///
    /// # Errors
    /// Returns `PluginCliError::Parse` if a required key is missing or malformed.
    pub fn parse(text: &str) -> Result<Self, PluginCliError> {
        let mut map: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_owned();
                let val = v.trim().trim_matches('"').to_owned();
                map.insert(key, val);
            }
        }

        let req = |k: &str| -> Result<String, PluginCliError> {
            map.get(k)
                .cloned()
                .ok_or_else(|| PluginCliError::Parse(format!("missing required key '{k}'")))
        };

        let id = req("id")?;
        let name = req("name")?;
        let version = SemVer::parse(&req("version")?)?;
        let api_version = SemVer::parse(&req("api_version")?)?;
        let author = req("author")?;
        let description = req("description")?;
        let homepage = map.get("homepage").cloned();
        let license  = map.get("license").cloned();
        let entry    = map.get("entry").cloned().unwrap_or_else(|| "plugin.so".into());

        let parse_list = |k: &str| -> Vec<String> {
            map.get(k)
                .map(|v| v.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default()
        };
        let dependencies  = parse_list("dependencies");
        let optional_deps = parse_list("optional_deps");
        let tags          = parse_list("tags");

        Ok(Self {
            id, name, version, api_version, author, description,
            homepage, license, dependencies, optional_deps, entry, tags,
            installed_at: None,
            status: PluginStatus::Unknown,
        })
    }

    /// Serialise back to a minimal TOML-like string.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("id = \"{}\"\n", self.id));
        out.push_str(&format!("name = \"{}\"\n", self.name));
        out.push_str(&format!("version = \"{}\"\n", self.version));
        out.push_str(&format!("api_version = \"{}\"\n", self.api_version));
        out.push_str(&format!("author = \"{}\"\n", self.author));
        out.push_str(&format!("description = \"{}\"\n", self.description));
        if let Some(ref h) = self.homepage {
            out.push_str(&format!("homepage = \"{h}\"\n"));
        }
        if let Some(ref l) = self.license {
            out.push_str(&format!("license = \"{l}\"\n"));
        }
        out.push_str(&format!("entry = \"{}\"\n", self.entry));
        if !self.dependencies.is_empty() {
            out.push_str(&format!("dependencies = \"{}\"\n", self.dependencies.join(", ")));
        }
        if !self.optional_deps.is_empty() {
            out.push_str(&format!("optional_deps = \"{}\"\n", self.optional_deps.join(", ")));
        }
        if !self.tags.is_empty() {
            out.push_str(&format!("tags = \"{}\"\n", self.tags.join(", ")));
        }
        out
    }
}

// ── Repository ────────────────────────────────────────────────────────────────

/// A remote plugin repository entry (the published metadata).
#[derive(Debug, Clone)]
pub struct RepoEntry {
    pub id: String,
    pub name: String,
    pub latest_version: SemVer,
    pub description: String,
    pub download_url: String,
    pub checksum_sha256: String,
}

/// An in-memory plugin repository index (parsed from a remote JSON feed).
pub struct PluginRepository {
    pub name: String,
    pub url: String,
    entries: Vec<RepoEntry>,
}

impl PluginRepository {
    /// Construct with a name and base URL.
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self { name: name.into(), url: url.into(), entries: Vec::new() }
    }

    /// Stub: populate with synthetic entries for testing.
    pub fn populate_stub(&mut self) {
        let stub_entries = [
            ("rustre.yara",      "YARA Scanner",    "3.1.0", "Scan binaries with YARA rules"),
            ("rustre.emu",       "Unicorn Emulator","1.0.2", "CPU emulation via Unicorn"),
            ("rustre.llvm",      "LLVM Lifter",     "0.9.0", "Lift to LLVM IR"),
            ("rustre.angr",      "angr Bridge",     "0.4.1", "Symbolic execution via angr"),
            ("rustre.retdec",    "RetDec Decompiler","2.0.0","RetDec-based C decompiler"),
            ("rustre.signature", "Sig Matcher",     "1.3.0", "Function signature matching"),
        ];
        for (id, name, ver, desc) in stub_entries {
            if let Ok(v) = SemVer::parse(ver) {
                self.entries.push(RepoEntry {
                    id: id.into(),
                    name: name.into(),
                    latest_version: v,
                    description: desc.into(),
                    download_url: format!("{}/download/{id}-{ver}.tar.gz", self.url),
                    checksum_sha256: format!("{:064x}", id.len() as u64 * 0xdeadbeef),
                });
            }
        }
    }

    /// Search entries by substring match on id, name, or description.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&RepoEntry> {
        let q = query.to_lowercase();
        self.entries.iter()
            .filter(|e| {
                e.id.to_lowercase().contains(&q)
                    || e.name.to_lowercase().contains(&q)
                    || e.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Find an entry by exact id.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&RepoEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// All entries.
    #[must_use]
    pub fn all(&self) -> &[RepoEntry] {
        &self.entries
    }
}

// ── Plugin registry ───────────────────────────────────────────────────────────

/// The local plugin registry — tracks what is installed.
pub struct PluginRegistry {
    /// Platform API version for compatibility checks.
    pub platform_api: SemVer,
    /// Plugin install root (e.g. `~/.rustre/plugins/`).
    pub root: PathBuf,
    /// Loaded manifests keyed by plugin id.
    manifests: HashMap<String, PluginManifest>,
    /// Disabled plugin ids.
    disabled: std::collections::HashSet<String>,
}

impl PluginRegistry {
    /// Create a registry pointing at `root` with the given platform API version.
    #[must_use]
    pub fn new(root: PathBuf, platform_api: SemVer) -> Self {
        Self {
            platform_api,
            root,
            manifests: HashMap::new(),
            disabled: std::collections::HashSet::new(),
        }
    }

    /// Scan `root` for `plugin.toml` files and load them.
    ///
    /// # Errors
    /// Returns first `PluginCliError::Io` or `PluginCliError::Parse` encountered.
    pub fn reload(&mut self) -> Result<usize, PluginCliError> {
        self.manifests.clear();
        if !self.root.exists() {
            return Ok(0);
        }
        let read_dir = fs::read_dir(&self.root)
            .map_err(|e| PluginCliError::Io(e.to_string()))?;
        let mut count = 0usize;
        for entry in read_dir.flatten() {
            let manifest_path = entry.path().join("plugin.toml");
            if !manifest_path.exists() { continue; }
            let text = fs::read_to_string(&manifest_path)
                .map_err(|e| PluginCliError::Io(e.to_string()))?;
            let mut manifest = PluginManifest::parse(&text)?;
            manifest.status = if self.disabled.contains(&manifest.id) {
                PluginStatus::Disabled
            } else {
                PluginStatus::Enabled
            };
            self.manifests.insert(manifest.id.clone(), manifest);
            count += 1;
        }
        Ok(count)
    }

    /// Insert a manifest directly (used by install).
    pub fn insert(&mut self, mut m: PluginManifest) {
        m.installed_at = Some(unix_now());
        m.status = PluginStatus::Enabled;
        self.manifests.insert(m.id.clone(), m);
    }

    /// Remove a plugin by id.
    ///
    /// # Errors
    /// Returns `PluginCliError::NotFound` if the plugin is not installed.
    pub fn remove(&mut self, id: &str) -> Result<PluginManifest, PluginCliError> {
        self.manifests.remove(id).ok_or_else(|| PluginCliError::NotFound(id.into()))
    }

    /// Enable a plugin.
    pub fn enable(&mut self, id: &str) -> Result<(), PluginCliError> {
        let m = self.manifests.get_mut(id).ok_or_else(|| PluginCliError::NotFound(id.into()))?;
        self.disabled.remove(id);
        m.status = PluginStatus::Enabled;
        Ok(())
    }

    /// Disable a plugin.
    pub fn disable(&mut self, id: &str) -> Result<(), PluginCliError> {
        let m = self.manifests.get_mut(id).ok_or_else(|| PluginCliError::NotFound(id.into()))?;
        self.disabled.insert(id.into());
        m.status = PluginStatus::Disabled;
        Ok(())
    }

    /// Check whether a plugin is installed.
    #[must_use]
    pub fn is_installed(&self, id: &str) -> bool {
        self.manifests.contains_key(id)
    }

    /// All installed manifests, sorted by id.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<&PluginManifest> {
        let mut v: Vec<&PluginManifest> = self.manifests.values().collect();
        v.sort_by_key(|m| m.id.as_str());
        v
    }

    /// Validate all loaded plugins for API compatibility and dependency satisfaction.
    #[must_use]
    pub fn validate(&self) -> Vec<PluginCliError> {
        let mut errors = Vec::new();
        for m in self.manifests.values() {
            if !self.platform_api.compatible_with(&m.api_version) {
                errors.push(PluginCliError::IncompatibleVersion {
                    plugin: m.id.clone(),
                    required: m.api_version.to_string(),
                    actual: self.platform_api.to_string(),
                });
            }
            for dep in &m.dependencies {
                if !self.manifests.contains_key(dep.as_str()) {
                    errors.push(PluginCliError::MissingDependency {
                        plugin: m.id.clone(),
                        dep: dep.clone(),
                    });
                }
            }
        }
        errors
    }

    /// Find plugin by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&PluginManifest> {
        self.manifests.get(id)
    }
}

// ── Table printer (ANSI-aware) ────────────────────────────────────────────────

const BOLD: &str  = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const CYAN: &str  = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str= "\x1b[33m";
const RED: &str   = "\x1b[31m";
const DIM: &str   = "\x1b[2m";

fn c(code: &'static str, use_color: bool) -> &'static str {
    if use_color { code } else { "" }
}

/// Print a simple ASCII-bordered table.
pub fn print_table(headers: &[&str], rows: &[Vec<String>], color: bool, w: &mut dyn Write) {
    let ncols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < ncols {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let sep = widths.iter().map(|w| "-".repeat(w + 2)).collect::<Vec<_>>().join("+");
    let sep_line = format!("+{}+", sep);
    let _ = writeln!(w, "{}", sep_line);
    // Header row
    let header_cells: Vec<String> = headers.iter().enumerate()
        .map(|(i, h)| format!(" {}{}{:<w$}{} ", c(BOLD, color), c(CYAN, color), h, c(RESET, color), w = widths[i]))
        .collect();
    let _ = writeln!(w, "|{}|", header_cells.join("|"));
    let _ = writeln!(w, "{}", sep_line);
    for row in rows {
        let cells: Vec<String> = row.iter().enumerate()
            .map(|(i, cell)| format!(" {:<w$} ", cell, w = widths.get(i).copied().unwrap_or(cell.len())))
            .collect();
        let _ = writeln!(w, "|{}|", cells.join("|"));
    }
    let _ = writeln!(w, "{}", sep_line);
}

// ── CLI command handlers ──────────────────────────────────────────────────────

/// Arguments for the `plugin list` command.
#[derive(Debug, Clone, Default)]
pub struct ListArgs {
    pub filter_status: Option<String>,
    pub search: Option<String>,
    pub json: bool,
    pub color: bool,
}

/// List installed plugins.
pub fn cmd_list(registry: &PluginRegistry, args: &ListArgs, w: &mut dyn io::Write) -> i32 {
    let plugins: Vec<&PluginManifest> = registry.all_sorted().into_iter()
        .filter(|m| {
            if let Some(ref f) = args.filter_status {
                m.status.label() == f.as_str()
            } else { true }
        })
        .filter(|m| {
            if let Some(ref q) = args.search {
                let q = q.to_lowercase();
                m.id.to_lowercase().contains(&q) || m.name.to_lowercase().contains(&q)
            } else { true }
        })
        .collect();

    if args.json {
        let _ = w.write_all(b"[\n");
        for (i, m) in plugins.iter().enumerate() {
            let comma = if i + 1 < plugins.len() { "," } else { "" };
            let line = format!(
                "  {{\"id\":\"{}\",\"name\":\"{}\",\"version\":\"{}\",\"status\":\"{}\",\"description\":\"{}\"}}{}\n",
                m.id, m.name, m.version, m.status, m.description, comma
            );
            let _ = w.write_all(line.as_bytes());
        }
        let _ = w.write_all(b"]\n");
        return 0;
    }

    let _ = writeln!(w, "\n{}{}Installed plugins ({}){}{}",
        c(BOLD, args.color), c(CYAN, args.color), plugins.len(), c(RESET, args.color), c(RESET, args.color));

    if plugins.is_empty() {
        let _ = writeln!(w, "  {}(none){}", c(DIM, args.color), c(RESET, args.color));
        return 0;
    }

    let rows: Vec<Vec<String>> = plugins.iter().map(|m| {
        let status_col = format!("{}{}{}",
            if m.status == PluginStatus::Enabled { c(GREEN, args.color) } else { c(YELLOW, args.color) },
            m.status,
            c(RESET, args.color));
        vec![m.id.clone(), m.name.clone(), m.version.to_string(), status_col, m.description.clone()]
    }).collect();
    print_table(&["ID", "Name", "Version", "Status", "Description"], &rows, args.color, w);
    0
}

/// Arguments for the `plugin install` command.
#[derive(Debug, Clone)]
pub struct InstallArgs {
    pub plugin_id: String,
    pub force: bool,
    pub json: bool,
    pub color: bool,
    pub dry_run: bool,
}

/// Install a plugin from a repository.
pub fn cmd_install(
    registry: &mut PluginRegistry,
    repo: &PluginRepository,
    args: &InstallArgs,
    w: &mut dyn io::Write,
) -> Result<i32, PluginCliError> {
    if registry.is_installed(&args.plugin_id) && !args.force {
        return Err(PluginCliError::AlreadyInstalled(args.plugin_id.clone()));
    }

    let entry = repo.find(&args.plugin_id)
        .ok_or_else(|| PluginCliError::NotFound(args.plugin_id.clone()))?;

    // Check API compatibility.
    if !registry.platform_api.compatible_with(&SemVer { major: entry.latest_version.major, minor: 0, patch: 0 }) {
        let _ = writeln!(w, "{}{}warn{}{} plugin {} targets API {}, platform is {}",
            c(BOLD, args.color), c(YELLOW, args.color), c(RESET, args.color), c(RESET, args.color),
            entry.id, entry.latest_version, registry.platform_api);
    }

    if args.dry_run {
        let _ = writeln!(w, "{}dry-run:{} would install {} v{}",
            c(DIM, args.color), c(RESET, args.color), entry.id, entry.latest_version);
        return Ok(0);
    }

    // Synthesise a manifest for the repo entry.
    let manifest_text = format!(
        "id = \"{}\"\nname = \"{}\"\nversion = \"{}\"\napi_version = \"{}\"\nauthor = \"repository\"\ndescription = \"{}\"\n",
        entry.id, entry.name, entry.latest_version, registry.platform_api, entry.description,
    );
    let manifest = PluginManifest::parse(&manifest_text)?;
    registry.insert(manifest);

    if args.json {
        let _ = writeln!(w, "{{\"action\":\"install\",\"id\":\"{}\",\"version\":\"{}\",\"ok\":true}}",
            entry.id, entry.latest_version);
    } else {
        let _ = writeln!(w, "  {} installed {} {}{}v{}{}",
            c(GREEN, args.color),
            entry.name,
            c(DIM, args.color), c(RESET, args.color),
            entry.latest_version, c(RESET, args.color));
    }
    Ok(0)
}

/// Arguments for the `plugin remove` command.
#[derive(Debug, Clone)]
pub struct RemoveArgs {
    pub plugin_id: String,
    pub json: bool,
    pub color: bool,
}

/// Remove an installed plugin.
pub fn cmd_remove(registry: &mut PluginRegistry, args: &RemoveArgs, w: &mut dyn io::Write)
    -> Result<i32, PluginCliError>
{
    let removed = registry.remove(&args.plugin_id)?;
    if args.json {
        let _ = writeln!(w, "{{\"action\":\"remove\",\"id\":\"{}\",\"ok\":true}}", removed.id);
    } else {
        let _ = writeln!(w, "  {}removed{} {} {}(v{}){}",
            c(RED, args.color), c(RESET, args.color),
            removed.id,
            c(DIM, args.color), removed.version, c(RESET, args.color));
    }
    Ok(0)
}

/// Arguments for the `plugin info` command.
#[derive(Debug, Clone)]
pub struct InfoArgs {
    pub plugin_id: String,
    pub json: bool,
    pub color: bool,
}

/// Show detailed plugin information.
pub fn cmd_info(registry: &PluginRegistry, args: &InfoArgs, w: &mut dyn io::Write)
    -> Result<i32, PluginCliError>
{
    let m = registry.get(&args.plugin_id)
        .ok_or_else(|| PluginCliError::NotFound(args.plugin_id.clone()))?;

    if args.json {
        let _ = writeln!(w,
            "{{\"id\":\"{}\",\"name\":\"{}\",\"version\":\"{}\",\"api_version\":\"{}\",\
            \"author\":\"{}\",\"status\":\"{}\",\"description\":\"{}\",\
            \"dependencies\":[{}],\"tags\":[{}]}}",
            m.id, m.name, m.version, m.api_version, m.author, m.status, m.description,
            m.dependencies.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(","),
            m.tags.iter().map(|t| format!("\"{t}\"")).collect::<Vec<_>>().join(","),
        );
        return Ok(0);
    }

    let kv = |w: &mut dyn io::Write, k: &str, v: &str| {
        let _ = writeln!(w, "  {}{:<20}{} {}", c(BOLD, args.color), k, c(RESET, args.color), v);
    };

    let _ = writeln!(w, "\n{}{}── Plugin: {} ──{}{}",
        c(BOLD, args.color), c(CYAN, args.color), m.name, c(RESET, args.color), c(RESET, args.color));
    kv(w, "ID",           &m.id);
    kv(w, "Version",      &m.version.to_string());
    kv(w, "API version",  &m.api_version.to_string());
    kv(w, "Author",       &m.author);
    kv(w, "Status",       m.status.label());
    kv(w, "Description",  &m.description);
    if let Some(ref h) = m.homepage { kv(w, "Homepage", h); }
    if let Some(ref l) = m.license  { kv(w, "License",  l); }
    kv(w, "Entry",  &m.entry);
    if !m.dependencies.is_empty() {
        kv(w, "Dependencies", &m.dependencies.join(", "));
    }
    if !m.optional_deps.is_empty() {
        kv(w, "Optional deps", &m.optional_deps.join(", "));
    }
    if !m.tags.is_empty() {
        kv(w, "Tags", &m.tags.join(", "));
    }
    if let Some(ts) = m.installed_at {
        kv(w, "Installed at", &format!("{}", ts));
    }
    Ok(0)
}

/// Update all installed plugins from the given repository.
pub fn cmd_update(
    registry: &mut PluginRegistry,
    repo: &PluginRepository,
    json: bool,
    color: bool,
    w: &mut dyn io::Write,
) -> i32 {
    let ids: Vec<String> = registry.all_sorted().iter().map(|m| m.id.clone()).collect();
    let mut updated = 0usize;
    let mut up_to_date = 0usize;

    for id in &ids {
        if let Some(entry) = repo.find(id) {
            let current_ver = registry.get(id).map(|m| m.version.clone());
            let newer = current_ver.map_or(true, |v| entry.latest_version > v);
            if newer {
                let install_args = InstallArgs {
                    plugin_id: id.clone(),
                    force: true, json, color, dry_run: false,
                };
                if cmd_install(registry, repo, &install_args, w).is_ok() {
                    updated += 1;
                }
            } else {
                up_to_date += 1;
            }
        }
    }

    if json {
        let _ = writeln!(w, "{{\"action\":\"update\",\"updated\":{updated},\"up_to_date\":{up_to_date}}}");
    } else {
        let _ = writeln!(w, "  {}update complete:{} {} updated, {} already up to date",
            c(GREEN, color), c(RESET, color), updated, up_to_date);
    }
    0
}

/// Validate installed plugins and report errors.
pub fn cmd_validate(registry: &PluginRegistry, json: bool, color: bool, w: &mut dyn io::Write) -> i32 {
    let errors = registry.validate();
    if json {
        let _ = w.write_all(b"[");
        for (i, e) in errors.iter().enumerate() {
            if i > 0 { let _ = w.write_all(b","); }
            let _ = write!(w, "\"{}\"", e);
        }
        let _ = w.write_all(b"]\n");
        return if errors.is_empty() { 0 } else { 1 };
    }
    if errors.is_empty() {
        let _ = writeln!(w, "  {}all plugins OK{}", c(GREEN, color), c(RESET, color));
        return 0;
    }
    for e in &errors {
        let _ = writeln!(w, "  {}error:{} {}", c(RED, color), c(RESET, color), e);
    }
    1
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> PluginRegistry {
        PluginRegistry::new(PathBuf::from("/tmp/plugins"), SemVer { major: 2, minor: 0, patch: 0 })
    }

    fn make_manifest(id: &str) -> PluginManifest {
        let text = format!(
            "id = \"{id}\"\nname = \"Test Plugin\"\nversion = \"1.0.0\"\napi_version = \"2.0.0\"\nauthor = \"tester\"\ndescription = \"A test plugin\"\n"
        );
        PluginManifest::parse(&text).unwrap()
    }

    #[test]
    fn test_semver_parse() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_semver_parse_bad() {
        assert!(SemVer::parse("1.2").is_err());
        assert!(SemVer::parse("a.b.c").is_err());
    }

    #[test]
    fn test_semver_compatible() {
        let platform = SemVer::parse("2.1.0").unwrap();
        let required = SemVer::parse("2.0.0").unwrap();
        assert!(platform.compatible_with(&required));

        let old = SemVer::parse("1.0.0").unwrap();
        assert!(!platform.compatible_with(&old));
    }

    #[test]
    fn test_manifest_parse_roundtrip() {
        let m = make_manifest("rustre.test");
        assert_eq!(m.id, "rustre.test");
        assert_eq!(m.version, SemVer::parse("1.0.0").unwrap());
        let toml = m.to_toml();
        assert!(toml.contains("rustre.test"));
    }

    #[test]
    fn test_registry_insert_get_remove() {
        let mut reg = make_registry();
        let m = make_manifest("rustre.test");
        reg.insert(m);
        assert!(reg.is_installed("rustre.test"));
        let removed = reg.remove("rustre.test").unwrap();
        assert_eq!(removed.id, "rustre.test");
        assert!(!reg.is_installed("rustre.test"));
    }

    #[test]
    fn test_registry_enable_disable() {
        let mut reg = make_registry();
        reg.insert(make_manifest("rustre.test"));
        reg.disable("rustre.test").unwrap();
        assert_eq!(reg.get("rustre.test").unwrap().status, PluginStatus::Disabled);
        reg.enable("rustre.test").unwrap();
        assert_eq!(reg.get("rustre.test").unwrap().status, PluginStatus::Enabled);
    }

    #[test]
    fn test_registry_validate_missing_dep() {
        let mut reg = make_registry();
        let text = "id = \"a\"\nname = \"A\"\nversion = \"1.0.0\"\napi_version = \"2.0.0\"\nauthor = \"x\"\ndescription = \"d\"\ndependencies = \"b\"\n";
        reg.insert(PluginManifest::parse(text).unwrap());
        let errs = reg.validate();
        assert!(!errs.is_empty());
    }

    #[test]
    fn test_repo_search() {
        let mut repo = PluginRepository::new("official", "https://example.com");
        repo.populate_stub();
        let results = repo.search("yara");
        assert!(!results.is_empty());
        assert!(results[0].id.contains("yara"));
    }

    #[test]
    fn test_cmd_list_json() {
        let mut reg = make_registry();
        reg.insert(make_manifest("rustre.test"));
        let mut buf = Vec::new();
        let args = ListArgs { json: true, color: false, ..Default::default() };
        cmd_list(&reg, &args, &mut buf);
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("rustre.test"));
        assert!(out.starts_with('['));
    }

    #[test]
    fn test_cmd_install_and_remove() {
        let mut reg = make_registry();
        let mut repo = PluginRepository::new("official", "https://example.com");
        repo.populate_stub();
        let args = InstallArgs {
            plugin_id: "rustre.yara".into(),
            force: false, json: false, color: false, dry_run: false,
        };
        let mut buf = Vec::new();
        cmd_install(&mut reg, &repo, &args, &mut buf).unwrap();
        assert!(reg.is_installed("rustre.yara"));
        let r_args = RemoveArgs { plugin_id: "rustre.yara".into(), json: false, color: false };
        cmd_remove(&mut reg, &r_args, &mut buf).unwrap();
        assert!(!reg.is_installed("rustre.yara"));
    }
}
