//! `rule_repository` — YARA rule repository: load from directory, git pull,
//! versioning, tag/category filtering, and rule metadata (author, date, family, TLP).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{Result, RuleSource, YaraRepoError};

// ── TLP classification ────────────────────────────────────────────────────────

/// Traffic Light Protocol classification for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tlp {
    White,
    Green,
    Amber,
    Red,
}

impl std::fmt::Display for Tlp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::White => write!(f, "TLP:WHITE"),
            Self::Green => write!(f, "TLP:GREEN"),
            Self::Amber => write!(f, "TLP:AMBER"),
            Self::Red   => write!(f, "TLP:RED"),
        }
    }
}

impl std::str::FromStr for Tlp {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "WHITE" | "TLP:WHITE" => Ok(Self::White),
            "GREEN" | "TLP:GREEN" => Ok(Self::Green),
            "AMBER" | "TLP:AMBER" => Ok(Self::Amber),
            "RED"   | "TLP:RED"   => Ok(Self::Red),
            _ => Err(format!("unknown TLP: {s}")),
        }
    }
}

// ── Rule metadata ─────────────────────────────────────────────────────────────

/// Rich metadata for a repository rule entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// YARA rule name.
    pub name: String,
    /// Author name or handle.
    pub author: String,
    /// ISO-8601 creation date.
    pub date: String,
    /// Malware family (e.g. "Emotet", "Cobalt Strike").
    pub family: Option<String>,
    /// Malware category (e.g. "trojan", "ransomware", "apt").
    pub category: Option<String>,
    /// Severity score 0–100.
    pub severity: u8,
    /// Tags (e.g. `["PE", "packed", "UPX"]`).
    pub tags: Vec<String>,
    /// TLP classification.
    pub tlp: Tlp,
    /// Source file path relative to the repository root.
    pub source_path: PathBuf,
    /// SHA-256 of the rule source.
    pub source_hash: String,
    /// Version string (e.g. "1.2.0").
    pub version: String,
    /// Unix timestamp of last update.
    pub updated_at: u64,
    /// References (CVEs, links, report URLs).
    pub references: Vec<String>,
}

impl RuleMetadata {
    fn from_source(name: impl Into<String>, source: &str, path: PathBuf) -> Self {
        // Extract metadata from YARA `meta:` section via simple text parsing.
        let mut author = String::from("unknown");
        let mut date   = String::from("unknown");
        let mut family = None;
        let mut category = None;
        let mut tags   = Vec::new();
        let mut tlp    = Tlp::White;
        let mut severity = 50u8;
        let mut references = Vec::new();
        let mut version = String::from("1.0.0");

        for line in source.lines() {
            let trimmed = line.trim();
            if let Some(v) = meta_value(trimmed, "author") { author = v; }
            if let Some(v) = meta_value(trimmed, "date")   { date = v; }
            if let Some(v) = meta_value(trimmed, "family") { family = Some(v); }
            if let Some(v) = meta_value(trimmed, "category") { category = Some(v); }
            if let Some(v) = meta_value(trimmed, "version") { version = v; }
            if let Some(v) = meta_value(trimmed, "reference") { references.push(v); }
            if let Some(v) = meta_value(trimmed, "tlp") {
                tlp = v.parse().unwrap_or(Tlp::White);
            }
            if let Some(v) = meta_value(trimmed, "severity") {
                severity = v.parse().unwrap_or(50);
            }
            if let Some(v) = meta_value(trimmed, "tags") {
                tags = v.split(',').map(|s| s.trim().to_string()).collect();
            }
        }

        Self {
            name: name.into(),
            author,
            date,
            family,
            category,
            severity,
            tags,
            tlp,
            source_path: path,
            source_hash: fnv1a_hex(source.as_bytes()),
            version,
            updated_at: unix_ts(),
            references,
        }
    }
}

fn meta_value(line: &str, key: &str) -> Option<String> {
    // Match lines like:  author = "John Doe"  or  author = John Doe
    let prefix = format!("{key} =");
    let line_lower = line.to_lowercase();
    if !line_lower.starts_with(&prefix) && !line_lower.starts_with(&format!("{key}\t=")) {
        return None;
    }
    let rest = line[prefix.len()..].trim();
    let value = rest.trim_matches('"').trim_matches('\'').to_string();
    if value.is_empty() { None } else { Some(value) }
}

// ── Repository entry ──────────────────────────────────────────────────────────

/// A single rule entry in the repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoEntry {
    pub id: u64,
    pub metadata: RuleMetadata,
    /// Raw YARA source text.
    pub source: String,
    /// Whether this rule is currently enabled.
    pub enabled: bool,
}

// ── Version info ──────────────────────────────────────────────────────────────

/// Repository version snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryVersion {
    /// Git commit hash or timestamp-based version.
    pub version_id: String,
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Number of rules at this version.
    pub rule_count: usize,
    /// Changelog lines since last version.
    pub changes: Vec<String>,
}

// ── Rule filter ───────────────────────────────────────────────────────────────

/// Filter parameters for querying the repository.
#[derive(Debug, Default, Clone)]
pub struct RuleFilter {
    pub tags: Vec<String>,
    pub categories: Vec<String>,
    pub families: Vec<String>,
    pub min_severity: Option<u8>,
    pub max_tlp: Option<Tlp>,
    pub enabled_only: bool,
    pub name_contains: Option<String>,
    pub author: Option<String>,
}

impl RuleFilter {
    #[must_use] 
    pub fn matches(&self, entry: &RepoEntry) -> bool {
        let m = &entry.metadata;

        if self.enabled_only && !entry.enabled { return false; }

        if let Some(min_sev) = self.min_severity
            && m.severity < min_sev { return false; }
        if let Some(max_tlp) = &self.max_tlp
            && m.tlp > *max_tlp { return false; }
        if !self.tags.is_empty() {
            let tag_set: HashSet<&str> = m.tags.iter().map(std::string::String::as_str).collect();
            if !self.tags.iter().any(|t| tag_set.contains(t.as_str())) {
                return false;
            }
        }
        if !self.categories.is_empty() {
            match &m.category {
                None => return false,
                Some(cat) => {
                    if !self.categories.iter().any(|c| c.eq_ignore_ascii_case(cat)) {
                        return false;
                    }
                }
            }
        }
        if !self.families.is_empty() {
            match &m.family {
                None => return false,
                Some(fam) => {
                    if !self.families.iter().any(|f| f.eq_ignore_ascii_case(fam)) {
                        return false;
                    }
                }
            }
        }
        if let Some(nc) = &self.name_contains
            && !m.name.to_lowercase().contains(&nc.to_lowercase()) {
                return false;
            }
        if let Some(auth) = &self.author
            && !m.author.to_lowercase().contains(&auth.to_lowercase()) {
                return false;
            }
        true
    }
}

// ── RuleRepository ────────────────────────────────────────────────────────────

/// In-memory YARA rule repository with versioning and filtering.
pub struct RuleRepository {
    entries: Vec<RepoEntry>,
    next_id: u64,
    versions: Vec<RepositoryVersion>,
    sources: Vec<RuleSource>,
}

impl RuleRepository {
    /// Create an empty repository.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 1,
            versions: Vec::new(),
            sources: Vec::new(),
        }
    }

    /// Add a rule source definition (directory, git, HTTP).
    pub fn add_source(&mut self, src: RuleSource) {
        self.sources.push(src);
    }

    /// Load rules from a directory.
    ///
    /// Recursively scans `*.yar` and `*.yara` files.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::Io`] if any rule file cannot be read.
    pub fn load_directory(&mut self, root: &Path) -> Result<usize> {
        let files = collect_yara_files(root);
        let mut loaded = 0;
        for path in files {
            let src = std::fs::read_to_string(&path)
                .map_err(|e| YaraRepoError::Io(e.to_string()))?;
            let names = extract_rule_names(&src);
            for name in names {
                self.insert_rule(&name, src.clone(), path.clone());
                loaded += 1;
            }
        }
        self.snapshot_version(&format!("dir:{}", root.display()));
        Ok(loaded)
    }

    /// Load a single rule source string.
    ///
    /// # Errors
    /// Currently infallible at this layer, but reserved for future validation
    /// failures during parsing.
    pub fn load_source(&mut self, source: impl Into<String>, label: impl Into<String>) -> Result<usize> {
        let src = source.into();
        let path = PathBuf::from(label.into());
        let names = extract_rule_names(&src);
        let count = names.len();
        for name in names {
            self.insert_rule(&name, src.clone(), path.clone());
        }
        Ok(count)
    }

    fn insert_rule(&mut self, name: &str, source: String, path: PathBuf) -> u64 {
        // Deduplicate by name — update if already exists
        if let Some(e) = self.entries.iter_mut().find(|e| e.metadata.name == name) {
            e.source.clone_from(&source);
            e.metadata = RuleMetadata::from_source(name, &source, path);
            return e.id;
        }
        let id = self.next_id;
        self.next_id += 1;
        let metadata = RuleMetadata::from_source(name, &source, path);
        self.entries.push(RepoEntry { id, metadata, source, enabled: true });
        id
    }

    /// Pull updates from all git sources (stub — calls `git pull` via process).
    ///
    /// # Errors
    /// Returns [`YaraRepoError::Io`] / [`YaraRepoError::SyncError`] if a pull
    /// or subsequent reload of the updated working tree fails.
    pub fn pull_updates(&mut self) -> Result<Vec<String>> {
        // Collect (url, local_path) pairs first to avoid holding an immutable borrow
        // while calling the mutable `load_directory`.
        let git_sources: Vec<(String, std::path::PathBuf)> = self.sources.iter()
            .filter_map(|src| {
                if let RuleSource::Git { url, local_path, enabled, .. } = src {
                    if *enabled { Some((url.clone(), local_path.clone())) } else { None }
                } else {
                    None
                }
            })
            .collect();

        let mut updated = Vec::new();
        for (url, local_path) in git_sources {
            match run_git_pull(&local_path) {
                Ok(output) if output.contains("Already up to date") => {}
                Ok(_) => {
                    let _ = self.load_directory(&local_path);
                    updated.push(url);
                }
                Err(e) => {
                    return Err(YaraRepoError::SyncError(format!("git pull failed: {e}")));
                }
            }
        }
        Ok(updated)
    }

    /// Query rules matching the given filter.
    #[must_use] 
    pub fn query(&self, filter: &RuleFilter) -> Vec<&RepoEntry> {
        self.entries.iter().filter(|e| filter.matches(e)).collect()
    }

    /// Get all enabled rule sources as (name, source) pairs.
    #[must_use] 
    pub fn enabled_rules(&self) -> Vec<(String, String)> {
        self.entries.iter()
            .filter(|e| e.enabled)
            .map(|e| (e.metadata.name.clone(), e.source.clone()))
            .collect()
    }

    /// Enable or disable a rule by name.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(e) = self.entries.iter_mut().find(|e| e.metadata.name == name) {
            e.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Get a specific rule by name.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&RepoEntry> {
        self.entries.iter().find(|e| e.metadata.name == name)
    }

    /// Number of rules in the repository.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All unique tags across the repository.
    #[must_use] 
    pub fn all_tags(&self) -> HashSet<String> {
        self.entries.iter()
            .flat_map(|e| e.metadata.tags.iter().cloned())
            .collect()
    }

    /// All unique categories.
    #[must_use] 
    pub fn all_categories(&self) -> HashSet<String> {
        self.entries.iter()
            .filter_map(|e| e.metadata.category.clone())
            .collect()
    }

    /// All unique families.
    #[must_use] 
    pub fn all_families(&self) -> HashSet<String> {
        self.entries.iter()
            .filter_map(|e| e.metadata.family.clone())
            .collect()
    }

    /// Current version history.
    #[must_use] 
    pub fn versions(&self) -> &[RepositoryVersion] {
        &self.versions
    }

    fn snapshot_version(&mut self, label: &str) {
        let v = RepositoryVersion {
            version_id: format!("{}-{}", label, unix_ts()),
            timestamp: iso_timestamp(),
            rule_count: self.entries.len(),
            changes: Vec::new(),
        };
        self.versions.push(v);
    }

    /// Export all rules to a directory, one file per rule.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::Io`] if the destination directory cannot be
    /// created or a rule file cannot be written.
    pub fn export_to_dir(&self, root: &Path) -> Result<usize> {
        std::fs::create_dir_all(root)
            .map_err(|e| YaraRepoError::Io(e.to_string()))?;
        let mut count = 0;
        for entry in &self.entries {
            let fname = sanitize_filename(&entry.metadata.name);
            let path = root.join(format!("{fname}.yar"));
            std::fs::write(&path, &entry.source)
                .map_err(|e| YaraRepoError::Io(e.to_string()))?;
            count += 1;
        }
        Ok(count)
    }

    /// Summary statistics.
    #[must_use] 
    pub fn stats(&self) -> RepositoryStats {
        let enabled = self.entries.iter().filter(|e| e.enabled).count();
        let by_tlp = {
            let mut m: HashMap<String, usize> = HashMap::new();
            for e in &self.entries {
                *m.entry(e.metadata.tlp.to_string()).or_insert(0) += 1;
            }
            m
        };
        let by_severity = {
            let mut counts = [0usize; 5];
            for e in &self.entries {
                let bucket = (e.metadata.severity / 20).min(4) as usize;
                counts[bucket] += 1;
            }
            counts
        };
        RepositoryStats {
            total: self.entries.len(),
            enabled,
            disabled: self.entries.len() - enabled,
            by_tlp,
            by_severity,
        }
    }
}

impl Default for RuleRepository {
    fn default() -> Self { Self::new() }
}

/// Repository statistics summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryStats {
    pub total: usize,
    pub enabled: usize,
    pub disabled: usize,
    pub by_tlp: HashMap<String, usize>,
    pub by_severity: [usize; 5], // [0-19, 20-39, 40-59, 60-79, 80-100]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn collect_yara_files(root: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Some(ext) = p.extension()
                && (ext == "yar" || ext == "yara") {
                    result.push(p);
                }
        }
    }
    result
}

fn extract_rule_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = source.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        // Skip whitespace and comments
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() { pos += 1; }
        if pos + 5 < bytes.len() && &bytes[pos..pos + 4] == b"rule" && bytes[pos + 4].is_ascii_whitespace() {
            pos += 5;
            while pos < bytes.len() && bytes[pos].is_ascii_whitespace() { pos += 1; }
            let start = pos;
            while pos < bytes.len() && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
                pos += 1;
            }
            if pos > start {
                names.push(String::from_utf8_lossy(&bytes[start..pos]).to_string());
            }
        } else {
            pos += 1;
        }
    }
    names
}

fn run_git_pull(path: &Path) -> std::result::Result<String, String> {
    std::process::Command::new("git")
        .args(["-C", &path.display().to_string(), "pull", "--ff-only"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .map_err(|e| e.to_string())
}

fn unix_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn iso_timestamp() -> String {
    // Without chrono, produce a basic numeric timestamp.
    format!("{}", unix_ts())
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

fn fnv1a_hex(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str = r#"
rule detect_eicar : test antivirus {
    meta:
        author = "EICAR"
        date = "2024-01-01"
        family = "EICAR"
        category = "test"
        severity = 80
        tlp = "WHITE"
        tags = "test,eicar,av"
    strings:
        $s = "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    condition:
        $s
}
"#;

    #[test]
    fn test_load_source() {
        let mut repo = RuleRepository::new();
        let count = repo.load_source(SAMPLE_RULE, "test.yar").unwrap();
        assert_eq!(count, 1);
        assert!(repo.get("detect_eicar").is_some());
    }

    #[test]
    fn test_metadata_extraction() {
        let meta = RuleMetadata::from_source("detect_eicar", SAMPLE_RULE, PathBuf::from("test.yar"));
        assert_eq!(meta.author, "EICAR");
        assert_eq!(meta.tlp, Tlp::White);
        assert_eq!(meta.severity, 80);
    }

    #[test]
    fn test_filter_by_tag() {
        let mut repo = RuleRepository::new();
        repo.load_source(SAMPLE_RULE, "test.yar").unwrap();
        let filter = RuleFilter {
            tags: vec!["eicar".to_string()],
            ..Default::default()
        };
        let results = repo.query(&filter);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_filter_by_severity() {
        let mut repo = RuleRepository::new();
        repo.load_source(SAMPLE_RULE, "test.yar").unwrap();
        let filter = RuleFilter {
            min_severity: Some(90),
            ..Default::default()
        };
        let results = repo.query(&filter);
        assert_eq!(results.len(), 0); // severity is 80, below 90
    }

    #[test]
    fn test_enable_disable() {
        let mut repo = RuleRepository::new();
        repo.load_source(SAMPLE_RULE, "test.yar").unwrap();
        assert!(repo.set_enabled("detect_eicar", false));
        assert!(!repo.get("detect_eicar").unwrap().enabled);
    }

    #[test]
    fn test_stats() {
        let mut repo = RuleRepository::new();
        repo.load_source(SAMPLE_RULE, "test.yar").unwrap();
        let stats = repo.stats();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.enabled, 1);
    }
}
