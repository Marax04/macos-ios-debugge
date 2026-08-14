// rustre-yara-rules/src/sync.rs
//! YARA rule synchronisation from git repositories and local directories.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for a single rule-sync source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSyncConfig {
    /// Remote git URL (e.g. `https://github.com/Yara-Rules/rules.git`).
    pub remote_url: String,
    /// Local clone path.
    pub local_path: PathBuf,
    /// Branch to track.
    pub branch: String,
    /// Whether this source is currently active.
    pub enabled: bool,
    /// Optional sub-directory inside the repo to search for `.yar` files.
    pub rules_subdir: Option<String>,
    /// Maximum file age in seconds before considered stale.
    pub max_age_secs: u64,
    /// Optional authentication token (for private repos).
    pub auth_token: Option<String>,
}

impl RuleSyncConfig {
    /// Create a new config with default settings.
    pub fn new(
        remote_url: impl Into<String>,
        local_path: impl Into<PathBuf>,
        branch: impl Into<String>,
    ) -> Self {
        Self {
            remote_url: remote_url.into(),
            local_path: local_path.into(),
            branch: branch.into(),
            enabled: true,
            rules_subdir: None,
            max_age_secs: 86400, // 24 h
            auth_token: None,
        }
    }

    /// Set the rules sub-directory.
    #[must_use]
    pub fn with_subdir(mut self, dir: impl Into<String>) -> Self {
        self.rules_subdir = Some(dir.into());
        self
    }

    /// Disable this source.
    #[must_use] 
    pub const fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Set authentication token.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Return the effective search root (`local_path` + optional subdir).
    #[must_use] 
    pub fn search_root(&self) -> PathBuf {
        self.rules_subdir.as_ref().map_or_else(|| self.local_path.clone(), |sub| self.local_path.join(sub))
    }
}

// ─── Sync result ──────────────────────────────────────────────────────────────

/// Result of a single sync operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncResult {
    pub source_url: String,
    pub local_path: String,
    pub success: bool,
    pub files_found: usize,
    pub rules_loaded: usize,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

impl SyncResult {
    #[must_use] 
    pub fn ok(url: &str, local: &str, files: usize, rules: usize, ms: u64) -> Self {
        Self {
            source_url: url.to_string(),
            local_path: local.to_string(),
            success: true,
            files_found: files,
            rules_loaded: rules,
            errors: Vec::new(),
            duration_ms: ms,
        }
    }

    pub fn err(url: &str, local: &str, error: impl Into<String>) -> Self {
        Self {
            source_url: url.to_string(),
            local_path: local.to_string(),
            success: false,
            files_found: 0,
            rules_loaded: 0,
            errors: vec![error.into()],
            duration_ms: 0,
        }
    }
}

// ─── Parsed rule file ─────────────────────────────────────────────────────────

/// A single parsed `.yar` / `.yara` file result.
#[derive(Debug, Clone)]
pub struct ParsedRuleFile {
    pub path: PathBuf,
    pub rule_texts: Vec<String>,
    pub rule_names: Vec<String>,
    pub errors: Vec<String>,
}

impl ParsedRuleFile {
    #[must_use] 
    pub const fn rule_count(&self) -> usize {
        self.rule_names.len()
    }
}

// ─── Sync engine ─────────────────────────────────────────────────────────────

/// High-level sync engine.
pub struct RuleSyncEngine {
    configs: Vec<RuleSyncConfig>,
}

impl RuleSyncEngine {
    #[must_use] 
    pub const fn new(configs: Vec<RuleSyncConfig>) -> Self {
        Self { configs }
    }

    /// Add a popular public YARA repository with default config.
    pub fn add_popular_sources(&mut self) {
        for cfg in popular_sources() {
            self.configs.push(cfg);
        }
    }

    /// Sync all enabled sources, returning one result per source.
    #[must_use] 
    pub fn sync_all(&self) -> Vec<SyncResult> {
        self.configs
            .iter()
            .filter(|c| c.enabled)
            .map(sync_rules)
            .collect()
    }

    /// Sync a single source by remote URL.
    pub fn sync_by_url(&self, url: &str) -> Option<SyncResult> {
        self.configs
            .iter()
            .find(|c| c.remote_url == url && c.enabled)
            .map(sync_rules)
    }

    /// Load all rule files from all local paths (no network required).
    #[must_use] 
    pub fn load_local(&self) -> Vec<ParsedRuleFile> {
        let mut results = Vec::new();
        for cfg in self.configs.iter().filter(|c| c.enabled) {
            let root = cfg.search_root();
            if root.exists() {
                results.extend(parse_rule_files_from_dir(&root));
            }
        }
        results
    }

    /// Return summary: `(total_sources, local_available, total_rules_on_disk)`.
    #[must_use] 
    pub fn summary(&self) -> (usize, usize, usize) {
        let total = self.configs.len();
        let local: usize = self
            .configs
            .iter()
            .filter(|c| c.search_root().exists())
            .count();
        let rules: usize = self.load_local().iter().map(ParsedRuleFile::rule_count).sum();
        (total, local, rules)
    }
}

// ─── Core sync function ───────────────────────────────────────────────────────

/// Attempt to sync rules from the given config.
///
/// This function tries `git pull` if a `git` binary is available.
/// If git is unavailable or the local path does not exist yet, it
/// records the error but still reads whatever is already on disk.
#[must_use] 
pub fn sync_rules(config: &RuleSyncConfig) -> SyncResult {
    let t0 = std::time::Instant::now();
    let local_str = config.local_path.to_string_lossy().to_string();

    if !config.enabled {
        return SyncResult::err(&config.remote_url, &local_str, "source disabled");
    }

    // If local path exists, try git pull; otherwise try git clone.
    if config.local_path.exists() {
        let pull_result = git_pull(&config.local_path, &config.branch);
        if let Err(e) = pull_result {
            // Non-fatal: fall through to reading what is there
            let files = parse_rule_files_from_dir(&config.search_root());
            let rule_count: usize = files.iter().map(ParsedRuleFile::rule_count).sum();
            return SyncResult {
                source_url: config.remote_url.clone(),
                local_path: local_str,
                success: false,
                files_found: files.len(),
                rules_loaded: rule_count,
                errors: vec![format!("git pull failed: {e}")],
                duration_ms: crate::casts::u128_to_u64_sat(t0.elapsed().as_millis()),
            };
        }
    } else {
        // git clone
        if let Err(e) = git_clone(&config.remote_url, &config.local_path, &config.branch) {
            return SyncResult::err(
                &config.remote_url,
                &local_str,
                format!("git clone failed: {e}"),
            );
        }
    }

    // Read all rule files
    let files = parse_rule_files_from_dir(&config.search_root());
    let rule_count: usize = files.iter().map(ParsedRuleFile::rule_count).sum();
    let file_count = files.len();

    SyncResult::ok(
        &config.remote_url,
        &local_str,
        file_count,
        rule_count,
        crate::casts::u128_to_u64_sat(t0.elapsed().as_millis()),
    )
}

// ─── Git helpers ──────────────────────────────────────────────────────────────

fn git_pull(path: &Path, branch: &str) -> Result<(), String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("pull")
        .arg("origin")
        .arg(branch)
        .output()
        .map_err(|e| format!("failed to execute git: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn git_clone(url: &str, dest: &Path, branch: &str) -> Result<(), String> {
    // Create parent directories if needed
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
    }

    let output = std::process::Command::new("git")
        .arg("clone")
        .arg("--depth=1")
        .arg("--branch")
        .arg(branch)
        .arg(url)
        .arg(dest)
        .output()
        .map_err(|e| format!("failed to execute git: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ─── Directory parser ─────────────────────────────────────────────────────────

/// Recursively walk `dir` and parse all `.yar` / `.yara` files.
#[must_use] 
pub fn parse_rule_files_from_dir(dir: &Path) -> Vec<ParsedRuleFile> {
    let mut results = Vec::new();
    walk_dir(dir, &mut results);
    results
}

fn walk_dir(dir: &Path, out: &mut Vec<ParsedRuleFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, out);
        } else {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "yar" || ext == "yara" {
                out.push(parse_yar_file(&path));
            }
        }
    }
}

/// Parse a single `.yar` or `.yara` file.
#[must_use] 
pub fn parse_yar_file(path: &Path) -> ParsedRuleFile {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            return ParsedRuleFile {
                path: path.to_path_buf(),
                rule_texts: Vec::new(),
                rule_names: Vec::new(),
                errors: vec![format!("read error: {e}")],
            };
        }
    };
    parse_yar_text(&text, path)
}

/// Parse YARA rule text, returning individual rule texts and names.
#[must_use] 
pub fn parse_yar_text(text: &str, path: &Path) -> ParsedRuleFile {
    let mut rule_texts = Vec::new();
    let mut rule_names = Vec::new();
    let mut errors = Vec::new();

    let mut current = String::new();
    let mut in_rule = false;
    let mut depth = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();

        // Skip comment lines
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }

        // Detect rule start
        if !in_rule && (trimmed.starts_with("rule ") || trimmed.starts_with("private rule ")) {
            in_rule = true;
            depth = 0;
            current.clear();
        }

        if in_rule {
            current.push_str(line);
            current.push('\n');
            for ch in line.chars() {
                if ch == '{' {
                    depth += 1;
                }
                if ch == '}' && depth > 0 {
                    depth -= 1;
                }
            }
            if depth == 0 && current.contains('{') {
                // Extract rule name
                let name = extract_rule_name(&current);
                if let Some(n) = name {
                    rule_names.push(n);
                    rule_texts.push(current.clone());
                } else {
                    errors.push(format!(
                        "could not extract rule name from: {}",
                        &current[..current.len().min(80)]
                    ));
                }
                in_rule = false;
                current.clear();
            }
        }
    }

    ParsedRuleFile {
        path: path.to_path_buf(),
        rule_texts,
        rule_names,
        errors,
    }
}

fn extract_rule_name(text: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("rule ") || t.starts_with("private rule ") {
            return t
                .split_whitespace()
                .find(|&w| w != "private" && w != "rule")
                .map(|w| {
                    w.trim_end_matches(':')
                        .trim_end_matches('{')
                        .trim()
                        .to_string()
                });
        }
    }
    None
}

// ─── Rule file index ──────────────────────────────────────────────────────────

/// An index mapping rule names to their source file paths.
#[derive(Debug, Default)]
pub struct RuleFileIndex {
    index: HashMap<String, PathBuf>,
}

impl RuleFileIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index from a set of parsed rule files.
    #[must_use] 
    pub fn from_files(files: &[ParsedRuleFile]) -> Self {
        let mut idx = Self::new();
        for file in files {
            for name in &file.rule_names {
                idx.index.insert(name.clone(), file.path.clone());
            }
        }
        idx
    }

    /// Look up the source file for a rule by name.
    #[must_use] 
    pub fn lookup(&self, name: &str) -> Option<&PathBuf> {
        self.index.get(name)
    }

    /// Total rules indexed.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.index.len()
    }
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// All indexed rule names.
    #[must_use] 
    pub fn rule_names(&self) -> Vec<&str> {
        self.index.keys().map(std::string::String::as_str).collect()
    }
}

// ─── Popular public sources ───────────────────────────────────────────────────

/// Returns a set of commonly used public YARA rule repositories.
#[must_use] 
pub fn popular_sources() -> Vec<RuleSyncConfig> {
    vec![
        RuleSyncConfig::new(
            "https://github.com/Yara-Rules/rules.git",
            dirs_home().join("yara-repos/yara-rules"),
            "master",
        ),
        RuleSyncConfig::new(
            "https://github.com/Neo23x0/signature-base.git",
            dirs_home().join("yara-repos/signature-base"),
            "master",
        ),
        RuleSyncConfig::new(
            "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
            dirs_home().join("yara-repos/reversinglabs"),
            "develop",
        ),
        RuleSyncConfig::new(
            "https://github.com/elastic/detection-rules.git",
            dirs_home().join("yara-repos/elastic-detection-rules"),
            "main",
        ),
        RuleSyncConfig::new(
            "https://github.com/bartblaze/Yara-rules.git",
            dirs_home().join("yara-repos/bartblaze"),
            "master",
        ),
        RuleSyncConfig::new(
            "https://github.com/MalGamy/YARA_Rules.git",
            dirs_home().join("yara-repos/malgamy"),
            "main",
        )
        .disabled(),
        RuleSyncConfig::new(
            "https://github.com/JPCERTCC/jpcert-yara.git",
            dirs_home().join("yara-repos/jpcert"),
            "main",
        ),
        RuleSyncConfig::new(
            "https://github.com/mandiant/red_team_tool_countermeasures.git",
            dirs_home().join("yara-repos/mandiant-redteam"),
            "master",
        ),
    ]
}

fn dirs_home() -> PathBuf {
    // Resolve home directory without the `dirs` crate
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE")).map_or_else(|_| PathBuf::from("/tmp"), PathBuf::from);
    home.join(".rustre")
}

// ─── Rule cache ───────────────────────────────────────────────────────────────

/// Simple on-disk cache for synced rule content.
pub struct RuleCache {
    cache_dir: PathBuf,
}

impl RuleCache {
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        let dir = cache_dir.into();
        let _ = std::fs::create_dir_all(&dir);
        Self { cache_dir: dir }
    }

    /// Store rule text keyed by name.
    ///
    /// # Errors
    /// Returns any I/O error encountered when writing the file.
    pub fn store(&self, name: &str, text: &str) -> std::io::Result<()> {
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = self.cache_dir.join(format!("{safe_name}.yar"));
        std::fs::write(path, text)
    }

    /// Retrieve cached rule text by name.
    #[must_use] 
    pub fn load(&self, name: &str) -> Option<String> {
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = self.cache_dir.join(format!("{safe_name}.yar"));
        std::fs::read_to_string(path).ok()
    }

    /// List all cached rule names.
    #[must_use] 
    pub fn list(&self) -> Vec<String> {
        std::fs::read_dir(&self.cache_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("yar") {
                    p.file_stem()
                        .and_then(|s| s.to_str())
                        .map(std::string::ToString::to_string)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Clear all cached files.
    pub fn clear(&self) {
        for name in self.list() {
            let path = self.cache_dir.join(format!("{name}.yar"));
            let _ = std::fs::remove_file(path);
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popular_sources_not_empty() {
        let sources = popular_sources();
        assert!(!sources.is_empty());
    }

    #[test]
    fn rule_sync_config_search_root_with_subdir() {
        let cfg = RuleSyncConfig::new("url", "/tmp/test", "main").with_subdir("rules/malware");
        assert!(
            cfg.search_root()
                .to_string_lossy()
                .contains("rules/malware")
        );
    }

    #[test]
    fn rule_sync_config_disabled() {
        let cfg = RuleSyncConfig::new("url", "/tmp/test", "main").disabled();
        assert!(!cfg.enabled);
    }

    #[test]
    fn parse_yar_text_extracts_rules() {
        let text = r#"
rule TestRule1 {
    meta:
        author = "test"
    strings:
        $s1 = "mimikatz"
    condition:
        $s1
}

rule TestRule2 {
    strings:
        $s2 = "sekurlsa"
    condition:
        $s2
}
"#;
        let parsed = parse_yar_text(text, Path::new("/tmp/test.yar"));
        assert_eq!(parsed.rule_names.len(), 2);
        assert!(parsed.rule_names.contains(&"TestRule1".to_string()));
        assert!(parsed.rule_names.contains(&"TestRule2".to_string()));
    }

    #[test]
    fn extract_rule_name_basic() {
        let text = "rule Mirai_Botnet {\n strings:\n $s1 = \"mirai\"\n condition:\n $s1\n}\n";
        let name = extract_rule_name(text);
        assert_eq!(name, Some("Mirai_Botnet".to_string()));
    }

    #[test]
    fn rule_file_index_lookup() {
        let file = ParsedRuleFile {
            path: PathBuf::from("/tmp/rules.yar"),
            rule_texts: vec!["rule A {}".to_string()],
            rule_names: vec!["A".to_string()],
            errors: Vec::new(),
        };
        let idx = RuleFileIndex::from_files(&[file]);
        assert!(idx.lookup("A").is_some());
        assert!(idx.lookup("B").is_none());
    }

    #[test]
    fn sync_result_err_not_success() {
        let r = SyncResult::err("http://x", "/tmp/y", "network error");
        assert!(!r.success);
        assert_eq!(r.errors.len(), 1);
    }

    #[test]
    fn sync_result_ok_success() {
        let r = SyncResult::ok("http://x", "/tmp/y", 3, 12, 100);
        assert!(r.success);
        assert_eq!(r.rules_loaded, 12);
    }

    #[test]
    fn sync_engine_summary_no_local() {
        let engine = RuleSyncEngine::new(vec![
            RuleSyncConfig::new("http://x", "/nonexistent/path/a", "main"),
            RuleSyncConfig::new("http://y", "/nonexistent/path/b", "main"),
        ]);
        let (total, local, _rules) = engine.summary();
        assert_eq!(total, 2);
        assert_eq!(local, 0);
    }

    #[test]
    fn parse_rule_file_nonexistent() {
        let result = parse_yar_file(Path::new("/nonexistent/file.yar"));
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn rule_cache_store_and_load() {
        let tmp = std::env::temp_dir().join("rustre_sync_cache_test");
        let cache = RuleCache::new(&tmp);
        cache.store("test_rule", "rule test {}").unwrap();
        let loaded = cache.load("test_rule");
        assert_eq!(loaded, Some("rule test {}".to_string()));
        cache.clear();
        assert!(cache.load("test_rule").is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
