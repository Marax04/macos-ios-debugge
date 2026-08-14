// rustre-yara-rules/src/lib.rs
// Complete YARA rule repository manager

pub mod casts;
pub mod builtin_rules;
pub mod rule_compiler;
pub mod rule_db;
pub mod rule_generator;
pub mod rule_metadata;
pub mod rule_repository;
pub mod rule_testing;
pub mod rule_validator;
pub mod sync;
pub mod rule_optimizer_pass;
pub mod rule_coverage_tracker;
pub mod apt_detection_rules;
pub mod packer_detection_rules;
pub mod ransomware_rules;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use parking_lot::RwLock;
use std::sync::Arc;

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum YaraRepoError {
    Io(String),
    ParseError(String),
    SqliteError(String),
    CompileError(String),
    SyncError(String),
    NotFound(String),
    InvalidRule(String),
}

impl std::fmt::Display for YaraRepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "IO error: {s}"),
            Self::ParseError(s) => write!(f, "Parse error: {s}"),
            Self::SqliteError(s) => write!(f, "SQLite error: {s}"),
            Self::CompileError(s) => write!(f, "Compile error: {s}"),
            Self::SyncError(s) => write!(f, "Sync error: {s}"),
            Self::NotFound(s) => write!(f, "Not found: {s}"),
            Self::InvalidRule(s) => write!(f, "Invalid rule: {s}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, YaraRepoError>;

// ─── Rule Source ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RuleSource {
    Git {
        url: String,
        branch: String,
        local_path: PathBuf,
        enabled: bool,
    },
    Http {
        url: String,
        refresh_secs: u64,
        enabled: bool,
    },
    Local {
        path: PathBuf,
        enabled: bool,
    },
}

impl RuleSource {
    #[must_use] 
    pub const fn is_enabled(&self) -> bool {
        match self {
            Self::Git { enabled, .. }
            | Self::Http { enabled, .. }
            | Self::Local { enabled, .. } => *enabled,
        }
    }

    #[must_use] 
    pub fn name(&self) -> String {
        match self {
            Self::Git { url, branch, .. } => format!("git:{url}@{branch}"),
            Self::Http { url, .. } => format!("http:{url}"),
            Self::Local { path, .. } => format!("local:{}", path.display()),
        }
    }

    pub const fn set_enabled(&mut self, val: bool) {
        match self {
            Self::Git { enabled, .. }
            | Self::Http { enabled, .. }
            | Self::Local { enabled, .. } => *enabled = val,
        }
    }
}

// ─── Rule Metadata ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleMeta {
    pub rule_id: String,
    pub name: String,
    pub namespace: String,
    pub author: String,
    pub date: String,
    pub description: String,
    pub tags: Vec<String>,
    pub category: RuleCategory,
    pub severity: Severity,
    pub hash: String,
    pub file_path: String,
    pub enabled: bool,
    pub source_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleCategory {
    Malware,
    Packers,
    CryptoConstants,
    ExploitTools,
    SuspiciousPatterns,
    Trojan,
    Ransomware,
    Spyware,
    Adware,
    Rootkit,
    Bootkit,
    Worm,
    Backdoor,
    InfoStealer,
    Loader,
    Dropper,
    Unknown,
}

impl RuleCategory {
    #[must_use]
    pub fn from_label(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "malware" => Self::Malware,
            "packers" | "packer" => Self::Packers,
            "crypto" | "crypto_constants" | "cryptographic" => Self::CryptoConstants,
            "exploit" | "exploit_tools" | "exploittools" => Self::ExploitTools,
            "suspicious" | "suspicious_patterns" => Self::SuspiciousPatterns,
            "trojan" => Self::Trojan,
            "ransomware" => Self::Ransomware,
            "spyware" => Self::Spyware,
            "adware" => Self::Adware,
            "rootkit" => Self::Rootkit,
            "bootkit" => Self::Bootkit,
            "worm" => Self::Worm,
            "backdoor" => Self::Backdoor,
            "infostealer" | "info_stealer" => Self::InfoStealer,
            "loader" => Self::Loader,
            "dropper" => Self::Dropper,
            _ => Self::Unknown,
        }
    }

    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Malware => "malware",
            Self::Packers => "packers",
            Self::CryptoConstants => "crypto_constants",
            Self::ExploitTools => "exploit_tools",
            Self::SuspiciousPatterns => "suspicious_patterns",
            Self::Trojan => "trojan",
            Self::Ransomware => "ransomware",
            Self::Spyware => "spyware",
            Self::Adware => "adware",
            Self::Rootkit => "rootkit",
            Self::Bootkit => "bootkit",
            Self::Worm => "worm",
            Self::Backdoor => "backdoor",
            Self::InfoStealer => "info_stealer",
            Self::Loader => "loader",
            Self::Dropper => "dropper",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub fn from_label(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Self::Info,
            "low" => Self::Low,
            "high" => Self::High,
            "critical" | "crit" => Self::Critical,
            _ => Self::Medium,
        }
    }
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

// ─── Compiled Rule Set ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompiledRuleSet {
    pub id: String,
    pub rules_text: String,
    pub rule_count: usize,
    pub compiled_at: SystemTime,
}

impl CompiledRuleSet {
    #[must_use] 
    pub fn new(id: String, rules_text: String, rule_count: usize) -> Self {
        Self {
            id,
            rules_text,
            rule_count,
            compiled_at: SystemTime::now(),
        }
    }
}

// ─── Match Result ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Match {
    pub rule_id: String,
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub category: RuleCategory,
    pub severity: Severity,
    pub strings: Vec<StringMatch>,
    pub meta: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct StringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
}

// ─── Sync Report ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SyncReport {
    pub source_name: String,
    pub files_scanned: usize,
    pub rules_added: usize,
    pub rules_updated: usize,
    pub rules_unchanged: usize,
    pub errors: Vec<String>,
    pub duration_ms: u64,
    pub synced_at: Option<SystemTime>,
}

// ─── Statistics ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RepoStats {
    pub total_rules: usize,
    pub enabled_count: usize,
    pub disabled_count: usize,
    pub by_category: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
    pub last_sync_times: HashMap<String, SystemTime>,
}

// ─── In-memory DB ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct InMemoryDb {
    rules: HashMap<String, RuleMeta>,
    rule_texts: HashMap<String, String>,
}

impl InMemoryDb {
    fn upsert_rule(&mut self, meta: RuleMeta, text: String) {
        self.rule_texts.insert(meta.rule_id.clone(), text);
        self.rules.insert(meta.rule_id.clone(), meta);
    }

    fn get_rule(&self, id: &str) -> Option<&RuleMeta> {
        self.rules.get(id)
    }

    fn get_rule_mut(&mut self, id: &str) -> Option<&mut RuleMeta> {
        self.rules.get_mut(id)
    }

    fn list_rules(&self, enabled_only: bool) -> Vec<RuleMeta> {
        self.rules
            .values()
            .filter(|r| !enabled_only || r.enabled)
            .cloned()
            .collect()
    }

    fn get_rule_text(&self, id: &str) -> Option<&str> {
        self.rule_texts.get(id).map(std::string::String::as_str)
    }

    pub fn delete_rule(&mut self, id: &str) {
        self.rules.remove(id);
        self.rule_texts.remove(id);
    }
}

// ─── Rule Repository ──────────────────────────────────────────────────────────

pub struct RuleRepository {
    sources: Vec<RuleSource>,
    db: Arc<RwLock<InMemoryDb>>,
    compiled_rules: HashMap<String, CompiledRuleSet>,
    last_sync: HashMap<String, SystemTime>,
    builtin_loaded: bool,
}

impl RuleRepository {
    #[must_use] 
    pub fn new() -> Self {
        let mut repo = Self {
            sources: Vec::new(),
            db: Arc::new(RwLock::new(InMemoryDb::default())),
            compiled_rules: HashMap::new(),
            last_sync: HashMap::new(),
            builtin_loaded: false,
        };
        repo.load_builtin_rules();
        repo
    }

    pub fn add_source(&mut self, source: RuleSource) {
        self.sources.push(source);
    }

    pub fn remove_source(&mut self, name: &str) {
        self.sources.retain(|s| s.name() != name);
    }

    /// Remove a rule (by id) from the in-memory database.
    ///
    /// # Errors
    /// Currently infallible; reserved for future persistence-layer errors.
    pub fn delete_rule(&self, id: &str) -> Result<()> {
        let mut db = self.db.write();
        db.delete_rule(id);
        drop(db);
        Ok(())
    }

    #[must_use] 
    pub fn list_sources(&self) -> &[RuleSource] {
        &self.sources
    }

    // ── Sync ───────────────────────────────────────────────────────────────

    pub fn sync_source(&mut self, source: &RuleSource) -> SyncReport {
        let start = std::time::Instant::now();
        let mut report = SyncReport {
            source_name: source.name(),
            ..Default::default()
        };

        if !source.is_enabled() {
            report.errors.push("Source is disabled".to_string());
            return report;
        }

        match source {
            RuleSource::Local { path, .. } => {
                self.sync_local_path(path, &mut report);
            }
            RuleSource::Git {
                url,
                branch,
                local_path,
                ..
            } => {
                self.sync_git(url, branch, local_path, &mut report);
            }
            RuleSource::Http { url, .. } => {
                Self::sync_http(url, &mut report);
            }
        }

        report.duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        report.synced_at = Some(SystemTime::now());
        self.last_sync.insert(source.name(), SystemTime::now());
        report
    }

    pub fn sync_all(&mut self) -> Vec<SyncReport> {
        let sources: Vec<RuleSource> = self.sources.clone();
        sources.iter().map(|s| self.sync_source(s)).collect()
    }

    fn sync_local_path(&mut self, path: &Path, report: &mut SyncReport) {
        if !path.exists() {
            report
                .errors
                .push(format!("Path does not exist: {}", path.display()));
            return;
        }
        if path.is_file() {
            self.sync_yar_file(path, "local", report);
        } else if path.is_dir() {
            self.sync_directory(path, "local", report);
        }
    }

    fn sync_directory(&mut self, dir: &Path, source: &str, report: &mut SyncReport) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                report
                    .errors
                    .push(format!("Cannot read dir {}: {}", dir.display(), e));
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.sync_directory(&path, source, report);
            } else if path.extension().and_then(|e| e.to_str()) == Some("yar")
                || path.extension().and_then(|e| e.to_str()) == Some("yara")
            {
                self.sync_yar_file(&path, source, report);
            }
        }
    }

    fn sync_yar_file(&self, path: &Path, source: &str, report: &mut SyncReport) {
        report.files_scanned += 1;
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                report
                    .errors
                    .push(format!("Cannot read {}: {}", path.display(), e));
                return;
            }
        };
        let rules = parse_yar_text(&text, path.to_str().unwrap_or(""), source);
        let mut db = self.db.write();
        for (meta, rule_text) in rules {
            if let Some(existing) = db.get_rule(&meta.rule_id) {
                let existing_hash = existing.hash.clone();
                if existing_hash == meta.hash {
                    report.rules_unchanged += 1;
                    continue;
                }
                report.rules_updated += 1;
            } else {
                report.rules_added += 1;
            }
            db.upsert_rule(meta, rule_text);
        }
    }

    fn sync_git(&mut self, url: &str, branch: &str, local_path: &Path, report: &mut SyncReport) {
        if local_path.exists() {
            report.errors.push(format!(
                "Git sync (pull) skipped — no git binary integration in this build. \
                 Falling back to reading existing local_path: {}",
                local_path.display()
            ));
            self.sync_local_path(local_path, report);
        } else {
            report.errors.push(format!(
                "Git sync skipped — local_path {} does not exist and git clone not implemented.",
                local_path.display()
            ));
        }
        let _ = (url, branch);
    }

    fn sync_http(url: &str, report: &mut SyncReport) {
        report.errors.push(format!(
            "HTTP sync for {url} skipped — no HTTP client linked in this build."
        ));
    }

    // ── Query ──────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn list_rules(&self) -> Vec<RuleMeta> {
        self.db.read().list_rules(false)
    }

    #[must_use] 
    pub fn list_enabled_rules(&self) -> Vec<RuleMeta> {
        self.db.read().list_rules(true)
    }

    #[must_use] 
    pub fn get_rule(&self, rule_id: &str) -> Option<RuleMeta> {
        self.db.read().get_rule(rule_id).cloned()
    }

    #[must_use] 
    pub fn filter_rules(&self, filter: &RuleFilter) -> Vec<RuleMeta> {
        self.list_rules()
            .into_iter()
            .filter(|r| filter.matches(r))
            .collect()
    }

    // ── Enable / Disable ───────────────────────────────────────────────────

    /// Enable a rule by id.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::NotFound`] if `rule_id` is unknown.
    pub fn enable(&mut self, rule_id: &str) -> Result<()> {
        let mut db = self.db.write();
        match db.get_rule_mut(rule_id) {
            Some(r) => {
                r.enabled = true;
                Ok(())
            }
            None => Err(YaraRepoError::NotFound(rule_id.to_string())),
        }
    }

    /// Disable a rule by id.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::NotFound`] if `rule_id` is unknown.
    pub fn disable(&mut self, rule_id: &str) -> Result<()> {
        let mut db = self.db.write();
        match db.get_rule_mut(rule_id) {
            Some(r) => {
                r.enabled = false;
                Ok(())
            }
            None => Err(YaraRepoError::NotFound(rule_id.to_string())),
        }
    }

    pub fn enable_category(&mut self, category: &RuleCategory) {
        let mut db = self.db.write();
        for rule in db.rules.values_mut() {
            if &rule.category == category {
                rule.enabled = true;
            }
        }
    }

    pub fn disable_category(&mut self, category: &RuleCategory) {
        let mut db = self.db.write();
        for rule in db.rules.values_mut() {
            if &rule.category == category {
                rule.enabled = false;
            }
        }
    }

    // ── Compile ────────────────────────────────────────────────────────────

    /// Compile all enabled rules into a single combined rule set.
    ///
    /// # Errors
    /// Returns a [`YaraRepoError::CompileError`] if any rule fails to compile.
    pub fn compile_enabled(&mut self) -> Result<CompiledRuleSet> {
        use std::fmt::Write as _;
        let db = self.db.read();
        let enabled: Vec<(String, String)> = db
            .list_rules(true)
            .into_iter()
            .filter_map(|m| {
                db.get_rule_text(&m.rule_id)
                    .map(|t| (m.rule_id, t.to_string()))
            })
            .collect();
        drop(db);
        let count = enabled.len();
        let mut combined = String::new();
        for (id, text) in &enabled {
            let _ = writeln!(combined, "// rule_id: {id}");
            combined.push_str(text);
            combined.push('\n');
        }
        let crs = CompiledRuleSet::new("enabled".to_string(), combined, count);
        self.compiled_rules
            .insert("enabled".to_string(), crs.clone());
        Ok(crs)
    }

    /// Compile all rules in the given category into a single rule set.
    ///
    /// # Errors
    /// Returns a [`YaraRepoError::CompileError`] if any rule fails to compile.
    pub fn compile_category(&mut self, category: &RuleCategory) -> Result<CompiledRuleSet> {
        use std::fmt::Write as _;
        let db = self.db.read();
        let rules: Vec<(String, String)> = db
            .list_rules(false)
            .into_iter()
            .filter(|r| &r.category == category)
            .filter_map(|m| {
                db.get_rule_text(&m.rule_id)
                    .map(|t| (m.rule_id, t.to_string()))
            })
            .collect();
        drop(db);
        let count = rules.len();
        let mut combined = String::new();
        for (id, text) in &rules {
            let _ = writeln!(combined, "// rule_id: {id}");
            combined.push_str(text);
            combined.push('\n');
        }
        let key = format!("cat:{}", category.as_str());
        let crs = CompiledRuleSet::new(key.clone(), combined, count);
        self.compiled_rules.insert(key, crs.clone());
        Ok(crs)
    }

    // ── Scan ───────────────────────────────────────────────────────────────

    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<Match> {
        let Some(crs) = self.compiled_rules.get("enabled") else { return vec![] };
        simple_scan(data, crs, &self.db.read())
    }

    #[must_use]
    pub fn scan_with_ruleset(&self, data: &[u8], ruleset_id: &str) -> Vec<Match> {
        let Some(crs) = self.compiled_rules.get(ruleset_id) else { return vec![] };
        simple_scan(data, crs, &self.db.read())
    }

    /// Scan a file path.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::Io`] if the file cannot be read.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<Match>> {
        let data = std::fs::read(path).map_err(|e| YaraRepoError::Io(e.to_string()))?;
        Ok(self.scan(&data))
    }

    // ── Export / Import ────────────────────────────────────────────────────

    /// Export the given rules (by id) to a single `.yar` file at `dest`.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::Io`] if writing to `dest` fails.
    pub fn export_rules(&self, rule_ids: &[&str], dest: &Path) -> Result<()> {
        let db = self.db.read();
        let mut out = String::new();
        for id in rule_ids {
            if let Some(text) = db.get_rule_text(id) {
                out.push_str(text);
                out.push('\n');
            }
        }
        std::fs::write(dest, &out).map_err(|e| YaraRepoError::Io(e.to_string()))
    }

    /// Export all rules in a category.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::Io`] if writing to `dest` fails.
    pub fn export_category(&self, category: &RuleCategory, dest: &Path) -> Result<()> {
        let db = self.db.read();
        let ids: Vec<String> = db
            .list_rules(false)
            .into_iter()
            .filter(|r| &r.category == category)
            .map(|r| r.rule_id)
            .collect();
        drop(db);
        let id_refs: Vec<&str> = ids.iter().map(std::string::String::as_str).collect();
        self.export_rules(&id_refs, dest)
    }

    /// Export all enabled rules to a single file.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::Io`] if writing to `dest` fails.
    pub fn export_all_enabled(&self, dest: &Path) -> Result<()> {
        let db = self.db.read();
        let ids: Vec<String> = db.list_rules(true).into_iter().map(|r| r.rule_id).collect();
        drop(db);
        let id_refs: Vec<&str> = ids.iter().map(std::string::String::as_str).collect();
        self.export_rules(&id_refs, dest)
    }

    /// Import rules from a `.yar` file.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::ParseError`] if any rules fail to parse.
    pub fn import_yar_file(&mut self, path: &Path) -> Result<usize> {
        let mut report = SyncReport::default();
        self.sync_yar_file(path, "import", &mut report);
        if report.errors.is_empty() {
            Ok(report.rules_added + report.rules_updated)
        } else {
            Err(YaraRepoError::ParseError(report.errors.join("; ")))
        }
    }

    // ── Statistics ─────────────────────────────────────────────────────────

    #[must_use] 
    pub fn stats(&self) -> RepoStats {
        let all = {
            let db = self.db.read();
            db.list_rules(false)
        };
        let mut stats = RepoStats {
            total_rules: all.len(),
            ..RepoStats::default()
        };
        for rule in &all {
            if rule.enabled {
                stats.enabled_count += 1;
            } else {
                stats.disabled_count += 1;
            }
            *stats
                .by_category
                .entry(rule.category.as_str().to_string())
                .or_insert(0) += 1;
            *stats
                .by_severity
                .entry(rule.severity.as_str().to_string())
                .or_insert(0) += 1;
            *stats.by_source.entry(rule.source_name.clone()).or_insert(0) += 1;
        }
        stats.last_sync_times.clone_from(&self.last_sync);
        stats
    }

    // ── Built-in Rules ─────────────────────────────────────────────────────

    fn load_builtin_rules(&mut self) {
        if self.builtin_loaded {
            return;
        }
        self.builtin_loaded = true;
        let mut db = self.db.write();
        for (meta, text) in builtin_rules() {
            db.upsert_rule(meta, text);
        }
    }
}

impl Default for RuleRepository {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Rule Filter ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct RuleFilter {
    pub category: Option<RuleCategory>,
    pub severity_min: Option<Severity>,
    pub tags: Vec<String>,
    pub enabled_only: bool,
    pub source: Option<String>,
    pub name_contains: Option<String>,
}

impl RuleFilter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub const fn enabled_only(mut self) -> Self {
        self.enabled_only = true;
        self
    }

    #[must_use] 
    pub const fn category(mut self, cat: RuleCategory) -> Self {
        self.category = Some(cat);
        self
    }

    #[must_use] 
    pub const fn severity_min(mut self, sev: Severity) -> Self {
        self.severity_min = Some(sev);
        self
    }

    #[must_use] 
    pub fn matches(&self, rule: &RuleMeta) -> bool {
        if self.enabled_only && !rule.enabled {
            return false;
        }
        if let Some(ref cat) = self.category
            && &rule.category != cat {
                return false;
            }
        if let Some(ref sev) = self.severity_min
            && &rule.severity < sev {
                return false;
            }
        if !self.tags.is_empty()
            && !self.tags.iter().any(|t| rule.tags.contains(t)) {
                return false;
            }
        if let Some(ref src) = self.source
            && &rule.source_name != src {
                return false;
            }
        if let Some(ref name) = self.name_contains
            && !rule.name.to_lowercase().contains(&name.to_lowercase()) {
                return false;
            }
        true
    }
}

// ─── Public Repo Sources ──────────────────────────────────────────────────────

#[must_use] 
pub fn popular_public_sources() -> Vec<RuleSource> {
    vec![
        RuleSource::Git {
            url: "https://github.com/Yara-Rules/rules.git".to_string(),
            branch: "master".to_string(),
            local_path: PathBuf::from("~/.rustre/yara-repos/yara-rules"),
            enabled: true,
        },
        RuleSource::Git {
            url: "https://github.com/Neo23x0/signature-base.git".to_string(),
            branch: "master".to_string(),
            local_path: PathBuf::from("~/.rustre/yara-repos/signature-base"),
            enabled: true,
        },
        RuleSource::Git {
            url: "https://github.com/reversinglabs/reversinglabs-yara-rules.git".to_string(),
            branch: "develop".to_string(),
            local_path: PathBuf::from("~/.rustre/yara-repos/reversinglabs"),
            enabled: true,
        },
        RuleSource::Git {
            url: "https://github.com/elastic/detection-rules.git".to_string(),
            branch: "main".to_string(),
            local_path: PathBuf::from("~/.rustre/yara-repos/elastic-detection-rules"),
            enabled: true,
        },
        RuleSource::Git {
            url: "https://github.com/bartblaze/Yara-rules.git".to_string(),
            branch: "master".to_string(),
            local_path: PathBuf::from("~/.rustre/yara-repos/bartblaze"),
            enabled: true,
        },
        RuleSource::Git {
            url: "https://github.com/MalGamy/YARA_Rules.git".to_string(),
            branch: "main".to_string(),
            local_path: PathBuf::from("~/.rustre/yara-repos/malgamy"),
            enabled: false,
        },
        RuleSource::Http {
            url: "https://raw.githubusercontent.com/InQuest/yara-rules/master/Phishing.rule"
                .to_string(),
            refresh_secs: 86400,
            enabled: false,
        },
    ]
}

// ─── Parser ───────────────────────────────────────────────────────────────────

fn simple_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn parse_yar_text(text: &str, file_path: &str, source: &str) -> Vec<(RuleMeta, String)> {
    let mut results = Vec::new();
    let mut current_rule = String::new();
    let mut in_rule = false;
    let mut brace_depth = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if !in_rule && (trimmed.starts_with("rule ") || trimmed.starts_with("private rule ")) {
            in_rule = true;
            brace_depth = 0;
            current_rule.clear();
        }
        if in_rule {
            current_rule.push_str(line);
            current_rule.push('\n');
            // Count structural braces while skipping characters inside
            // double-quoted strings (meta values like description = "foo { bar }")
            // and hex byte patterns (e.g. $s = { AB CD }) which open and close
            // on the same line.  Both would otherwise corrupt the depth counter.
            let mut in_quote = false;
            let mut prev_ch = '\0';
            for ch in line.chars() {
                match ch {
                    // Toggle quoted-string tracking; honour backslash escapes.
                    '"' if prev_ch != '\\' => {
                        in_quote = !in_quote;
                    }
                    '{' if !in_quote => {
                        brace_depth += 1;
                    }
                    '}' if !in_quote && brace_depth > 0 => {
                        brace_depth -= 1;
                    }
                    _ => {}
                }
                prev_ch = ch;
            }
            if brace_depth == 0 && current_rule.contains('{') {
                if let Some(meta) = extract_rule_meta(&current_rule, file_path, source) {
                    results.push((meta, current_rule.clone()));
                }
                in_rule = false;
                current_rule.clear();
            }
        }
    }
    results
}

fn extract_rule_meta(rule_text: &str, file_path: &str, source: &str) -> Option<RuleMeta> {
    let name = rule_text
        .lines()
        .find(|l| l.trim().starts_with("rule ") || l.trim().starts_with("private rule "))?
        .split_whitespace()
        .find(|w| !["rule", "private", "{"].contains(w))
        .map(|w| w.trim_end_matches('{').trim().to_string())?;

    let mut author = String::new();
    let mut description = String::new();
    let mut date = String::new();
    let mut tags: Vec<String> = Vec::new();
    let mut category_str = "unknown".to_string();
    let mut severity_str = "medium".to_string();
    let mut namespace = "default".to_string();

    for line in rule_text.lines() {
        let t = line.trim();
        if t.starts_with("author") && t.contains('=') {
            author = extract_meta_value(t);
        } else if t.starts_with("description") && t.contains('=') {
            description = extract_meta_value(t);
        } else if t.starts_with("date") && t.contains('=') {
            date = extract_meta_value(t);
        } else if t.starts_with("tags") && t.contains('=') {
            tags = extract_meta_value(t)
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        } else if t.starts_with("category") && t.contains('=') {
            category_str = extract_meta_value(t);
        } else if t.starts_with("severity") && t.contains('=') {
            severity_str = extract_meta_value(t);
        } else if t.starts_with("namespace") && t.contains('=') {
            namespace = extract_meta_value(t);
        }
    }

    let hash = simple_hash(rule_text);
    let rule_id = format!("{source}:{name}");

    Some(RuleMeta {
        rule_id,
        name,
        namespace,
        author,
        date,
        description,
        tags,
        category: RuleCategory::from_label(&category_str),
        severity: Severity::from_label(&severity_str),
        hash,
        file_path: file_path.to_string(),
        enabled: true,
        source_name: source.to_string(),
    })
}

fn extract_meta_value(line: &str) -> String {
    line.find('=').map_or_else(String::new, |pos| {
        let val = line[pos + 1..].trim();
        val.trim_matches('"').trim_matches('\'').to_string()
    })
}

// ─── Simple Scan ─────────────────────────────────────────────────────────────

fn simple_scan(data: &[u8], crs: &CompiledRuleSet, db: &InMemoryDb) -> Vec<Match> {
    // Compile the combined rule text using the in-crate YARA-subset compiler
    // and scan `data` against it. Rule metadata (category, severity, tags,
    // namespace) is looked up in the in-memory DB via the `// rule_id: {id}`
    // markers embedded in `crs.rules_text` when the ruleset was built.
    let text = &crs.rules_text;
    if text.is_empty() {
        return Vec::new();
    }

    // Build a rule_name -> rule_id map by scanning the `// rule_id:` comments
    // that `compile_enabled` / `compile_category` emit before each rule block.
    let name_to_id = build_rule_name_to_id_map(text);

    let executor = rule_compiler::RuleExecutor::from_text(text);
    let rule_matches = executor.scan(data);

    let mut results = Vec::with_capacity(rule_matches.len());
    for rm in rule_matches {
        // Convert per-pattern hits into the public StringMatch shape.
        let mut strings = Vec::new();
        for hit in &rm.string_hits {
            for (i, off) in hit.offsets.iter().enumerate() {
                let bytes = hit.data.get(i).cloned().unwrap_or_default();
                let length = bytes.len();
                strings.push(StringMatch {
                    identifier: hit.id.clone(),
                    offset: *off,
                    length,
                    data: bytes,
                });
            }
        }

        // Resolve metadata: prefer DB record (authoritative), fall back to the
        // information the compiler recovered from the rule text.
        let rule_id = name_to_id
            .get(rm.rule_name.as_str())
            .cloned()
            .unwrap_or_else(|| rm.rule_name.clone());

        let (namespace, tags, category, severity) = if let Some(meta) = db.get_rule(&rule_id) {
            (
                meta.namespace.clone(),
                meta.tags.clone(),
                meta.category.clone(),
                meta.severity.clone(),
            )
        } else {
            let cat_str = rm.meta.get("category").cloned().unwrap_or_default();
            let sev_str = rm.meta.get("severity").cloned().unwrap_or_default();
            (
                rm.namespace.clone(),
                rm.tags.clone(),
                RuleCategory::from_label(&cat_str),
                Severity::from_label(&sev_str),
            )
        };

        results.push(Match {
            rule_id,
            rule_name: rm.rule_name,
            namespace,
            tags,
            category,
            severity,
            strings,
            meta: rm.meta,
        });
    }

    results
}

/// Parse the combined rules text emitted by `compile_enabled` /
/// `compile_category` and build a map from rule name to the originating
/// `rule_id`.  Each rule is preceded by a `// rule_id: {id}` comment; the next
/// `rule <Name>` token on a subsequent line is associated with that id.
fn build_rule_name_to_id_map(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut pending_id: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("// rule_id:") {
            pending_id = Some(rest.trim().to_string());
            continue;
        }
        // Look for a `rule <Name>` header line. Tolerate `rule Name : tags {`
        // and `private rule Name {` variants.
        let header = trimmed
            .strip_prefix("private ")
            .map_or(trimmed, str::trim_start);
        if let Some(after) = header.strip_prefix("rule ")
            && let Some(id) = pending_id.take() {
                let name = after
                    .split(|c: char| c.is_whitespace() || c == '{' || c == ':')
                    .find(|s| !s.is_empty())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !name.is_empty() {
                    map.insert(name, id);
                }
            }
    }
    map
}

// ─── Built-in Rule Text Constants ─────────────────────────────────────────────

const RULE_COBALT_STRIKE_BEACON: &str = r#"
rule CobaltStrike_Beacon_Config {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Cobalt Strike beacon configuration block"
        category = "malware"
        severity = "critical"
        tags = "cobalt_strike,beacon,c2"
    strings:
        $cs1 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }
        $cs_cfg = { 2e 2f 2e 2f 2e 2c }
    condition:
        uint16(0) == 0x5A4D and ($cs1 or $cs_cfg) and filesize < 2097152
}
"#;

const RULE_COBALT_STRIKE_SHELLCODE: &str = r#"
rule CobaltStrike_Shellcode {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Cobalt Strike shellcode stager pattern"
        category = "malware"
        severity = "critical"
        tags = "cobalt_strike,shellcode,stager"
    strings:
        $sc1 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51 56 48 31 D2 }
        $sc2 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
    condition:
        any of them
}
"#;

const RULE_EMOTET_LOADER: &str = r#"
rule Emotet_Loader {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Emotet loader characteristics"
        category = "loader"
        severity = "critical"
        tags = "emotet,loader,banking_trojan"
    strings:
        $emotet1 = { 55 8B EC 83 EC ?? 53 56 57 8B 7D 08 8B 77 3C }
        $emotet2 = "GlobalMemoryStatusEx" ascii
        $emotet_str2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
"#;

const RULE_TRICKBOT: &str = r#"
rule TrickBot_Module {
    meta:
        author = "rustre-yara-rules"
        description = "Detects TrickBot banking trojan module"
        category = "malware"
        severity = "critical"
        tags = "trickbot,banking_trojan,infostealer"
    strings:
        $tb1 = "moduleconfig" ascii
        $tb2 = "<mcconf>" ascii
        $tb3 = "<autorun>" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
"#;

const RULE_RYUK_RANSOMWARE: &str = r#"
rule Ryuk_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Ryuk ransomware binary"
        category = "ransomware"
        severity = "critical"
        tags = "ryuk,ransomware,encryption"
    strings:
        $ryk1 = "RyukReadMe.txt" ascii wide
        $ryk2 = "UNIQUE_ID_DO_NOT_REMOVE" ascii
        $ryk3 = "No system is safe" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
"#;

const RULE_LOCKBIT_RANSOMWARE: &str = r#"
rule LockBit_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects LockBit ransomware family"
        category = "ransomware"
        severity = "critical"
        tags = "lockbit,ransomware,encryption"
    strings:
        $lb1 = "LockBit" ascii nocase
        $lb2 = ".lockbit" ascii nocase
        $lb3 = "Restore-My-Files.txt" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
"#;

const RULE_CONTI_RANSOMWARE: &str = r#"
rule Conti_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Conti ransomware"
        category = "ransomware"
        severity = "critical"
        tags = "conti,ransomware"
    strings:
        $c1 = "CONTI" ascii wide
        $c4 = "vssadmin delete shadows /all /quiet" ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_BLACKCAT_RANSOMWARE: &str = r#"
rule BlackCat_ALPHV_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects BlackCat / ALPHV ransomware"
        category = "ransomware"
        severity = "critical"
        tags = "blackcat,alphv,ransomware,rust"
    strings:
        $bc1 = "ALPHV" ascii
        $bc2 = "BlackCat" ascii
        $bc6 = "--access-token" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
"#;

const RULE_QAKBOT: &str = r#"
rule Qakbot_Loader {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Qakbot loader"
        category = "loader"
        severity = "high"
        tags = "qakbot,loader,banking"
    strings:
        $q1 = { 33 C0 8A 04 31 32 04 11 48 75 F7 }
        $q4 = "qbot" ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_ICEDID: &str = r#"
rule IcedID_Loader {
    meta:
        author = "rustre-yara-rules"
        description = "Detects IcedID banking trojan"
        category = "malware"
        severity = "high"
        tags = "icedid,banking,loader"
    strings:
        $i1 = { 55 8B EC 83 EC 0C 8B 45 0C 56 57 8B 7D 08 }
        $i2 = "gzip" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_DRIDEX: &str = r#"
rule Dridex_Loader {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Dridex banking trojan loader"
        category = "malware"
        severity = "high"
        tags = "dridex,banking_trojan"
    strings:
        $d1 = { E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 45 FC }
        $d2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_ASYNCRAT: &str = r#"
rule AsyncRAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects AsyncRAT remote access trojan"
        category = "malware"
        severity = "high"
        tags = "asyncrat,rat,remote_access"
    strings:
        $a1 = "AsyncRAT" ascii wide
        $a3 = "AES" ascii wide
        $a4 = "Mutex" ascii wide
    condition:
        2 of them
}
"#;

const RULE_NJRAT: &str = r#"
rule NjRAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects NjRAT remote access trojan"
        category = "malware"
        severity = "high"
        tags = "njrat,rat,remote_access"
    strings:
        $n1 = "njq8" ascii
        $n4 = "|'|'|" ascii
    condition:
        any of them
}
"#;

const RULE_AGENT_TESLA: &str = r#"
rule AgentTesla_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects AgentTesla keylogger/stealer"
        category = "info_stealer"
        severity = "high"
        tags = "agent_tesla,keylogger,stealer"
    strings:
        $at1 = "AgentTesla" ascii wide nocase
        $at3 = "SmtpClient" ascii wide
        $at4 = "GetKeyboardState" ascii
    condition:
        2 of them
}
"#;

const RULE_FORMBOOK: &str = r#"
rule FormBook_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects FormBook information stealer"
        category = "info_stealer"
        severity = "high"
        tags = "formbook,stealer,infostealer"
    strings:
        $fb1 = { 55 8B EC 83 C4 ?? 53 33 C3 89 45 F4 }
        $fb4 = "NtQueryInformationProcess" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_GULOADER: &str = r#"
rule GuLoader_Downloader {
    meta:
        author = "rustre-yara-rules"
        description = "Detects GuLoader downloader"
        category = "loader"
        severity = "high"
        tags = "guloader,downloader,loader"
    strings:
        $g2 = "NSIS" ascii
        $g3 = { E8 00 00 00 00 5D 81 ED }
    condition:
        any of them
}
"#;

const RULE_REMCOS: &str = r#"
rule Remcos_RAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Remcos RAT"
        category = "malware"
        severity = "high"
        tags = "remcos,rat,remote_access"
    strings:
        $r1 = "Remcos" ascii wide nocase
        $r3 = "Breaking-Security.Net" ascii
    condition:
        any of them
}
"#;

const RULE_AZORULT: &str = r#"
rule AZORult_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects AZORult infostealer"
        category = "info_stealer"
        severity = "high"
        tags = "azorult,stealer,infostealer"
    strings:
        $az3 = "wallet.dat" ascii
        $az4 = "Mozilla\\Firefox\\Profiles" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_REDLINE_STEALER: &str = r#"
rule RedLine_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects RedLine credential stealer"
        category = "info_stealer"
        severity = "high"
        tags = "redline,stealer,credentials"
    strings:
        $r1 = "RedLine" ascii wide nocase
        $r4 = "Login Data" ascii
    condition:
        any of them
}
"#;

const RULE_RACCOON_STEALER: &str = r#"
rule Raccoon_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Raccoon Stealer"
        category = "info_stealer"
        severity = "high"
        tags = "raccoon,stealer,infostealer"
    strings:
        $rc1 = "raccoon" ascii wide nocase
        $rc3 = "CryptUnprotectData" ascii
    condition:
        any of them
}
"#;

const RULE_VIDAR: &str = r#"
rule Vidar_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Vidar information stealer"
        category = "info_stealer"
        severity = "high"
        tags = "vidar,stealer,infostealer"
    strings:
        $v1 = "Vidar" ascii wide nocase
        $v3 = "Wallets" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_UPX_3X: &str = r#"
rule UPX_3x_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects UPX 3.x packed binary"
        category = "packers"
        severity = "low"
        tags = "upx,packer,compression"
    strings:
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and ($upx2 and $upx3) or $upx4
}
"#;

const RULE_UPX_4X: &str = r#"
rule UPX_4x_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects UPX 4.x packed binary"
        category = "packers"
        severity = "low"
        tags = "upx,packer"
    strings:
        $u1 = "UPX 4." ascii
        $u3 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_THEMIDA: &str = r#"
rule Themida_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Themida software protection"
        category = "packers"
        severity = "medium"
        tags = "themida,packer,protector"
    strings:
        $t1 = ".themida" ascii nocase
        $t2 = "WinLicense" ascii
    condition:
        uint16(0) == 0x5A4D and ($t1 or $t2)
}
"#;

const RULE_VMPROTECT_2X: &str = r#"
rule VMProtect_2x {
    meta:
        author = "rustre-yara-rules"
        description = "Detects VMProtect 2.x"
        category = "packers"
        severity = "medium"
        tags = "vmprotect,packer,virtualizer"
    strings:
        $vm1 = ".vmp0" ascii
        $vm2 = ".vmp1" ascii
    condition:
        uint16(0) == 0x5A4D and $vm1 and $vm2
}
"#;

const RULE_VMPROTECT_3X: &str = r#"
rule VMProtect_3x {
    meta:
        author = "rustre-yara-rules"
        description = "Detects VMProtect 3.x"
        category = "packers"
        severity = "medium"
        tags = "vmprotect,packer"
    strings:
        $vm1 = ".vmp0" ascii
        $vm3 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 }
    condition:
        uint16(0) == 0x5A4D and $vm1 and $vm3
}
"#;

const RULE_MPRESS: &str = r#"
rule MPRESS_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects MPRESS packer"
        category = "packers"
        severity = "low"
        tags = "mpress,packer"
    strings:
        $mp1 = ".MPRESS1" ascii
        $mp2 = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and $mp1 and $mp2
}
"#;

const RULE_PECOMPACT: &str = r#"
rule PECompact_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects PECompact packer"
        category = "packers"
        severity = "low"
        tags = "pecompact,packer"
    strings:
        $pec1 = "PECompact2" ascii
    condition:
        uint16(0) == 0x5A4D and $pec1
}
"#;

const RULE_ASPACK: &str = r#"
rule ASPack_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects ASPack packer"
        category = "packers"
        severity = "low"
        tags = "aspack,packer"
    strings:
        $asp1 = ".aspack" ascii nocase
        $asp2 = ".adata" ascii
    condition:
        uint16(0) == 0x5A4D and ($asp1 or $asp2)
}
"#;

const RULE_PESPIN: &str = r#"
rule PESpin_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects PESpin packer"
        category = "packers"
        severity = "low"
        tags = "pespin,packer"
    strings:
        $ps1 = { EB 01 ?? 60 EB 01 ?? E8 01 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and $ps1
}
"#;

const RULE_ENIGMA_PROTECTOR: &str = r#"
rule Enigma_Protector {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Enigma Protector"
        category = "packers"
        severity = "medium"
        tags = "enigma,protector,packer"
    strings:
        $e1 = "Enigma" ascii
    condition:
        uint16(0) == 0x5A4D and $e1
}
"#;

const RULE_NSPACK: &str = r#"
rule nSPack_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects nSPack packer"
        category = "packers"
        severity = "low"
        tags = "nspack,packer"
    strings:
        $n1 = ".nSPack" ascii
    condition:
        uint16(0) == 0x5A4D and $n1
}
"#;

const RULE_FSG_PACKER: &str = r#"
rule FSG_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects FSG packer"
        category = "packers"
        severity = "low"
        tags = "fsg,packer"
    strings:
        $f1 = { EB 02 CD 20 }
    condition:
        uint16(0) == 0x5A4D and $f1
}
"#;

const RULE_WWPACK32: &str = r#"
rule WWPack32_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects WWPack32 packer"
        category = "packers"
        severity = "low"
        tags = "wwpack32,packer"
    strings:
        $w1 = "WWpack32" ascii
    condition:
        uint16(0) == 0x5A4D and $w1
}
"#;

const RULE_MORPHINE: &str = r#"
rule Morphine_Packer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Morphine packer"
        category = "packers"
        severity = "low"
        tags = "morphine,packer"
    strings:
        $m1 = { E8 ?? 00 00 00 5E 83 C6 ?? EB }
    condition:
        uint16(0) == 0x5A4D and $m1
}
"#;

const RULE_AES_SBOX: &str = r#"
rule AES_SBOX {
    meta:
        author = "rustre-yara-rules"
        description = "Detects AES S-Box constant table"
        category = "crypto_constants"
        severity = "info"
        tags = "aes,crypto,sbox"
    strings:
        $aes_sbox = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
        }
    condition:
        $aes_sbox
}
"#;

const RULE_AES_INV_SBOX: &str = r#"
rule AES_Inverse_SBOX {
    meta:
        author = "rustre-yara-rules"
        description = "Detects AES inverse S-Box constant table"
        category = "crypto_constants"
        severity = "info"
        tags = "aes,crypto,sbox"
    strings:
        $inv_sbox = {
            52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB
            7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB
        }
    condition:
        $inv_sbox
}
"#;

const RULE_AES_RCON: &str = r#"
rule AES_RCON {
    meta:
        author = "rustre-yara-rules"
        description = "Detects AES round constant (RCON) table"
        category = "crypto_constants"
        severity = "info"
        tags = "aes,crypto,rcon"
    strings:
        $rcon = { 01 02 04 08 10 20 40 80 1B 36 }
    condition:
        $rcon
}
"#;

const RULE_CHACHA20_SIGMA: &str = r#"
rule ChaCha20_SIGMA {
    meta:
        author = "rustre-yara-rules"
        description = "Detects ChaCha20 SIGMA constant"
        category = "crypto_constants"
        severity = "info"
        tags = "chacha20,crypto"
    strings:
        $sigma = "expand 32-byte k" ascii
    condition:
        $sigma
}
"#;

const RULE_RC4_CHARACTERISTIC: &str = r#"
rule RC4_KSA {
    meta:
        author = "rustre-yara-rules"
        description = "Detects RC4 Key Scheduling Algorithm pattern"
        category = "crypto_constants"
        severity = "info"
        tags = "rc4,crypto"
    strings:
        $rc4_ksa = { 88 04 0E 02 04 0E 88 01 }
    condition:
        $rc4_ksa
}
"#;

const RULE_SHA256_K: &str = r#"
rule SHA256_K_Constants {
    meta:
        author = "rustre-yara-rules"
        description = "Detects SHA-256 K constants"
        category = "crypto_constants"
        severity = "info"
        tags = "sha256,crypto"
    strings:
        $sha256_k = {
            98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9
            5B C2 56 39 F1 11 F1 59 A4 82 3F 92 3C 66 D1 AB
        }
    condition:
        $sha256_k
}
"#;

const RULE_MD5_T: &str = r#"
rule MD5_T_Constants {
    meta:
        author = "rustre-yara-rules"
        description = "Detects MD5 T (sine-based) constants"
        category = "crypto_constants"
        severity = "info"
        tags = "md5,crypto"
    strings:
        $md5_t = { D7 6A A4 78 E8 C7 B7 56 24 20 70 DB }
    condition:
        $md5_t
}
"#;

const RULE_BLOWFISH_P: &str = r#"
rule Blowfish_P_Array {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Blowfish P-array initial constants"
        category = "crypto_constants"
        severity = "info"
        tags = "blowfish,crypto"
    strings:
        $bf_p = {
            93 2F 3D 24 38 98 A2 4A 17 F5 58 24 52 81 16 4F
        }
    condition:
        $bf_p
}
"#;

const RULE_CURVE25519: &str = r#"
rule Curve25519_Constants {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Curve25519 / X25519 field constants"
        category = "crypto_constants"
        severity = "info"
        tags = "curve25519,ecdh,crypto"
    strings:
        $c25519 = {
            ED FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
            FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 7F
        }
    condition:
        $c25519
}
"#;

const RULE_RSA_BIGNUM: &str = r#"
rule RSA_BigNum_Operations {
    meta:
        author = "rustre-yara-rules"
        description = "Detects RSA bignum Montgomery multiplication patterns"
        category = "crypto_constants"
        severity = "info"
        tags = "rsa,crypto,bignum"
    strings:
        $mont2 = "BN_mod_exp" ascii
        $mont3 = "RSA_private_decrypt" ascii
    condition:
        any of them
}
"#;

const RULE_MIMIKATZ: &str = r#"
rule Mimikatz_Binary {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Mimikatz credential dumping tool"
        category = "exploit_tools"
        severity = "critical"
        tags = "mimikatz,credential_dumping,sekurlsa"
    strings:
        $m1 = "mimikatz" ascii wide nocase
        $m2 = "sekurlsa" ascii wide nocase
        $m3 = "lsadump" ascii wide nocase
        $m6 = "mimilib" ascii
    condition:
        2 of them
}
"#;

const RULE_SHARPBOUND: &str = r#"
rule SharpHound_Collector {
    meta:
        author = "rustre-yara-rules"
        description = "Detects SharpHound AD enumeration tool"
        category = "exploit_tools"
        severity = "high"
        tags = "sharphound,bloodhound,ad_enum"
    strings:
        $s1 = "SharpHound" ascii wide nocase
        $s2 = "BloodHound" ascii wide nocase
    condition:
        any of them
}
"#;

const RULE_RUBEUS: &str = r#"
rule Rubeus_Kerberos {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Rubeus Kerberos attack tool"
        category = "exploit_tools"
        severity = "critical"
        tags = "rubeus,kerberos,kerberoasting"
    strings:
        $r1 = "Rubeus" ascii wide
        $r2 = "kerberoast" ascii wide nocase
    condition:
        any of them
}
"#;

const RULE_IMPACKET: &str = r#"
rule Impacket_Scripts {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Impacket Python scripts compiled or referenced"
        category = "exploit_tools"
        severity = "high"
        tags = "impacket,pentest,smb"
    strings:
        $i1 = "impacket" ascii wide nocase
        $i2 = "secretsdump" ascii wide nocase
    condition:
        any of them
}
"#;

const RULE_METASPLOIT_STAGER: &str = r#"
rule Metasploit_Stager {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Metasploit shellcode stager"
        category = "exploit_tools"
        severity = "critical"
        tags = "metasploit,stager,shellcode"
    strings:
        $ms1 = { FC E8 82 00 00 00 60 89 E5 }
        $ms2 = { 31 C9 64 8B 71 30 8B 76 0C 8B 76 1C }
    condition:
        any of them
}
"#;

const RULE_SLIVER_IMPLANT: &str = r#"
rule Sliver_C2_Implant {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Sliver C2 framework implant"
        category = "exploit_tools"
        severity = "critical"
        tags = "sliver,c2,golang"
    strings:
        $s1 = "sliver" ascii wide nocase
        $s3 = "github.com/bishopfox/sliver" ascii
    condition:
        any of them
}
"#;

const RULE_POWERSPLOIT: &str = r#"
rule PowerSploit_Module {
    meta:
        author = "rustre-yara-rules"
        description = "Detects PowerSploit PowerShell post-exploitation framework"
        category = "exploit_tools"
        severity = "high"
        tags = "powersploit,powershell,post_exploitation"
    strings:
        $ps1 = "PowerSploit" ascii wide nocase
        $ps3 = "Invoke-ReflectivePEInjection" ascii wide nocase
    condition:
        any of them
}
"#;

const RULE_EMPIRE: &str = r#"
rule Empire_Framework {
    meta:
        author = "rustre-yara-rules"
        description = "Detects PowerShell Empire post-exploitation framework"
        category = "exploit_tools"
        severity = "critical"
        tags = "empire,powershell,c2"
    strings:
        $e1 = "Empire" ascii wide nocase
        $e4 = "staging_key" ascii
    condition:
        any of them
}
"#;

const RULE_ANTIVM_CPUID: &str = r#"
rule AntiVM_CPUID_Check {
    meta:
        author = "rustre-yara-rules"
        description = "Detects CPUID-based VM detection technique"
        category = "suspicious_patterns"
        severity = "medium"
        tags = "antivm,cpuid,evasion"
    strings:
        $cpuid1 = { 0F A2 }
        $vmware_str = "VMwareVMware" ascii
        $vbox_str = "VirtualBox" ascii
    condition:
        $cpuid1 and ($vmware_str or $vbox_str)
}
"#;

const RULE_ANTIDEBUG_ISDBGPRESENT: &str = r#"
rule AntiDebug_IsDebuggerPresent {
    meta:
        author = "rustre-yara-rules"
        description = "Detects IsDebuggerPresent anti-debug call"
        category = "suspicious_patterns"
        severity = "low"
        tags = "antidebug,evasion"
    strings:
        $idbp = "IsDebuggerPresent" ascii wide
        $ntqip = "NtQueryInformationProcess" ascii
    condition:
        any of them
}
"#;

const RULE_SLEEPING_ANTI_ANALYSIS: &str = r#"
rule Sleeping_Anti_Analysis {
    meta:
        author = "rustre-yara-rules"
        description = "Detects time-based anti-analysis technique"
        category = "suspicious_patterns"
        severity = "medium"
        tags = "anti_analysis,evasion,sleep"
    strings:
        $sleep_api = "Sleep" ascii
        $timeget1 = "GetTickCount" ascii
        $timeget2 = "QueryPerformanceCounter" ascii
    condition:
        $sleep_api and ($timeget1 or $timeget2)
}
"#;

const RULE_HTTP_C2_BEACON: &str = r#"
rule HTTP_C2_Beacon_Pattern {
    meta:
        author = "rustre-yara-rules"
        description = "Detects generic HTTP C2 beacon pattern"
        category = "suspicious_patterns"
        severity = "high"
        tags = "c2,http,beacon"
    strings:
        $ua1 = "User-Agent:" ascii nocase
        $post = "POST" ascii
        $http_lib = "wininet" ascii nocase
    condition:
        $ua1 and $post and $http_lib
}
"#;

const RULE_BASE64_POWERSHELL: &str = r#"
rule Base64_Encoded_PowerShell {
    meta:
        author = "rustre-yara-rules"
        description = "Detects base64 encoded PowerShell command"
        category = "suspicious_patterns"
        severity = "medium"
        tags = "powershell,base64,obfuscation"
    strings:
        $ps_enc = "-EncodedCommand" ascii nocase
        $ps_b64_prefix = "powershell" ascii nocase
    condition:
        $ps_enc and $ps_b64_prefix
}
"#;

const RULE_DNS_DOH_TUNNEL: &str = r#"
rule DNS_over_HTTPS_Tunnel {
    meta:
        author = "rustre-yara-rules"
        description = "Detects DNS-over-HTTPS tunneling patterns"
        category = "suspicious_patterns"
        severity = "high"
        tags = "dns,doh,tunnel,exfiltration"
    strings:
        $doh1 = "dns.google" ascii
        $doh3 = "cloudflare-dns.com" ascii
    condition:
        any of them
}
"#;

const RULE_ENCODED_CMD_WSCRIPT: &str = r#"
rule Encoded_Command_WScript {
    meta:
        author = "rustre-yara-rules"
        description = "Detects encoded WScript/CScript execution"
        category = "suspicious_patterns"
        severity = "medium"
        tags = "wscript,cscript,obfuscation,vbs"
    strings:
        $ws1 = "wscript.exe" ascii nocase
        $ws3 = "//E:VBScript" ascii nocase
    condition:
        any of them
}
"#;

// Additional rules to reach 200+ total

const RULE_WANNACRY: &str = r#"
rule WannaCry_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects WannaCry ransomware"
        category = "ransomware"
        severity = "critical"
        tags = "wannacry,ransomware,eternalblue"
    strings:
        $w1 = "WannaCry" ascii wide nocase
        $w2 = "WANACRY!" ascii
        $w3 = "@Please_Read_Me@.txt" ascii
        $w4 = "tasksche.exe" ascii
    condition:
        2 of them
}
"#;

const RULE_NOTPETYA: &str = r#"
rule NotPetya_Wiper {
    meta:
        author = "rustre-yara-rules"
        description = "Detects NotPetya / ExPetr wiper"
        category = "ransomware"
        severity = "critical"
        tags = "notpetya,wiper,ransomware"
    strings:
        $np1 = "wevtutil cl Setup" ascii nocase
        $np2 = { 1C 00 00 00 01 00 00 00 }
        $np3 = "MBR" ascii
    condition:
        2 of them
}
"#;

const RULE_DARKSIDE_RANSOM: &str = r#"
rule DarkSide_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects DarkSide ransomware"
        category = "ransomware"
        severity = "critical"
        tags = "darkside,ransomware"
    strings:
        $d1 = "DarkSide" ascii wide nocase
        $d2 = "README." ascii
    condition:
        any of them
}
"#;

const RULE_REVIL_RANSOMWARE: &str = r#"
rule REvil_Sodinokibi_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects REvil/Sodinokibi ransomware"
        category = "ransomware"
        severity = "critical"
        tags = "revil,sodinokibi,ransomware"
    strings:
        $r1 = "sodinokibi" ascii wide nocase
        $r2 = "REvil" ascii wide nocase
        $r3 = "-readme.txt" ascii
    condition:
        any of them
}
"#;

const RULE_HIVE_RANSOMWARE: &str = r#"
rule Hive_Ransomware {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Hive ransomware"
        category = "ransomware"
        severity = "critical"
        tags = "hive,ransomware"
    strings:
        $h1 = "HiveLeaks" ascii wide nocase
        $h2 = "hive_secret_key" ascii
    condition:
        any of them
}
"#;

const RULE_DARKCOMET_RAT: &str = r#"
rule DarkComet_RAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects DarkComet RAT"
        category = "malware"
        severity = "high"
        tags = "darkcomet,rat,remote_access"
    strings:
        $dc1 = "DarkComet" ascii wide nocase
        $dc2 = "DARKCOMET-RAT" ascii
    condition:
        any of them
}
"#;

const RULE_BLACKSHADES_RAT: &str = r#"
rule BlackShades_RAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects BlackShades RAT"
        category = "malware"
        severity = "high"
        tags = "blackshades,rat"
    strings:
        $bs1 = "BlackShades" ascii wide nocase
        $bs2 = "bs_mutex" ascii
    condition:
        any of them
}
"#;

const RULE_NETWIRE_RAT: &str = r#"
rule NetWire_RAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects NetWire RAT"
        category = "malware"
        severity = "high"
        tags = "netwire,rat"
    strings:
        $nw1 = "NetWire" ascii wide nocase
        $nw2 = "NetWireRC" ascii
    condition:
        any of them
}
"#;

const RULE_WARZONE_RAT: &str = r#"
rule WarzoneRAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Warzone/Ave Maria RAT"
        category = "malware"
        severity = "high"
        tags = "warzone,ave_maria,rat"
    strings:
        $wz1 = "Warzone" ascii wide nocase
        $wz2 = "Ave Maria" ascii wide nocase
    condition:
        any of them
}
"#;

const RULE_BITRAT: &str = r#"
rule BitRAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects BitRAT remote access trojan"
        category = "malware"
        severity = "high"
        tags = "bitrat,rat"
    strings:
        $b1 = "BitRAT" ascii wide nocase
        $b2 = "bitrat_mutex" ascii
    condition:
        any of them
}
"#;

const RULE_NANOCORE_RAT: &str = r#"
rule NanoCore_RAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects NanoCore RAT"
        category = "malware"
        severity = "high"
        tags = "nanocore,rat"
    strings:
        $n1 = "NanoCore" ascii wide nocase
        $n2 = "ClientPlugin" ascii wide
    condition:
        any of them
}
"#;

const RULE_QUASAR_RAT: &str = r#"
rule QuasarRAT {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Quasar RAT"
        category = "malware"
        severity = "high"
        tags = "quasar,rat"
    strings:
        $q1 = "QuasarRAT" ascii wide nocase
        $q2 = "Quasar.Client" ascii wide
    condition:
        any of them
}
"#;

const RULE_REDLINE_V2: &str = r#"
rule RedLine_Stealer_v2 {
    meta:
        author = "rustre-yara-rules"
        description = "Detects RedLine Stealer v2 patterns"
        category = "info_stealer"
        severity = "high"
        tags = "redline,stealer"
    strings:
        $r1 = "RedLine" ascii wide nocase
        $r2 = "Browser_Passwords" ascii wide
        $r3 = "GrabScreenshot" ascii wide
    condition:
        2 of them
}
"#;

const RULE_MARS_STEALER: &str = r#"
rule Mars_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Mars Stealer"
        category = "info_stealer"
        severity = "high"
        tags = "mars,stealer"
    strings:
        $m1 = "Mars" ascii wide nocase
        $m2 = "mars_stealer" ascii nocase
    condition:
        any of them
}
"#;

const RULE_LUMMA_STEALER: &str = r#"
rule Lumma_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Lumma C2 stealer"
        category = "info_stealer"
        severity = "high"
        tags = "lumma,stealer"
    strings:
        $l1 = "LummaC2" ascii wide nocase
        $l2 = "lumma" ascii nocase
    condition:
        any of them
}
"#;

const RULE_META_STEALER: &str = r#"
rule META_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects META Stealer"
        category = "info_stealer"
        severity = "high"
        tags = "meta,stealer"
    strings:
        $ms1 = "META Stealer" ascii wide nocase
    condition:
        $ms1
}
"#;

const RULE_STEALC: &str = r#"
rule StealC_Stealer {
    meta:
        author = "rustre-yara-rules"
        description = "Detects StealC infostealer"
        category = "info_stealer"
        severity = "high"
        tags = "stealc,stealer"
    strings:
        $s1 = "stealc" ascii wide nocase
    condition:
        $s1
}
"#;

const RULE_DONUT_LOADER: &str = r#"
rule Donut_Shellcode_Loader {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Donut shellcode loader"
        category = "loader"
        severity = "high"
        tags = "donut,loader,shellcode"
    strings:
        $d1 = "donut" ascii wide nocase
        $d2 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 }
    condition:
        $d1 or $d2
}
"#;

const RULE_HAVOC_C2: &str = r#"
rule Havoc_C2_Framework {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Havoc C2 framework"
        category = "exploit_tools"
        severity = "critical"
        tags = "havoc,c2"
    strings:
        $h1 = "HavocC2" ascii wide nocase
        $h2 = "Havoc" ascii wide
    condition:
        any of them
}
"#;

const RULE_BRUTE_RATEL: &str = r#"
rule BruteRatel_C4 {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Brute Ratel C4 framework"
        category = "exploit_tools"
        severity = "critical"
        tags = "brute_ratel,c4,c2"
    strings:
        $b1 = "BruteRatel" ascii wide nocase
        $b2 = "brute_ratel" ascii nocase
    condition:
        any of them
}
"#;

const RULE_COVENANT_C2: &str = r#"
rule Covenant_C2 {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Covenant C2 implant"
        category = "exploit_tools"
        severity = "high"
        tags = "covenant,c2"
    strings:
        $c1 = "Covenant" ascii wide nocase
        $c2 = "GruntHTTP" ascii
    condition:
        any of them
}
"#;

const RULE_MERLIN_AGENT: &str = r#"
rule Merlin_C2_Agent {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Merlin C2 golang agent"
        category = "exploit_tools"
        severity = "high"
        tags = "merlin,c2,golang"
    strings:
        $m1 = "merlin" ascii wide nocase
        $m2 = "Ne0njA/merlin" ascii
    condition:
        any of them
}
"#;

const RULE_PACKING_HIGH_ENTROPY: &str = r#"
rule High_Entropy_Section {
    meta:
        author = "rustre-yara-rules"
        description = "Detects potentially packed binary with high entropy section names"
        category = "packers"
        severity = "low"
        tags = "packer,entropy,suspicious"
    strings:
        $s1 = ".packed" ascii
        $s2 = ".text0" ascii
        $s3 = ".rsrc0" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
"#;

const RULE_INDIRECT_SYSCALL: &str = r#"
rule Indirect_Syscall_Pattern {
    meta:
        author = "rustre-yara-rules"
        description = "Detects indirect syscall invocation stub"
        category = "suspicious_patterns"
        severity = "medium"
        tags = "syscall,evasion,EDR_bypass"
    strings:
        $sc1 = { 4C 8B D1 B8 ?? 00 00 00 0F 05 }
        $sc2 = { 49 89 CA B8 ?? 00 00 00 0F 05 }
    condition:
        any of them
}
"#;

const RULE_HEAP_SPRAY: &str = r#"
rule Heap_Spray_JavaScript {
    meta:
        author = "rustre-yara-rules"
        description = "Detects heap spray technique in JavaScript"
        category = "exploit_tools"
        severity = "high"
        tags = "heap_spray,exploit,javascript"
    strings:
        $hs1 = "unescape(" ascii nocase
        $hs2 = "%u9090%u9090" ascii
        $hs3 = "shellcode" ascii nocase
    condition:
        2 of them
}
"#;

const RULE_ROP_CHAIN: &str = r#"
rule ROP_Chain_Pattern {
    meta:
        author = "rustre-yara-rules"
        description = "Detects ROP chain gadget sequences"
        category = "exploit_tools"
        severity = "high"
        tags = "rop,exploit,gadget"
    strings:
        $rop1 = { C3 58 C3 }
        $rop2 = { C3 59 C3 }
        $rop3 = { 5B C3 5A C3 }
    condition:
        2 of them
}
"#;

const RULE_SHELLCODE_GETPC: &str = r#"
rule Generic_Shellcode_GetPC {
    meta:
        author = "rustre-yara-rules"
        description = "Detects generic shellcode GetPC technique"
        category = "suspicious_patterns"
        severity = "medium"
        tags = "shellcode,getpc"
    strings:
        $getpc1 = { E8 00 00 00 00 5? }
        $getpc2 = { D9 EE D9 74 24 F4 5? }
    condition:
        any of them
}
"#;

const RULE_POWERSHELL_DOWNLOAD: &str = r#"
rule PowerShell_Download_Cradle {
    meta:
        author = "rustre-yara-rules"
        description = "Detects PowerShell download cradle pattern"
        category = "suspicious_patterns"
        severity = "high"
        tags = "powershell,download,cradle"
    strings:
        $d1 = "DownloadString" ascii wide nocase
        $d2 = "DownloadFile" ascii wide nocase
        $d3 = "Invoke-Expression" ascii wide nocase
        $d4 = "iex" ascii wide nocase
    condition:
        2 of them
}
"#;

const RULE_REFLECTIVE_DLL: &str = r#"
rule Reflective_DLL_Injection {
    meta:
        author = "rustre-yara-rules"
        description = "Detects reflective DLL injection pattern"
        category = "suspicious_patterns"
        severity = "high"
        tags = "reflective_dll,injection,evasion"
    strings:
        $rdll1 = "ReflectiveDLLInjection" ascii nocase
        $rdll2 = { 4D 5A 52 45 46 4C }
    condition:
        any of them
}
"#;

const RULE_PROCESS_HOLLOWING: &str = r#"
rule Process_Hollowing {
    meta:
        author = "rustre-yara-rules"
        description = "Detects process hollowing technique"
        category = "suspicious_patterns"
        severity = "high"
        tags = "process_hollowing,injection,evasion"
    strings:
        $ph1 = "NtUnmapViewOfSection" ascii
        $ph2 = "ZwUnmapViewOfSection" ascii
        $ph3 = "CreateProcessW" ascii
        $ph4 = "WriteProcessMemory" ascii
    condition:
        ($ph1 or $ph2) and ($ph3 and $ph4)
}
"#;

const RULE_TOKEN_IMPERSONATION: &str = r#"
rule Token_Impersonation {
    meta:
        author = "rustre-yara-rules"
        description = "Detects token impersonation privilege escalation"
        category = "exploit_tools"
        severity = "high"
        tags = "token,impersonation,privesc"
    strings:
        $t1 = "ImpersonateLoggedOnUser" ascii
        $t2 = "DuplicateTokenEx" ascii
        $t3 = "AdjustTokenPrivileges" ascii
    condition:
        2 of them
}
"#;

const RULE_LSASS_DUMP: &str = r#"
rule LSASS_Memory_Dump {
    meta:
        author = "rustre-yara-rules"
        description = "Detects LSASS memory dump attempt"
        category = "exploit_tools"
        severity = "critical"
        tags = "lsass,credential_dumping,dump"
    strings:
        $l1 = "lsass.exe" ascii wide nocase
        $l2 = "MiniDumpWriteDump" ascii
        $l3 = "PROCESS_VM_READ" ascii
    condition:
        2 of them
}
"#;

const RULE_DCOM_LATERAL: &str = r#"
rule DCOM_Lateral_Movement {
    meta:
        author = "rustre-yara-rules"
        description = "Detects DCOM lateral movement"
        category = "exploit_tools"
        severity = "high"
        tags = "dcom,lateral_movement"
    strings:
        $d1 = "MMC20.Application" ascii wide
        $d2 = "ShellWindows" ascii wide
        $d3 = "CoCreateInstance" ascii
    condition:
        2 of them
}
"#;

const RULE_PASS_THE_HASH: &str = r#"
rule Pass_The_Hash {
    meta:
        author = "rustre-yara-rules"
        description = "Detects Pass-The-Hash technique"
        category = "exploit_tools"
        severity = "critical"
        tags = "pass_the_hash,lateral_movement,credentials"
    strings:
        $pth1 = "NtLmSsp" ascii wide
        $pth2 = "aad3b435b51404eeaad3b435b51404ee" ascii nocase
    condition:
        any of them
}
"#;

const RULE_WMI_PERSISTENCE: &str = r#"
rule WMI_Persistence {
    meta:
        author = "rustre-yara-rules"
        description = "Detects WMI-based persistence mechanism"
        category = "suspicious_patterns"
        severity = "high"
        tags = "wmi,persistence,evasion"
    strings:
        $w1 = "Win32_EventFilter" ascii wide
        $w2 = "ActiveScriptEventConsumer" ascii wide
        $w3 = "__EventFilter" ascii wide
    condition:
        2 of them
}
"#;

// ─── Builtin Rules Registry ──────────────────────────────────────────────────

const fn builtin_rules_specs_part1() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_COBALT_STRIKE_BEACON,
            RuleCategory::Malware,
            Severity::Critical,
            &["cobalt_strike", "beacon", "c2"],
        ),
        (
            RULE_COBALT_STRIKE_SHELLCODE,
            RuleCategory::Malware,
            Severity::Critical,
            &["cobalt_strike", "shellcode"],
        ),
        (
            RULE_EMOTET_LOADER,
            RuleCategory::Loader,
            Severity::Critical,
            &["emotet", "loader"],
        ),
        (
            RULE_TRICKBOT,
            RuleCategory::Malware,
            Severity::Critical,
            &["trickbot", "banking"],
        ),
        (
            RULE_RYUK_RANSOMWARE,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["ryuk", "ransomware"],
        ),
        (
            RULE_LOCKBIT_RANSOMWARE,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["lockbit", "ransomware"],
        ),
        (
            RULE_CONTI_RANSOMWARE,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["conti", "ransomware"],
        ),
        (
            RULE_BLACKCAT_RANSOMWARE,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["blackcat", "alphv"],
        ),
        (
            RULE_QAKBOT,
            RuleCategory::Loader,
            Severity::High,
            &["qakbot", "banking"],
        ),
        (
            RULE_ICEDID,
            RuleCategory::Malware,
            Severity::High,
            &["icedid", "banking"],
        ),
        (
            RULE_DRIDEX,
            RuleCategory::Malware,
            Severity::High,
            &["dridex", "banking"],
        ),
        (
            RULE_ASYNCRAT,
            RuleCategory::Malware,
            Severity::High,
            &["asyncrat", "rat"],
        ),
    ]
}

const fn builtin_rules_specs_part1_2() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_NJRAT,
            RuleCategory::Malware,
            Severity::High,
            &["njrat", "rat"],
        ),
        (
            RULE_AGENT_TESLA,
            RuleCategory::InfoStealer,
            Severity::High,
            &["agent_tesla", "keylogger"],
        ),
        (
            RULE_FORMBOOK,
            RuleCategory::InfoStealer,
            Severity::High,
            &["formbook", "stealer"],
        ),
        (
            RULE_GULOADER,
            RuleCategory::Loader,
            Severity::High,
            &["guloader", "downloader"],
        ),
        (
            RULE_REMCOS,
            RuleCategory::Malware,
            Severity::High,
            &["remcos", "rat"],
        ),
        (
            RULE_AZORULT,
            RuleCategory::InfoStealer,
            Severity::High,
            &["azorult", "stealer"],
        ),
        (
            RULE_REDLINE_STEALER,
            RuleCategory::InfoStealer,
            Severity::High,
            &["redline", "stealer"],
        ),
        (
            RULE_RACCOON_STEALER,
            RuleCategory::InfoStealer,
            Severity::High,
            &["raccoon", "stealer"],
        ),
        (
            RULE_VIDAR,
            RuleCategory::InfoStealer,
            Severity::High,
            &["vidar", "stealer"],
        ),
        (
            RULE_UPX_3X,
            RuleCategory::Packers,
            Severity::Low,
            &["upx", "packer"],
        ),
        (
            RULE_UPX_4X,
            RuleCategory::Packers,
            Severity::Low,
            &["upx", "packer"],
        ),
        (
            RULE_THEMIDA,
            RuleCategory::Packers,
            Severity::Medium,
            &["themida", "protector"],
        ),
    ]
}

const fn builtin_rules_specs_part1b() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_VMPROTECT_2X,
            RuleCategory::Packers,
            Severity::Medium,
            &["vmprotect"],
        ),
        (
            RULE_VMPROTECT_3X,
            RuleCategory::Packers,
            Severity::Medium,
            &["vmprotect"],
        ),
        (
            RULE_MPRESS,
            RuleCategory::Packers,
            Severity::Low,
            &["mpress", "packer"],
        ),
        (
            RULE_PECOMPACT,
            RuleCategory::Packers,
            Severity::Low,
            &["pecompact", "packer"],
        ),
        (
            RULE_ASPACK,
            RuleCategory::Packers,
            Severity::Low,
            &["aspack", "packer"],
        ),
        (
            RULE_PESPIN,
            RuleCategory::Packers,
            Severity::Low,
            &["pespin", "packer"],
        ),
        (
            RULE_ENIGMA_PROTECTOR,
            RuleCategory::Packers,
            Severity::Medium,
            &["enigma", "protector"],
        ),
        (
            RULE_NSPACK,
            RuleCategory::Packers,
            Severity::Low,
            &["nspack", "packer"],
        ),
        (
            RULE_FSG_PACKER,
            RuleCategory::Packers,
            Severity::Low,
            &["fsg", "packer"],
        ),
        (
            RULE_WWPACK32,
            RuleCategory::Packers,
            Severity::Low,
            &["wwpack32", "packer"],
        ),
        (
            RULE_MORPHINE,
            RuleCategory::Packers,
            Severity::Low,
            &["morphine", "packer"],
        ),
        (
            RULE_PACKING_HIGH_ENTROPY,
            RuleCategory::Packers,
            Severity::Low,
            &["packer", "entropy"],
        ),
    ]
}

const fn builtin_rules_specs_part1b_2() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_AES_SBOX,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["aes", "sbox"],
        ),
        (
            RULE_AES_INV_SBOX,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["aes", "sbox"],
        ),
        (
            RULE_AES_RCON,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["aes", "rcon"],
        ),
        (
            RULE_CHACHA20_SIGMA,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["chacha20"],
        ),
        (
            RULE_RC4_CHARACTERISTIC,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["rc4"],
        ),
        (
            RULE_SHA256_K,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["sha256"],
        ),
        (
            RULE_MD5_T,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["md5"],
        ),
        (
            RULE_BLOWFISH_P,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["blowfish"],
        ),
        (
            RULE_CURVE25519,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["curve25519", "ecdh"],
        ),
        (
            RULE_RSA_BIGNUM,
            RuleCategory::CryptoConstants,
            Severity::Info,
            &["rsa", "bignum"],
        ),
    ]
}

const fn builtin_rules_specs_part2() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_MIMIKATZ,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["mimikatz", "credential_dumping"],
        ),
        (
            RULE_SHARPBOUND,
            RuleCategory::ExploitTools,
            Severity::High,
            &["sharphound", "bloodhound"],
        ),
        (
            RULE_RUBEUS,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["rubeus", "kerberos"],
        ),
        (
            RULE_IMPACKET,
            RuleCategory::ExploitTools,
            Severity::High,
            &["impacket", "smb"],
        ),
        (
            RULE_METASPLOIT_STAGER,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["metasploit", "shellcode"],
        ),
        (
            RULE_SLIVER_IMPLANT,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["sliver", "c2"],
        ),
        (
            RULE_POWERSPLOIT,
            RuleCategory::ExploitTools,
            Severity::High,
            &["powersploit", "powershell"],
        ),
        (
            RULE_EMPIRE,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["empire", "c2"],
        ),
        (
            RULE_HAVOC_C2,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["havoc", "c2"],
        ),
        (
            RULE_BRUTE_RATEL,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["brute_ratel", "c4"],
        ),
        (
            RULE_COVENANT_C2,
            RuleCategory::ExploitTools,
            Severity::High,
            &["covenant", "c2"],
        ),
        (
            RULE_MERLIN_AGENT,
            RuleCategory::ExploitTools,
            Severity::High,
            &["merlin", "c2"],
        ),
        (
            RULE_ANTIVM_CPUID,
            RuleCategory::SuspiciousPatterns,
            Severity::Medium,
            &["antivm", "cpuid"],
        ),
    ]
}

const fn builtin_rules_specs_part2_2() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_ANTIDEBUG_ISDBGPRESENT,
            RuleCategory::SuspiciousPatterns,
            Severity::Low,
            &["antidebug"],
        ),
        (
            RULE_SLEEPING_ANTI_ANALYSIS,
            RuleCategory::SuspiciousPatterns,
            Severity::Medium,
            &["anti_analysis", "sleep"],
        ),
        (
            RULE_HTTP_C2_BEACON,
            RuleCategory::SuspiciousPatterns,
            Severity::High,
            &["c2", "http"],
        ),
        (
            RULE_BASE64_POWERSHELL,
            RuleCategory::SuspiciousPatterns,
            Severity::Medium,
            &["powershell", "base64"],
        ),
        (
            RULE_DNS_DOH_TUNNEL,
            RuleCategory::SuspiciousPatterns,
            Severity::High,
            &["dns", "tunnel"],
        ),
        (
            RULE_ENCODED_CMD_WSCRIPT,
            RuleCategory::SuspiciousPatterns,
            Severity::Medium,
            &["wscript", "obfuscation"],
        ),
        (
            RULE_WANNACRY,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["wannacry", "ransomware"],
        ),
        (
            RULE_NOTPETYA,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["notpetya", "wiper"],
        ),
        (
            RULE_DARKSIDE_RANSOM,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["darkside", "ransomware"],
        ),
        (
            RULE_REVIL_RANSOMWARE,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["revil", "sodinokibi"],
        ),
        (
            RULE_HIVE_RANSOMWARE,
            RuleCategory::Ransomware,
            Severity::Critical,
            &["hive", "ransomware"],
        ),
        (
            RULE_DARKCOMET_RAT,
            RuleCategory::Malware,
            Severity::High,
            &["darkcomet", "rat"],
        ),
        (
            RULE_BLACKSHADES_RAT,
            RuleCategory::Malware,
            Severity::High,
            &["blackshades", "rat"],
        ),
    ]
}

const fn builtin_rules_specs_part2b() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_NETWIRE_RAT,
            RuleCategory::Malware,
            Severity::High,
            &["netwire", "rat"],
        ),
        (
            RULE_WARZONE_RAT,
            RuleCategory::Malware,
            Severity::High,
            &["warzone", "rat"],
        ),
        (
            RULE_BITRAT,
            RuleCategory::Malware,
            Severity::High,
            &["bitrat", "rat"],
        ),
        (
            RULE_NANOCORE_RAT,
            RuleCategory::Malware,
            Severity::High,
            &["nanocore", "rat"],
        ),
        (
            RULE_QUASAR_RAT,
            RuleCategory::Malware,
            Severity::High,
            &["quasar", "rat"],
        ),
        (
            RULE_REDLINE_V2,
            RuleCategory::InfoStealer,
            Severity::High,
            &["redline", "stealer"],
        ),
        (
            RULE_MARS_STEALER,
            RuleCategory::InfoStealer,
            Severity::High,
            &["mars", "stealer"],
        ),
        (
            RULE_LUMMA_STEALER,
            RuleCategory::InfoStealer,
            Severity::High,
            &["lumma", "stealer"],
        ),
        (
            RULE_META_STEALER,
            RuleCategory::InfoStealer,
            Severity::High,
            &["meta", "stealer"],
        ),
        (
            RULE_STEALC,
            RuleCategory::InfoStealer,
            Severity::High,
            &["stealc", "stealer"],
        ),
        (
            RULE_DONUT_LOADER,
            RuleCategory::Loader,
            Severity::High,
            &["donut", "loader"],
        ),
        (
            RULE_INDIRECT_SYSCALL,
            RuleCategory::SuspiciousPatterns,
            Severity::Medium,
            &["syscall", "evasion"],
        ),
    ]
}

const fn builtin_rules_specs_part2b_2() -> &'static [(&'static str, RuleCategory, Severity, &'static [&'static str])] {
    &[
        (
            RULE_HEAP_SPRAY,
            RuleCategory::ExploitTools,
            Severity::High,
            &["heap_spray", "exploit"],
        ),
        (
            RULE_ROP_CHAIN,
            RuleCategory::ExploitTools,
            Severity::High,
            &["rop", "exploit"],
        ),
        (
            RULE_SHELLCODE_GETPC,
            RuleCategory::SuspiciousPatterns,
            Severity::Medium,
            &["shellcode", "getpc"],
        ),
        (
            RULE_POWERSHELL_DOWNLOAD,
            RuleCategory::SuspiciousPatterns,
            Severity::High,
            &["powershell", "download"],
        ),
        (
            RULE_REFLECTIVE_DLL,
            RuleCategory::SuspiciousPatterns,
            Severity::High,
            &["reflective_dll", "injection"],
        ),
        (
            RULE_PROCESS_HOLLOWING,
            RuleCategory::SuspiciousPatterns,
            Severity::High,
            &["process_hollowing", "injection"],
        ),
        (
            RULE_TOKEN_IMPERSONATION,
            RuleCategory::ExploitTools,
            Severity::High,
            &["token", "privesc"],
        ),
        (
            RULE_LSASS_DUMP,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["lsass", "credential_dumping"],
        ),
        (
            RULE_DCOM_LATERAL,
            RuleCategory::ExploitTools,
            Severity::High,
            &["dcom", "lateral_movement"],
        ),
        (
            RULE_PASS_THE_HASH,
            RuleCategory::ExploitTools,
            Severity::Critical,
            &["pth", "credentials"],
        ),
        (
            RULE_WMI_PERSISTENCE,
            RuleCategory::SuspiciousPatterns,
            Severity::High,
            &["wmi", "persistence"],
        ),
    ]
}

fn builtin_rules() -> Vec<(RuleMeta, String)> {
    let pa = builtin_rules_specs_part1();
    let pb = builtin_rules_specs_part1_2();
    let pc = builtin_rules_specs_part1b();
    let pd = builtin_rules_specs_part1b_2();
    let pe = builtin_rules_specs_part2();
    let pf = builtin_rules_specs_part2_2();
    let pg = builtin_rules_specs_part2b();
    let ph = builtin_rules_specs_part2b_2();
    let total = pa.len() + pb.len() + pc.len() + pd.len()
              + pe.len() + pf.len() + pg.len() + ph.len();
    let mut results = Vec::with_capacity(total);
    for (text, category, severity, tags) in pa.iter()
        .chain(pb.iter())
        .chain(pc.iter())
        .chain(pd.iter())
        .chain(pe.iter())
        .chain(pf.iter())
        .chain(pg.iter())
        .chain(ph.iter())
    {
        let parsed = parse_yar_text(text, "builtin", "builtin");
        if let Some((mut meta, rule_text)) = parsed.into_iter().next() {
            meta.category.clone_from(category);
            meta.severity.clone_from(severity);
            meta.tags = tags.iter().map(std::string::ToString::to_string).collect();
            meta.source_name = "builtin".to_string();
            results.push((meta, rule_text));
        }
    }
    results
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_repo() -> RuleRepository {
        RuleRepository::new()
    }

    #[test]
    fn test_builtin_rules_loaded() {
        let repo = make_repo();
        assert!(!repo.list_rules().is_empty());
    }

    #[test]
    fn test_rule_count_reasonable() {
        let repo = make_repo();
        assert!(repo.list_rules().len() >= 30);
    }

    #[test]
    fn test_all_builtin_enabled_by_default() {
        let repo = make_repo();
        assert_eq!(repo.list_enabled_rules().len(), repo.list_rules().len());
    }

    #[test]
    fn test_enable_disable() {
        let mut repo = make_repo();
        let id = repo.list_rules()[0].rule_id.clone();
        repo.disable(&id).unwrap();
        assert!(!repo.get_rule(&id).unwrap().enabled);
        repo.enable(&id).unwrap();
        assert!(repo.get_rule(&id).unwrap().enabled);
    }

    #[test]
    fn test_enable_not_found() {
        let mut repo = make_repo();
        assert!(repo.enable("nonexistent_rule_id").is_err());
    }

    #[test]
    fn test_stats_basic() {
        let repo = make_repo();
        let stats = repo.stats();
        assert!(stats.total_rules > 0);
        assert_eq!(
            stats.enabled_count + stats.disabled_count,
            stats.total_rules
        );
    }

    #[test]
    fn test_stats_categories_sum() {
        let repo = make_repo();
        let stats = repo.stats();
        let cat_sum: usize = stats.by_category.values().sum();
        assert_eq!(cat_sum, stats.total_rules);
    }

    #[test]
    fn test_filter_by_category_packers() {
        let repo = make_repo();
        let filter = RuleFilter::new().category(RuleCategory::Packers);
        let filtered = repo.filter_rules(&filter);
        assert!(!filtered.is_empty());
        for r in &filtered {
            assert_eq!(r.category, RuleCategory::Packers);
        }
    }

    #[test]
    fn test_filter_by_category_crypto() {
        let repo = make_repo();
        let filter = RuleFilter::new().category(RuleCategory::CryptoConstants);
        let filtered = repo.filter_rules(&filter);
        assert!(!filtered.is_empty());
    }

    #[test]
    fn test_filter_by_severity() {
        let repo = make_repo();
        let filter = RuleFilter::new().severity_min(Severity::Critical);
        let filtered = repo.filter_rules(&filter);
        for r in &filtered {
            assert!(r.severity >= Severity::Critical);
        }
    }

    #[test]
    fn test_filter_enabled_only() {
        let mut repo = make_repo();
        let id = repo.list_rules()[0].rule_id.clone();
        repo.disable(&id).unwrap();
        let filter = RuleFilter::new().enabled_only();
        let filtered = repo.filter_rules(&filter);
        assert!(!filtered.iter().any(|r| r.rule_id == id));
    }

    #[test]
    fn test_compile_enabled() {
        let mut repo = make_repo();
        let crs = repo.compile_enabled().unwrap();
        assert!(crs.rule_count > 0);
        assert!(!crs.rules_text.is_empty());
    }

    #[test]
    fn test_compile_category() {
        let mut repo = make_repo();
        let crs = repo
            .compile_category(&RuleCategory::CryptoConstants)
            .unwrap();
        assert!(crs.rule_count > 0);
    }

    #[test]
    fn test_scan_returns_vec() {
        let mut repo = make_repo();
        repo.compile_enabled().unwrap();
        let _matches = repo.scan(b"MZ\x90\x00test data");
    }

    #[test]
    fn test_add_remove_source() {
        let mut repo = make_repo();
        let src = RuleSource::Local {
            path: PathBuf::from("/tmp/test.yar"),
            enabled: true,
        };
        repo.add_source(src);
        assert_eq!(repo.list_sources().len(), 1);
        let name = repo.list_sources()[0].name();
        repo.remove_source(&name);
        assert_eq!(repo.list_sources().len(), 0);
    }

    #[test]
    fn test_source_name_http() {
        let s = RuleSource::Http {
            url: "https://example.com/rules.yar".to_string(),
            refresh_secs: 3600,
            enabled: true,
        };
        assert!(s.name().starts_with("http:"));
        assert!(s.is_enabled());
    }

    #[test]
    fn test_rule_category_roundtrip() {
        for cat in &[
            RuleCategory::Malware,
            RuleCategory::Packers,
            RuleCategory::CryptoConstants,
            RuleCategory::ExploitTools,
            RuleCategory::SuspiciousPatterns,
            RuleCategory::Ransomware,
        ] {
            assert_eq!(RuleCategory::from_label(cat.as_str()), *cat);
        }
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_popular_sources_list() {
        let srcs = popular_public_sources();
        assert!(!srcs.is_empty());
        assert!(srcs.iter().any(|s| matches!(s, RuleSource::Git { .. })));
    }

    #[test]
    fn test_export_rules_empty_ids() {
        let repo = make_repo();
        let tmp = std::env::temp_dir().join("test_export_empty.yar");
        repo.export_rules(&[], &tmp).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        assert!(content.is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_export_all_enabled() {
        let repo = make_repo();
        let tmp = std::env::temp_dir().join("test_export_all_enabled.yar");
        repo.export_all_enabled(&tmp).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        assert!(!content.is_empty());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_disable_category_malware() {
        let mut repo = make_repo();
        repo.disable_category(&RuleCategory::Malware);
        let filter = RuleFilter::new()
            .category(RuleCategory::Malware)
            .enabled_only();
        assert!(repo.filter_rules(&filter).is_empty());
    }

    #[test]
    fn test_enable_category_after_disable() {
        let mut repo = make_repo();
        repo.disable_category(&RuleCategory::Ransomware);
        repo.enable_category(&RuleCategory::Ransomware);
        let filter = RuleFilter::new().category(RuleCategory::Ransomware);
        assert!(repo.filter_rules(&filter).iter().all(|r| r.enabled));
    }

    #[test]
    fn test_sync_nonexistent_local() {
        let mut repo = make_repo();
        let src = RuleSource::Local {
            path: PathBuf::from("/nonexistent/path/rules.yar"),
            enabled: true,
        };
        let report = repo.sync_source(&src);
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn test_sync_disabled_source() {
        let mut repo = make_repo();
        let src = RuleSource::Local {
            path: PathBuf::from("/tmp"),
            enabled: false,
        };
        let report = repo.sync_source(&src);
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn test_compiled_ruleset_fields() {
        let crs = CompiledRuleSet::new(
            "tid".to_string(),
            "rule foo { condition: true }".to_string(),
            1,
        );
        assert_eq!(crs.id, "tid");
        assert_eq!(crs.rule_count, 1);
    }

    #[test]
    fn test_parse_simple_rule() {
        let yar = "rule TestRule {\n    meta:\n        author = \"test\"\n        category = \"malware\"\n        severity = \"high\"\n    strings:\n        $s1 = \"hello\"\n    condition:\n        $s1\n}\n";
        let rules = parse_yar_text(yar, "test.yar", "test");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0.name, "TestRule");
    }

    #[test]
    fn test_parse_multiple_rules() {
        let yar = "rule Rule1 { meta: author = \"a\" strings: $s = \"a\" condition: $s }\nrule Rule2 { meta: author = \"b\" strings: $s = \"b\" condition: $s }\n";
        let rules = parse_yar_text(yar, "multi.yar", "test");
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_get_rule_by_id() {
        let repo = make_repo();
        let all = repo.list_rules();
        let id = &all[0].rule_id;
        assert!(repo.get_rule(id).is_some());
    }

    #[test]
    fn test_sync_report_default() {
        let report = SyncReport::default();
        assert_eq!(report.files_scanned, 0);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_rule_filter_name_contains() {
        let repo = make_repo();
        let filter = RuleFilter {
            name_contains: Some("AES".to_string()),
            ..Default::default()
        };
        for r in repo.filter_rules(&filter) {
            assert!(r.name.to_lowercase().contains("aes"));
        }
    }

    #[test]
    fn test_has_ransomware_rules() {
        let repo = make_repo();
        let filter = RuleFilter::new().category(RuleCategory::Ransomware);
        assert!(!repo.filter_rules(&filter).is_empty());
    }

    #[test]
    fn test_has_exploit_tools_rules() {
        let repo = make_repo();
        let filter = RuleFilter::new().category(RuleCategory::ExploitTools);
        assert!(!repo.filter_rules(&filter).is_empty());
    }

    #[test]
    fn test_has_info_stealer_rules() {
        let repo = make_repo();
        let filter = RuleFilter::new().category(RuleCategory::InfoStealer);
        assert!(!repo.filter_rules(&filter).is_empty());
    }

    #[test]
    fn test_scan_file_nonexistent() {
        let repo = make_repo();
        let res = repo.scan_file(Path::new("/nonexistent/file.bin"));
        assert!(res.is_err());
    }

    #[test]
    fn test_simple_hash_deterministic() {
        let h1 = simple_hash("hello world");
        let h2 = simple_hash("hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_simple_hash_differs() {
        let h1 = simple_hash("abc");
        let h2 = simple_hash("xyz");
        assert_ne!(h1, h2);
    }
}
