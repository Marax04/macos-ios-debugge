//! YARA ruleset manager.
//!
//! Provides [`YaraRulesetManager`], a registry that loads, indexes, and
//! lifecycle-manages collections of [`YaraTriageRule`]s from directories on
//! disk and from in-memory sources.  Rules are keyed by name; duplicate names
//! trigger a configurable conflict-resolution policy.
//!
//! Design goals:
//! - Load entire directories of `.yar` / `.yara` rule text files.
//! - Hot-reload individual rulesets without rebuilding the whole engine.
//! - Query rulesets by tag, severity, or name prefix.
//! - Track load metadata (source path, load time, error count).

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// DuplicatePolicy
// ─────────────────────────────────────────────────────────────────────────────

/// How to handle a rule whose name already exists in the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicatePolicy {
    /// Keep the existing rule; skip the new one.
    #[default]
    KeepExisting,
    /// Overwrite the existing rule with the new one.
    Overwrite,
    /// Reject the load operation and return an error.
    Reject,
}

// ─────────────────────────────────────────────────────────────────────────────
// RulesetEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single ruleset entry stored in the [`YaraRulesetManager`].
///
/// Each entry wraps one YARA-like rule together with provenance metadata.
#[derive(Debug, Clone)]
pub struct RulesetEntry {
    /// The rule name (unique within the manager).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Classification tags (e.g. `"malware"`, `"packer"`).
    pub tags: Vec<String>,
    /// Metadata key→value pairs.
    pub metadata: HashMap<String, String>,
    /// Named byte patterns: `(identifier, bytes)`.
    pub patterns: Vec<(String, Vec<u8>)>,
    /// When `true`, ALL patterns must match; when `false`, ANY match fires.
    pub condition_all: bool,
    /// The path the rule was loaded from, if any.
    pub source_path: Option<PathBuf>,
    /// Number of times this rule has matched during scans in this session.
    pub match_count: u64,
    /// Whether the rule is currently enabled.
    pub enabled: bool,
}

impl RulesetEntry {
    /// Create a new [`RulesetEntry`] with a name and description.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            tags: Vec::new(),
            metadata: HashMap::new(),
            patterns: Vec::new(),
            condition_all: false,
            source_path: None,
            match_count: 0,
            enabled: true,
        }
    }

    /// Add a named byte pattern.
    pub fn add_pattern(&mut self, id: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        self.patterns.push((id.into(), bytes.into()));
    }

    /// Add a classification tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Set a metadata key/value pair.
    pub fn set_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Return the `"severity"` metadata field, or `"unknown"` if absent.
    #[must_use]
    pub fn severity(&self) -> &str {
        self.metadata.get("severity").map_or("unknown", String::as_str)
    }

    /// Return `true` if the entry carries the given tag.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Increment the match counter.
    pub fn record_match(&mut self) {
        self.match_count += 1;
    }

    /// Return the total number of bytes across all patterns.
    #[must_use]
    pub fn total_pattern_bytes(&self) -> usize {
        self.patterns.iter().map(|(_, b)| b.len()).sum()
    }
}

impl fmt::Display for RulesetEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule {} [{}] ({} patterns, severity={})",
            self.name,
            self.tags.join(", "),
            self.patterns.len(),
            self.severity()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoadStats — per-directory load statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics produced by a [`load_directory`] call.
#[derive(Debug, Clone, Default)]
pub struct LoadStats {
    /// Directory that was scanned.
    pub directory: PathBuf,
    /// Number of `.yar` / `.yara` files found.
    pub files_found: usize,
    /// Number of rules successfully loaded.
    pub rules_loaded: usize,
    /// Number of rules skipped due to duplicate names.
    pub rules_skipped: usize,
    /// Number of rules that failed to parse.
    pub parse_errors: usize,
    /// Elapsed wall-clock time.
    pub elapsed: Duration,
    /// Non-fatal error messages.
    pub errors: Vec<String>,
}

impl LoadStats {
    /// Return `true` if all files were parsed without errors.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.parse_errors == 0
    }

    /// Total rules encountered (loaded + skipped + errored).
    #[must_use]
    pub const fn total_encountered(&self) -> usize {
        self.rules_loaded + self.rules_skipped + self.parse_errors
    }
}

impl fmt::Display for LoadStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LoadStats {{ dir={}, files={}, loaded={}, skipped={}, errors={}, elapsed={:.2?} }}",
            self.directory.display(),
            self.files_found,
            self.rules_loaded,
            self.rules_skipped,
            self.parse_errors,
            self.elapsed
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RulesetManagerError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the [`YaraRulesetManager`].
#[derive(Debug)]
pub enum RulesetManagerError {
    /// The directory does not exist or is not readable.
    DirectoryNotFound(PathBuf),
    /// A rule name already exists and the policy is [`DuplicatePolicy::Reject`].
    DuplicateRule(String),
    /// A parse error in a rule file.
    ParseError { path: PathBuf, message: String },
    /// Generic I/O error description.
    Io(String),
}

impl fmt::Display for RulesetManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectoryNotFound(p) => write!(f, "directory not found: {}", p.display()),
            Self::DuplicateRule(n) => write!(f, "duplicate rule name: '{n}'"),
            Self::ParseError { path, message } => {
                write!(f, "parse error in {}: {message}", path.display())
            }
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for RulesetManagerError {}

// ─────────────────────────────────────────────────────────────────────────────
// YaraRulesetManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages a collection of YARA-like rules.
///
/// Rules are stored in insertion order (for deterministic scan order) and also
/// indexed by name for O(1) lookup.
#[derive(Debug)]
pub struct YaraRulesetManager {
    /// All rules in insertion order.
    entries: Vec<RulesetEntry>,
    /// Name → index into `entries` for O(1) lookup.
    index: HashMap<String, usize>,
    /// Policy for handling duplicate names.
    duplicate_policy: DuplicatePolicy,
    /// Directories that have been loaded.
    loaded_dirs: Vec<PathBuf>,
}

impl YaraRulesetManager {
    /// Create an empty manager with the default duplicate policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
            duplicate_policy: DuplicatePolicy::default(),
            loaded_dirs: Vec::new(),
        }
    }

    /// Override the duplicate-name policy.
    #[must_use]
    pub fn with_duplicate_policy(mut self, policy: DuplicatePolicy) -> Self {
        self.duplicate_policy = policy;
        self
    }

    // ── Insertion ─────────────────────────────────────────────────────────────

    /// Add a single [`RulesetEntry`].
    ///
    /// # Errors
    ///
    /// Returns [`RulesetManagerError::DuplicateRule`] when the policy is
    /// [`DuplicatePolicy::Reject`] and a rule with the same name already exists.
    pub fn add_entry(&mut self, entry: RulesetEntry) -> Result<(), RulesetManagerError> {
        if let Some(&existing_idx) = self.index.get(&entry.name) {
            match self.duplicate_policy {
                DuplicatePolicy::KeepExisting => return Ok(()),
                DuplicatePolicy::Overwrite => {
                    self.entries[existing_idx] = entry;
                    return Ok(());
                }
                DuplicatePolicy::Reject => {
                    return Err(RulesetManagerError::DuplicateRule(entry.name));
                }
            }
        }
        let idx = self.entries.len();
        self.index.insert(entry.name.clone(), idx);
        self.entries.push(entry);
        Ok(())
    }

    /// Load all `.yar` and `.yara` files from a directory (non-recursive).
    ///
    /// Each file is parsed using [`parse_yar_file`].  Parse errors are
    /// recorded in [`LoadStats`] but do not stop the load.
    ///
    /// # Errors
    ///
    /// Returns [`RulesetManagerError::DirectoryNotFound`] if `dir` does not
    /// exist.
    pub fn load_directory(&mut self, dir: &Path) -> Result<LoadStats, RulesetManagerError> {
        if !dir.is_dir() {
            return Err(RulesetManagerError::DirectoryNotFound(dir.to_path_buf()));
        }

        let start = Instant::now();
        let mut stats = LoadStats {
            directory: dir.to_path_buf(),
            ..Default::default()
        };

        let read_dir = std::fs::read_dir(dir).map_err(|e| RulesetManagerError::Io(e.to_string()))?;

        for dir_entry_res in read_dir {
            let dir_entry = match dir_entry_res {
                Ok(e) => e,
                Err(e) => {
                    stats.errors.push(format!("read_dir entry error: {e}"));
                    continue;
                }
            };
            let path = dir_entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yar" && ext != "yara" {
                continue;
            }
            stats.files_found += 1;

            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    stats.parse_errors += 1;
                    stats.errors.push(format!("{}: read error: {e}", path.display()));
                    continue;
                }
            };

            match parse_yar_text(&text, &path) {
                Ok(mut rule) => {
                    rule.source_path = Some(path.clone());
                    match self.add_entry(rule) {
                        Ok(()) => stats.rules_loaded += 1,
                        Err(RulesetManagerError::DuplicateRule(_)) => stats.rules_skipped += 1,
                        Err(e) => {
                            stats.parse_errors += 1;
                            stats.errors.push(format!("{}: {e}", path.display()));
                        }
                    }
                }
                Err(msg) => {
                    stats.parse_errors += 1;
                    stats.errors.push(format!("{}: parse error: {msg}", path.display()));
                }
            }
        }

        stats.elapsed = start.elapsed();
        self.loaded_dirs.push(dir.to_path_buf());
        Ok(stats)
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Find a rule by exact name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&RulesetEntry> {
        self.index.get(name).map(|&i| &self.entries[i])
    }

    /// Find a rule by exact name (mutable).
    #[must_use]
    pub fn get_mut(&mut self, name: &str) -> Option<&mut RulesetEntry> {
        self.index.get(name).copied().map(|i| &mut self.entries[i])
    }

    /// Return all rules whose names start with `prefix`.
    #[must_use]
    pub fn by_prefix(&self, prefix: &str) -> Vec<&RulesetEntry> {
        self.entries
            .iter()
            .filter(|e| e.name.starts_with(prefix))
            .collect()
    }

    /// Return all rules that carry `tag`.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<&RulesetEntry> {
        self.entries.iter().filter(|e| e.has_tag(tag)).collect()
    }

    /// Return all rules whose `"severity"` metadata equals `severity`.
    #[must_use]
    pub fn by_severity(&self, severity: &str) -> Vec<&RulesetEntry> {
        self.entries
            .iter()
            .filter(|e| e.severity() == severity)
            .collect()
    }

    /// Return all enabled rules.
    #[must_use]
    pub fn enabled_rules(&self) -> Vec<&RulesetEntry> {
        self.entries.iter().filter(|e| e.enabled).collect()
    }

    // ── Management ────────────────────────────────────────────────────────────

    /// Disable a rule by name. Returns `true` if the rule was found.
    pub fn disable(&mut self, name: &str) -> bool {
        if let Some(entry) = self.get_mut(name) {
            entry.enabled = false;
            true
        } else {
            false
        }
    }

    /// Enable a rule by name. Returns `true` if the rule was found.
    pub fn enable(&mut self, name: &str) -> bool {
        if let Some(entry) = self.get_mut(name) {
            entry.enabled = true;
            true
        } else {
            false
        }
    }

    /// Remove a rule by name. Returns the removed entry, if any.
    pub fn remove(&mut self, name: &str) -> Option<RulesetEntry> {
        let idx = *self.index.get(name)?;
        self.index.remove(name);
        let entry = self.entries.remove(idx);
        // Re-index entries after the removed one
        for (i, e) in self.entries.iter().enumerate().skip(idx) {
            self.index.insert(e.name.clone(), i);
        }
        Some(entry)
    }

    /// Clear all rules.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
        self.loaded_dirs.clear();
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Total number of rules (enabled + disabled).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of enabled rules.
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.entries.iter().filter(|e| e.enabled).count()
    }

    /// Total match count across all rules.
    #[must_use]
    pub fn total_match_count(&self) -> u64 {
        self.entries.iter().map(|e| e.match_count).sum()
    }

    /// Directories that have been loaded into this manager.
    #[must_use]
    pub fn loaded_directories(&self) -> &[PathBuf] {
        &self.loaded_dirs
    }

    /// Iterate over all entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &RulesetEntry> {
        self.entries.iter()
    }

    /// Return all unique tags across all rules.
    #[must_use]
    pub fn all_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .entries
            .iter()
            .flat_map(|e| e.tags.iter().cloned())
            .collect();
        tags.sort_unstable();
        tags.dedup();
        tags
    }

    /// Record a match hit for the named rule. Does nothing if the rule is
    /// not found.
    pub fn record_match(&mut self, name: &str) {
        if let Some(entry) = self.get_mut(name) {
            entry.record_match();
        }
    }

    /// Return the top-N most-matched rules.
    #[must_use]
    pub fn top_matched(&self, n: usize) -> Vec<&RulesetEntry> {
        let mut sorted: Vec<&RulesetEntry> = self.entries.iter().collect();
        sorted.sort_unstable_by(|a, b| b.match_count.cmp(&a.match_count));
        sorted.truncate(n);
        sorted
    }

    /// Build a manager pre-loaded with the standard built-in rules.
    #[must_use]
    pub fn with_builtin_rules() -> Self {
        let mut mgr = Self::new();
        for entry in builtin_rules() {
            let _ = mgr.add_entry(entry);
        }
        mgr
    }
}

impl Default for YaraRulesetManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_yar_text — minimal .yar text parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a simplified YARA rule text block.
///
/// Supported subset:
/// ```text
/// rule <name> [: tag1 tag2] {
///     meta:
///         key = "value"
///     strings:
///         $id = "text" | { hex bytes }
///     condition:
///         any of them | all of them
/// }
/// ```
///
/// # Errors
///
/// Returns a string error if the text is malformed.
pub fn parse_yar_text(text: &str, path: &Path) -> Result<RulesetEntry, String> {
    let mut entry: Option<RulesetEntry> = None;
    let mut section = "";

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with("/*") {
            continue;
        }

        if line.starts_with("rule ") {
            // rule <name> [: tag1 tag2] {
            let after_rule = line.trim_start_matches("rule ").trim_end_matches('{').trim();
            let (name_part, tags_part) = after_rule.find(':').map_or(
                (after_rule, ""),
                |colon| (&after_rule[..colon], &after_rule[colon + 1..]),
            );
            let name = name_part.trim().to_string();
            if name.is_empty() {
                return Err(format!("{}: rule has no name", path.display()));
            }
            let mut e = RulesetEntry::new(name, "");
            for tag in tags_part.split_whitespace() {
                e.add_tag(tag);
            }
            e.source_path = Some(path.to_path_buf());
            entry = Some(e);
            continue;
        }

        if line == "meta:" {
            section = "meta";
            continue;
        }
        if line == "strings:" {
            section = "strings";
            continue;
        }
        if line == "condition:" {
            section = "condition";
            continue;
        }
        if line == "}" {
            section = "";
            continue;
        }

        let e = entry.as_mut().ok_or_else(|| format!("{}: content before rule header", path.display()))?;

        match section {
            "meta" => {
                // key = "value"
                if let Some(eq) = line.find('=') {
                    let key = line[..eq].trim().to_string();
                    let val = line[eq + 1..]
                        .trim()
                        .trim_matches('"')
                        .to_string();
                    if key == "description" {
                        e.description = val;
                    } else {
                        e.set_meta(key, val);
                    }
                }
            }
            "strings" => {
                // $id = "text"  or  $id = { hex }
                if let Some(eq) = line.find('=') {
                    let id = line[..eq].trim().to_string();
                    let val_part = line[eq + 1..].trim();
                    if val_part.starts_with('"') {
                        let text_val = val_part.trim_matches('"').as_bytes().to_vec();
                        e.add_pattern(id, text_val);
                    } else if val_part.starts_with('{') {
                        let hex_str = val_part
                            .trim_start_matches('{')
                            .trim_end_matches('}')
                            .trim();
                        let bytes: Vec<u8> = hex_str
                            .split_whitespace()
                            .filter(|t| *t != "??")
                            .filter_map(|t| u8::from_str_radix(t, 16).ok())
                            .collect();
                        e.add_pattern(id, bytes);
                    }
                }
            }
            "condition" => {
                if line.contains("all of them") {
                    e.condition_all = true;
                }
            }
            _ => {}
        }
    }

    entry.ok_or_else(|| format!("{}: no rule found in file", path.display()))
}

// ─────────────────────────────────────────────────────────────────────────────
// load_directory (free function)
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience free function: create a [`YaraRulesetManager`] loaded from `dir`.
///
/// # Errors
///
/// Propagates [`RulesetManagerError`] from [`YaraRulesetManager::load_directory`].
pub fn load_directory(dir: &Path) -> Result<(YaraRulesetManager, LoadStats), RulesetManagerError> {
    let mut mgr = YaraRulesetManager::new();
    let stats = mgr.load_directory(dir)?;
    Ok((mgr, stats))
}

// ─────────────────────────────────────────────────────────────────────────────
// builtin_rules
// ─────────────────────────────────────────────────────────────────────────────

/// Return the set of built-in rules that ship with the triage engine.
fn builtin_rules() -> Vec<RulesetEntry> {
    let mut rules = Vec::new();

    macro_rules! rule {
        ($name:expr, $desc:expr, $sev:expr, $tags:expr, $patterns:expr) => {{
            let mut e = RulesetEntry::new($name, $desc);
            e.set_meta("severity", $sev);
            for tag in $tags.iter() {
                e.add_tag(*tag);
            }
            for &(id, bytes) in $patterns.iter() {
                e.add_pattern(id, bytes.to_vec());
            }
            e
        }};
    }

    rules.push(rule!(
        "UPX_Packer",
        "UPX executable packer",
        "medium",
        &["packer"],
        &[("$s0", b"UPX0".as_ref()), ("$s1", b"UPX1".as_ref())]
    ));

    rules.push(rule!(
        "Mimikatz",
        "Mimikatz credential dump tool",
        "critical",
        &["credential-theft"],
        &[("$s0", b"mimikatz".as_ref()), ("$s1", b"sekurlsa".as_ref())]
    ));

    rules.push(rule!(
        "WannaCry",
        "WannaCry ransomware",
        "critical",
        &["ransomware"],
        &[("$s0", b"WNcry@2ol7".as_ref()), ("$s1", b".wnry".as_ref())]
    ));

    rules.push(rule!(
        "Cobalt_Strike",
        "Cobalt Strike beacon",
        "critical",
        &["rat", "c2"],
        &[("$s0", b"beacon.dll".as_ref()), ("$s1", b"ReflectiveDll".as_ref())]
    ));

    rules.push(rule!(
        "AntiDebug",
        "Anti-debugging techniques detected",
        "medium",
        &["anti-analysis"],
        &[
            ("$s0", b"IsDebuggerPresent".as_ref()),
            ("$s1", b"NtQueryInformationProcess".as_ref())
        ]
    ));

    rules.push(rule!(
        "Process_Injection",
        "Process injection API usage",
        "high",
        &["injection"],
        &[
            ("$s0", b"VirtualAllocEx".as_ref()),
            ("$s1", b"WriteProcessMemory".as_ref()),
            ("$s2", b"CreateRemoteThread".as_ref())
        ]
    ));

    rules.push(rule!(
        "PowerShell_Cradle",
        "PowerShell download-and-execute cradle",
        "high",
        &["powershell", "downloader"],
        &[("$s0", b"IEX".as_ref()), ("$s1", b"DownloadString".as_ref())]
    ));

    rules.push(rule!(
        "ELF_Magic",
        "ELF binary magic bytes",
        "info",
        &["format", "elf"],
        &[("$s0", b"\x7FELF".as_ref())]
    ));

    rules.push(rule!(
        "PE_Magic",
        "PE/MZ binary magic bytes",
        "info",
        &["format", "pe"],
        &[("$s0", b"MZ".as_ref())]
    ));

    rules.push(rule!(
        "TrickBot",
        "TrickBot banking trojan",
        "critical",
        &["banking", "trojan"],
        &[("$s0", b"trickbot".as_ref()), ("$s1", b"pwgrab".as_ref())]
    ));

    rules
}

// ─────────────────────────────────────────────────────────────────────────────
// RulesetSummary
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight summary of the manager's current state.
#[derive(Debug, Clone)]
pub struct RulesetSummary {
    /// Total rules loaded.
    pub total_rules: usize,
    /// Number of enabled rules.
    pub enabled_rules: usize,
    /// All unique tags.
    pub tags: Vec<String>,
    /// Total matches recorded this session.
    pub total_matches: u64,
    /// Loaded directories.
    pub loaded_dirs: Vec<PathBuf>,
}

impl YaraRulesetManager {
    /// Produce a lightweight summary of the manager state.
    #[must_use]
    pub fn summary(&self) -> RulesetSummary {
        RulesetSummary {
            total_rules: self.rule_count(),
            enabled_rules: self.enabled_count(),
            tags: self.all_tags(),
            total_matches: self.total_match_count(),
            loaded_dirs: self.loaded_dirs.clone(),
        }
    }
}

impl fmt::Display for RulesetSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RulesetSummary {{ rules={}/{}, tags=[{}], matches={} }}",
            self.enabled_rules,
            self.total_rules,
            self.tags.join(", "),
            self.total_matches
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, severity: &str, tags: &[&str]) -> RulesetEntry {
        let mut e = RulesetEntry::new(name, "desc");
        e.set_meta("severity", severity);
        for t in tags {
            e.add_tag(*t);
        }
        e.add_pattern("$s0", b"pattern".to_vec());
        e
    }

    #[test]
    fn test_add_and_get() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("R1", "high", &["tag1"])).unwrap();
        assert!(mgr.get("R1").is_some());
        assert!(mgr.get("R2").is_none());
    }

    #[test]
    fn test_duplicate_keep_existing() {
        let mut mgr = YaraRulesetManager::new().with_duplicate_policy(DuplicatePolicy::KeepExisting);
        mgr.add_entry(make_entry("R1", "high", &[])).unwrap();
        mgr.add_entry(make_entry("R1", "low", &[])).unwrap();
        assert_eq!(mgr.get("R1").unwrap().severity(), "high");
        assert_eq!(mgr.rule_count(), 1);
    }

    #[test]
    fn test_duplicate_overwrite() {
        let mut mgr = YaraRulesetManager::new().with_duplicate_policy(DuplicatePolicy::Overwrite);
        mgr.add_entry(make_entry("R1", "high", &[])).unwrap();
        mgr.add_entry(make_entry("R1", "low", &[])).unwrap();
        assert_eq!(mgr.get("R1").unwrap().severity(), "low");
        assert_eq!(mgr.rule_count(), 1);
    }

    #[test]
    fn test_duplicate_reject() {
        let mut mgr = YaraRulesetManager::new().with_duplicate_policy(DuplicatePolicy::Reject);
        mgr.add_entry(make_entry("R1", "high", &[])).unwrap();
        let err = mgr.add_entry(make_entry("R1", "low", &[]));
        assert!(matches!(err, Err(RulesetManagerError::DuplicateRule(_))));
    }

    #[test]
    fn test_by_tag() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("A", "high", &["malware"])).unwrap();
        mgr.add_entry(make_entry("B", "medium", &["packer"])).unwrap();
        mgr.add_entry(make_entry("C", "high", &["malware"])).unwrap();
        let tagged = mgr.by_tag("malware");
        assert_eq!(tagged.len(), 2);
    }

    #[test]
    fn test_by_severity() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("A", "critical", &[])).unwrap();
        mgr.add_entry(make_entry("B", "medium", &[])).unwrap();
        assert_eq!(mgr.by_severity("critical").len(), 1);
        assert_eq!(mgr.by_severity("medium").len(), 1);
    }

    #[test]
    fn test_enable_disable() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("R1", "high", &[])).unwrap();
        assert_eq!(mgr.enabled_count(), 1);
        mgr.disable("R1");
        assert_eq!(mgr.enabled_count(), 0);
        mgr.enable("R1");
        assert_eq!(mgr.enabled_count(), 1);
    }

    #[test]
    fn test_remove() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("R1", "high", &[])).unwrap();
        mgr.add_entry(make_entry("R2", "low", &[])).unwrap();
        let removed = mgr.remove("R1");
        assert!(removed.is_some());
        assert_eq!(mgr.rule_count(), 1);
        assert!(mgr.get("R1").is_none());
        assert!(mgr.get("R2").is_some());
    }

    #[test]
    fn test_record_match() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("R1", "high", &[])).unwrap();
        mgr.record_match("R1");
        mgr.record_match("R1");
        assert_eq!(mgr.get("R1").unwrap().match_count, 2);
        assert_eq!(mgr.total_match_count(), 2);
    }

    #[test]
    fn test_top_matched() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("R1", "high", &[])).unwrap();
        mgr.add_entry(make_entry("R2", "high", &[])).unwrap();
        mgr.record_match("R1");
        mgr.record_match("R1");
        mgr.record_match("R2");
        let top = mgr.top_matched(1);
        assert_eq!(top[0].name, "R1");
    }

    #[test]
    fn test_builtin_rules() {
        let mgr = YaraRulesetManager::with_builtin_rules();
        assert!(mgr.rule_count() >= 5);
        assert!(mgr.get("Mimikatz").is_some());
        assert!(mgr.get("UPX_Packer").is_some());
    }

    #[test]
    fn test_all_tags() {
        let mut mgr = YaraRulesetManager::new();
        mgr.add_entry(make_entry("A", "high", &["tag1", "tag2"])).unwrap();
        mgr.add_entry(make_entry("B", "high", &["tag2", "tag3"])).unwrap();
        let tags = mgr.all_tags();
        assert!(tags.contains(&"tag1".to_string()));
        assert!(tags.contains(&"tag2".to_string()));
        assert!(tags.contains(&"tag3".to_string()));
        // dedup: tag2 appears once
        assert_eq!(tags.iter().filter(|t| t.as_str() == "tag2").count(), 1);
    }

    #[test]
    fn test_summary() {
        let mgr = YaraRulesetManager::with_builtin_rules();
        let s = mgr.summary();
        assert_eq!(s.total_rules, mgr.rule_count());
        assert!(s.total_rules > 0);
    }

    #[test]
    fn test_parse_yar_text_minimal() {
        let text = r#"
rule TestRule : malware packer {
    meta:
        description = "A test rule"
        severity = "high"
    strings:
        $s0 = "MZ"
    condition:
        any of them
}
"#;
        let path = Path::new("test.yar");
        let entry = parse_yar_text(text, path).unwrap();
        assert_eq!(entry.name, "TestRule");
        assert_eq!(entry.description, "A test rule");
        assert!(entry.has_tag("malware"));
        assert!(entry.has_tag("packer"));
        assert_eq!(entry.severity(), "high");
        assert_eq!(entry.patterns.len(), 1);
    }

    #[test]
    fn test_entry_display() {
        let e = make_entry("MyRule", "critical", &["malware"]);
        let s = e.to_string();
        assert!(s.contains("MyRule"));
        assert!(s.contains("malware"));
    }

    #[test]
    fn test_load_stats_is_clean() {
        let stats = LoadStats::default();
        assert!(stats.is_clean());
    }

    #[test]
    fn test_load_directory_not_found() {
        let mut mgr = YaraRulesetManager::new();
        let result = mgr.load_directory(Path::new("/nonexistent/path/abc123"));
        assert!(matches!(result, Err(RulesetManagerError::DirectoryNotFound(_))));
    }
}
