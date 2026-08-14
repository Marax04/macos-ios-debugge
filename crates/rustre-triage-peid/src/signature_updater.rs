// rustre-triage-peid/src/signature_updater.rs
// Download, merge, and version PEiD signature databases from online sources.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Error from signature updating operations.
#[derive(Debug, Clone)]
pub enum UpdaterError {
    Io(String),
    Network(String),
    Parse(String),
    InvalidVersion,
    AlreadyUpToDate,
}

impl std::fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O error: {s}"),
            Self::Network(s) => write!(f, "Network error: {s}"),
            Self::Parse(s) => write!(f, "Parse error: {s}"),
            Self::InvalidVersion => write!(f, "Invalid version format"),
            Self::AlreadyUpToDate => write!(f, "Database is already up-to-date"),
        }
    }
}

pub type UpdaterResult<T> = Result<T, UpdaterError>;

/// A version identifier for a signature database.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DbVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub build: Option<u32>,
}

impl DbVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch, build: None }
    }

    pub fn parse(s: &str) -> UpdaterResult<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 3 { return Err(UpdaterError::InvalidVersion); }
        Ok(Self {
            major: parts[0].parse().map_err(|_| UpdaterError::InvalidVersion)?,
            minor: parts[1].parse().map_err(|_| UpdaterError::InvalidVersion)?,
            patch: parts[2].parse().map_err(|_| UpdaterError::InvalidVersion)?,
            build: parts.get(3).and_then(|p| p.parse().ok()),
        })
    }
}

impl std::fmt::Display for DbVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(b) = self.build {
            write!(f, "{}.{}.{}.{}", self.major, self.minor, self.patch, b)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

/// A known source for PEiD signature databases.
#[derive(Debug, Clone)]
pub struct SignatureSource {
    pub name: &'static str,
    pub url: &'static str,
    pub format: SourceFormat,
    pub priority: u8, // Higher = preferred.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    PeidUserdb,
    DieSig,
    Json,
}

/// Built-in list of known signature sources.
pub const KNOWN_SOURCES: &[SignatureSource] = &[
    SignatureSource {
        name: "PEiD Official",
        url: "https://raw.githubusercontent.com/wolfram77web/app-peid/master/userdb.txt",
        format: SourceFormat::PeidUserdb,
        priority: 90,
    },
    SignatureSource {
        name: "DIE Signatures",
        url: "https://raw.githubusercontent.com/horsicq/DIE-engine/master/db/PE",
        format: SourceFormat::DieSig,
        priority: 85,
    },
    SignatureSource {
        name: "kanal-peid",
        url: "https://raw.githubusercontent.com/KasperskyLab/kanal/master/signatures/userdb.txt",
        format: SourceFormat::PeidUserdb,
        priority: 80,
    },
    SignatureSource {
        name: "peid-signatures",
        url: "https://github.com/ExeinIoT/peid-signatures/raw/main/peid_userdb.txt",
        format: SourceFormat::PeidUserdb,
        priority: 75,
    },
];

/// Changelog entry recording what was added/removed in an update.
#[derive(Debug, Clone)]
pub struct ChangelogEntry {
    pub version: DbVersion,
    pub timestamp: u64,     // Unix timestamp.
    pub added: usize,
    pub removed: usize,
    pub updated: usize,
    pub source: String,
    pub notes: Vec<String>,
}

/// Local signature database state.
#[derive(Debug, Clone)]
pub struct LocalDatabaseState {
    pub path: PathBuf,
    pub version: DbVersion,
    pub signature_count: usize,
    pub last_updated: u64,
    pub changelog: Vec<ChangelogEntry>,
}

impl LocalDatabaseState {
    pub fn new(path: impl Into<PathBuf>, version: DbVersion) -> Self {
        Self {
            path: path.into(),
            version,
            signature_count: 0,
            last_updated: 0,
            changelog: Vec::new(),
        }
    }
}

/// Result of an update operation.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub success: bool,
    pub new_version: DbVersion,
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub source_used: String,
    pub warnings: Vec<String>,
}

/// Configuration for the updater.
#[derive(Debug, Clone)]
pub struct UpdaterConfig {
    pub sources: Vec<SignatureSource>,
    pub cache_dir: PathBuf,
    pub timeout_secs: u64,
    pub auto_dedup: bool,
    pub max_signatures: usize,
    pub min_signature_length: usize,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            sources: KNOWN_SOURCES.to_vec(),
            cache_dir: PathBuf::from("./.peid_cache"),
            timeout_secs: 30,
            auto_dedup: true,
            max_signatures: 100_000,
            min_signature_length: 4,
        }
    }
}

/// The signature updater.
pub struct SignatureUpdater {
    pub config: UpdaterConfig,
    state: Option<LocalDatabaseState>,
}

impl Default for SignatureUpdater {
    fn default() -> Self {
        Self { config: UpdaterConfig::default(), state: None }
    }
}

impl SignatureUpdater {
    pub fn new(config: UpdaterConfig) -> Self {
        Self { config, state: None }
    }

    pub fn with_state(mut self, state: LocalDatabaseState) -> Self {
        self.state = Some(state);
        self
    }

    /// Download raw text from a URL (requires a network-capable runtime).
    /// This is a stub — in a real implementation, use reqwest or ureq.
    #[cfg(feature = "network")]
    pub fn download_raw(&self, url: &str) -> UpdaterResult<String> {
        // Stub: would use reqwest::blocking::get(url).
        Err(UpdaterError::Network(format!("Network not available for: {url}")))
    }

    /// Offline version: read from a local file path.
    pub fn load_local(&self, path: &Path) -> UpdaterResult<String> {
        std::fs::read_to_string(path).map_err(|e| UpdaterError::Io(e.to_string()))
    }

    /// Parse signatures from a raw userdb.txt string.
    pub fn parse_raw(&self, raw: &str) -> UpdaterResult<Vec<crate::userdb_parser::ParsedSignature>> {
        crate::userdb_parser::parse_inline(raw).map_err(|e| UpdaterError::Parse(e.to_string()))
    }

    /// Merge new signatures into an existing set, returning counts.
    pub fn merge(
        &self,
        existing: Vec<crate::userdb_parser::ParsedSignature>,
        new_sigs: Vec<crate::userdb_parser::ParsedSignature>,
    ) -> (Vec<crate::userdb_parser::ParsedSignature>, usize, usize) {
        let original_count = existing.len();
        let merged = crate::userdb_parser::merge_signatures(existing, new_sigs);
        let added = merged.len().saturating_sub(original_count);
        let deduped = original_count + added - merged.len();
        (merged, added, deduped)
    }

    /// Save a signature list to a file.
    pub fn save_to_file(
        &self,
        sigs: &[crate::userdb_parser::ParsedSignature],
        path: &Path,
    ) -> UpdaterResult<()> {
        let text = crate::userdb_parser::to_userdb_text(sigs);
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))
            .map_err(|e| UpdaterError::Io(e.to_string()))?;
        std::fs::write(path, text).map_err(|e| UpdaterError::Io(e.to_string()))
    }

    /// Perform a full update cycle from a local file (offline).
    pub fn update_from_file(
        &mut self,
        source_path: &Path,
        dest_path: &Path,
    ) -> UpdaterResult<UpdateResult> {
        // Load current DB if it exists.
        let existing = if dest_path.exists() {
            let text = self.load_local(dest_path)?;
            self.parse_raw(&text).unwrap_or_default()
        } else {
            Vec::new()
        };

        // Load new sigs.
        let raw = self.load_local(source_path)?;
        let new_sigs = self.parse_raw(&raw)?;

        let _new_count = new_sigs.len();
        let (merged, added, _) = self.merge(existing.clone(), new_sigs);

        // Filter too-short sigs.
        let min_len = self.config.min_signature_length;
        let filtered: Vec<_> = merged.into_iter()
            .filter(|s| s.pattern.len() >= min_len)
            .take(self.config.max_signatures)
            .collect();

        let removed = existing.len().saturating_sub(filtered.len());
        let unchanged = filtered.len().saturating_sub(added);

        self.save_to_file(&filtered, dest_path)?;

        let new_version = if let Some(ref s) = self.state {
            DbVersion::new(s.version.major, s.version.minor, s.version.patch + 1)
        } else {
            DbVersion::new(1, 0, 0)
        };

        if let Some(ref mut s) = self.state {
            s.version = new_version.clone();
            s.signature_count = filtered.len();
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            s.last_updated = ts;
            s.changelog.push(ChangelogEntry {
                version: new_version.clone(),
                timestamp: ts,
                added,
                removed,
                updated: 0,
                source: source_path.display().to_string(),
                notes: Vec::new(),
            });
        }

        Ok(UpdateResult {
            success: true,
            new_version,
            added,
            removed,
            unchanged,
            source_used: source_path.display().to_string(),
            warnings: Vec::new(),
        })
    }

    /// Collect statistics about the signature database.
    pub fn statistics(
        &self,
        sigs: &[crate::userdb_parser::ParsedSignature],
    ) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total".into(), sigs.len());
        stats.insert("ep_only".into(), sigs.iter().filter(|s| s.ep_only).count());
        stats.insert("with_wildcard".into(), sigs.iter().filter(|s| s.pattern.iter().any(|b| b.is_none())).count());

        let mut by_cat: HashMap<String, usize> = HashMap::new();
        for sig in sigs {
            *by_cat.entry(format!("{:?}", sig.category)).or_insert(0) += 1;
        }
        stats.extend(by_cat);
        stats
    }

    /// Version check: parse version from the first comment line of a userdb.txt.
    /// Convention: first line is `; Version: X.Y.Z`.
    pub fn parse_version_from_header(text: &str) -> Option<DbVersion> {
        for line in text.lines().take(10) {
            let trimmed = line.trim_start_matches(';').trim();
            if let Some(rest) = trimmed.strip_prefix("Version:") {
                return DbVersion::parse(rest.trim()).ok();
            }
        }
        None
    }

    /// Check whether a remote database is newer than the current local version.
    pub fn is_newer(&self, remote_version: &DbVersion) -> bool {
        self.state.as_ref().map_or(true, |s| remote_version > &s.version)
    }

    /// Generate a diff summary between two signature lists.
    pub fn diff(
        base: &[crate::userdb_parser::ParsedSignature],
        updated: &[crate::userdb_parser::ParsedSignature],
    ) -> DiffSummary {
        let base_names: std::collections::HashSet<&str> = base.iter().map(|s| s.name.as_str()).collect();
        let updated_names: std::collections::HashSet<&str> = updated.iter().map(|s| s.name.as_str()).collect();

        let added: Vec<String> = updated_names.difference(&base_names)
            .map(|s| s.to_string()).collect();
        let removed: Vec<String> = base_names.difference(&updated_names)
            .map(|s| s.to_string()).collect();

        DiffSummary { added, removed, total_base: base.len(), total_updated: updated.len() }
    }
}

/// Result of a diff operation between two signature sets.
#[derive(Debug, Clone)]
pub struct DiffSummary {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub total_base: usize,
    pub total_updated: usize,
}

impl DiffSummary {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    pub fn net_change(&self) -> i64 {
        self.added.len() as i64 - self.removed.len() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_version_parse() {
        let v = DbVersion::parse("2.13.4").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 13);
        assert_eq!(v.patch, 4);
    }

    #[test]
    fn db_version_ord() {
        let v1 = DbVersion::new(1, 0, 0);
        let v2 = DbVersion::new(1, 0, 1);
        assert!(v2 > v1);
    }

    #[test]
    fn db_version_display() {
        let v = DbVersion::new(3, 14, 159);
        assert_eq!(v.to_string(), "3.14.159");
    }

    #[test]
    fn is_newer_no_state() {
        let updater = SignatureUpdater::default();
        let v = DbVersion::new(1, 0, 0);
        assert!(updater.is_newer(&v));
    }

    #[test]
    fn is_newer_with_older_state() {
        let state = LocalDatabaseState::new(".", DbVersion::new(1, 0, 0));
        let updater = SignatureUpdater::default().with_state(state);
        assert!(updater.is_newer(&DbVersion::new(1, 0, 1)));
        assert!(!updater.is_newer(&DbVersion::new(0, 9, 0)));
    }

    #[test]
    fn parse_version_from_header() {
        let text = "; Version: 2.5.1\n; Author: Test\n[SomeSig]\nsignature = 4D 5A\n";
        let v = SignatureUpdater::parse_version_from_header(text).unwrap();
        assert_eq!(v, DbVersion::new(2, 5, 1));
    }

    #[test]
    fn diff_detects_changes() {
        let base_text = "[SigA]\nsignature = 4D 5A\nep_only = false\nsection_start_only = false\n";
        let updated_text = "[SigA]\nsignature = 4D 5A\nep_only = false\nsection_start_only = false\n\
                            [SigB]\nsignature = 60 BE\nep_only = true\nsection_start_only = false\n";
        let base = crate::userdb_parser::parse_inline(base_text).unwrap();
        let updated = crate::userdb_parser::parse_inline(updated_text).unwrap();
        let diff = SignatureUpdater::diff(&base, &updated);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.net_change(), 1);
    }

    #[test]
    fn statistics_basic() {
        let text = "[UPX]\nsignature = 60 BE ??\nep_only = true\nsection_start_only = false\n\
                    [MSVC]\nsignature = 48 89 5C\nep_only = false\nsection_start_only = false\n";
        let sigs = crate::userdb_parser::parse_inline(text).unwrap();
        let updater = SignatureUpdater::default();
        let stats = updater.statistics(&sigs);
        assert_eq!(*stats.get("total").unwrap(), 2);
        assert_eq!(*stats.get("ep_only").unwrap(), 1);
        assert_eq!(*stats.get("with_wildcard").unwrap(), 1);
    }

    #[test]
    fn update_from_file_roundtrip() {
        let dir = std::env::temp_dir();
        let src = dir.join("peid_test_src.txt");
        let dst = dir.join("peid_test_dst.txt");

        let content = "; Version: 1.0.0\n[UPX 3.94]\nsignature = 60 BE ?? ?? ?? ??\nep_only = true\nsection_start_only = false\n";
        std::fs::write(&src, content).unwrap();

        let mut updater = SignatureUpdater::default();
        let result = updater.update_from_file(&src, &dst).unwrap();
        assert!(result.success);
        assert_eq!(result.added, 1);
        assert!(dst.exists());

        // Clean up.
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&dst);
    }
}
