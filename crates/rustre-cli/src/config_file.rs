//! `config_file` — Load and persist the `RustRE` CLI configuration file.
//!
//! Supports reading `~/.rustre/cli.toml` (or an arbitrary path) and writing
//! it back.  The format is a simple `key = value` text format (one pair per
//! line, `#` comments, blank lines ignored), compatible with the existing
//! [`crate::CliConfig`] in-memory representation.
//!
//! # Design
//!
//! * [`CliConfigReader::load`] reads and parses a TOML-like key=value file.
//! * [`CliConfigWriter::save`] serialises a [`FileConfig`] back to disk.
//! * [`FileConfig`] is the on-disk representation (wraps a `HashMap<ConfigKey,
//!   ConfigValue>`).
//! * [`ConfigKey`] is a typed enum of all known configuration keys.
//! * [`ConfigValue`] (re-exported from the parent crate) covers all value
//!   types.

use std::collections::HashMap;
use std::fmt;
use std::io::{BufRead, Write as IoWrite};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ConfigValue — mirrors crate::ConfigValue for standalone use
// ---------------------------------------------------------------------------

/// A typed configuration value that can appear in `~/.rustre/cli.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfigValue {
    /// A UTF-8 string.
    String(String),
    /// A 64-bit signed integer.
    Int(i64),
    /// An IEEE 754 64-bit float.
    Float(f64),
    /// A boolean.
    Bool(bool),
}

impl ConfigValue {
    /// Return the string representation, if this is a `String` variant.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return the integer value, if this is an `Int` variant.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Return the float value, if this is a `Float` variant.
    #[must_use]
    pub const fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Return the boolean value, if this is a `Bool` variant.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Render the value to a string suitable for `key = <value>` serialisation.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::String(s) => {
                // Quote if the string contains spaces or special characters.
                if s.contains(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
                    format!("\"{s}\"")
                } else {
                    s.clone()
                }
            }
            Self::Int(n) => n.to_string(),
            Self::Float(f) => format!("{f}"),
            Self::Bool(b) => b.to_string(),
        }
    }
}

impl fmt::Display for ConfigValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Parse a raw `value` string from the config file into a typed [`ConfigValue`].
///
/// Order of type inference:
/// 1. `true` / `false` → `Bool`
/// 2. Integer → `Int`
/// 3. Float → `Float`
/// 4. Strip surrounding quotes → `String`
pub(crate) fn parse_value(raw: &str) -> ConfigValue {
    if raw == "true" {
        return ConfigValue::Bool(true);
    }
    if raw == "false" {
        return ConfigValue::Bool(false);
    }
    if let Ok(n) = raw.parse::<i64>() {
        return ConfigValue::Int(n);
    }
    if let Ok(f) = raw.parse::<f64>() {
        return ConfigValue::Float(f);
    }
    let s = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(raw);
    ConfigValue::String(s.to_string())
}

// ---------------------------------------------------------------------------
// ConfigKey — typed enumeration of all known keys
// ---------------------------------------------------------------------------

/// All well-known configuration keys for `~/.rustre/cli.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigKey {
    /// Default output format (`table`, `json`, `csv`, `lines`, …).
    OutputFormat,
    /// Default verbosity level (integer, 0–3).
    Verbosity,
    /// Whether coloured output is enabled by default.
    ColorEnabled,
    /// Default binary analysis architecture override (e.g. `"x86_64"`).
    DefaultArch,
    /// Path to a default YARA rules file.
    YaraRulesPath,
    /// Maximum number of functions to diff before giving up.
    MaxDiffFunctions,
    /// Default script language (`"lua"`, `"rhai"`, …).
    ScriptLanguage,
    /// Whether to use the MCP server by default.
    McpEnabled,
    /// MCP server bind address.
    McpBind,
    /// Log file path (empty = stderr).
    LogFile,
    /// An arbitrary user-defined key.
    Custom(String),
}

impl ConfigKey {
    /// Canonical string representation used in the config file.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::OutputFormat => "output.format".to_string(),
            Self::Verbosity => "verbosity".to_string(),
            Self::ColorEnabled => "color.enabled".to_string(),
            Self::DefaultArch => "default.arch".to_string(),
            Self::YaraRulesPath => "yara.rules_path".to_string(),
            Self::MaxDiffFunctions => "diff.max_functions".to_string(),
            Self::ScriptLanguage => "script.language".to_string(),
            Self::McpEnabled => "mcp.enabled".to_string(),
            Self::McpBind => "mcp.bind".to_string(),
            Self::LogFile => "log.file".to_string(),
            Self::Custom(k) => k.clone(),
        }
    }

    /// Parse a string key into a [`ConfigKey`].
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "output.format" => Self::OutputFormat,
            "verbosity" => Self::Verbosity,
            "color.enabled" => Self::ColorEnabled,
            "default.arch" => Self::DefaultArch,
            "yara.rules_path" => Self::YaraRulesPath,
            "diff.max_functions" => Self::MaxDiffFunctions,
            "script.language" => Self::ScriptLanguage,
            "mcp.enabled" => Self::McpEnabled,
            "mcp.bind" => Self::McpBind,
            "log.file" => Self::LogFile,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FileConfig — the full on-disk configuration representation
// ---------------------------------------------------------------------------

/// The full configuration loaded from or to be written to disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileConfig {
    /// All key-value pairs.
    pub entries: HashMap<ConfigKey, ConfigValue>,
    /// Source path, if this config was loaded from a file.
    pub source_path: Option<PathBuf>,
}

impl FileConfig {
    /// Create an empty [`FileConfig`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a key to a value.
    pub fn set(&mut self, key: ConfigKey, value: ConfigValue) {
        self.entries.insert(key, value);
    }

    /// Retrieve the value for `key`.
    #[must_use]
    pub fn get(&self, key: &ConfigKey) -> Option<&ConfigValue> {
        self.entries.get(key)
    }

    /// Remove a key from the configuration.
    pub fn remove(&mut self, key: &ConfigKey) -> Option<ConfigValue> {
        self.entries.remove(key)
    }

    /// Return `true` if there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Merge `other` into `self`, overwriting existing keys.
    pub fn merge(&mut self, other: Self) {
        for (k, v) in other.entries {
            self.entries.insert(k, v);
        }
    }

    /// Return a sorted list of `(key_string, rendered_value)` pairs.
    #[must_use]
    pub fn sorted_pairs(&self) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = self
            .entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.render()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    }
}

impl fmt::Display for FileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, v) in self.sorted_pairs() {
            writeln!(f, "{k} = {v}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CliConfigReader
// ---------------------------------------------------------------------------

/// Reads a `~/.rustre/cli.toml`-style key=value file and parses it into a
/// [`FileConfig`].
///
/// # File format
///
/// ```text
/// # RustRE CLI configuration
/// output.format = json
/// verbosity = 2
/// color.enabled = true
/// default.arch = "x86_64"
/// ```
pub struct CliConfigReader {
    /// Path from which to load.
    path: PathBuf,
}

impl CliConfigReader {
    /// Create a reader for `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Create a reader targeting the default location `~/.rustre/cli.toml`.
    ///
    /// On non-Unix platforms where there is no `HOME` environment variable,
    /// falls back to `.rustre/cli.toml` in the current directory.
    #[must_use]
    pub fn default_path() -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        let base = if home.is_empty() {
            PathBuf::from(".rustre")
        } else {
            PathBuf::from(home).join(".rustre")
        };
        Self::new(base.join("cli.toml"))
    }

    /// Load and parse the configuration file.
    ///
    /// Returns a default empty [`FileConfig`] if the file does not exist, so
    /// that missing config is not an error.
    ///
    /// # Errors
    ///
    /// Returns a `String` error message if the file exists but cannot be read
    /// or contains a malformed line.
    pub fn load(&self) -> Result<FileConfig, String> {
        // Open directly rather than checking exists() first to avoid a TOCTOU
        // race between the existence check and the actual open.
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut cfg = FileConfig::new();
                cfg.source_path = Some(self.path.clone());
                return Ok(cfg);
            }
            Err(e) => return Err(format!("cannot open {}: {e}", self.path.display())),
        };
        let reader = std::io::BufReader::new(file);

        let mut cfg = FileConfig::new();
        cfg.source_path = Some(self.path.clone());

        for (lineno, line) in reader.lines().enumerate() {
            let line = line
                .map_err(|e| format!("{}:{}: read error: {e}", self.path.display(), lineno + 1))?;
            let line = line.trim().to_string();

            // Skip comments and blank lines.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (raw_key, raw_value) = line.split_once('=').ok_or_else(|| {
                format!(
                    "{}:{}: expected 'key = value'",
                    self.path.display(),
                    lineno + 1
                )
            })?;

            let key = ConfigKey::from_str(raw_key.trim());
            let value = parse_value(raw_value.trim());
            cfg.set(key, value);
        }

        Ok(cfg)
    }

    /// Path this reader will load from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// CliConfigWriter
// ---------------------------------------------------------------------------

/// Writes a [`FileConfig`] to disk.
///
/// Creates parent directories if they do not exist.
pub struct CliConfigWriter {
    path: PathBuf,
}

impl CliConfigWriter {
    /// Create a writer for `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Create a writer targeting the default location `~/.rustre/cli.toml`.
    #[must_use]
    pub fn default_path() -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        let base = if home.is_empty() {
            PathBuf::from(".rustre")
        } else {
            PathBuf::from(home).join(".rustre")
        };
        Self::new(base.join("cli.toml"))
    }

    /// Serialise `config` and write it to the configured path.
    ///
    /// # Errors
    ///
    /// Returns a `String` error message if the parent directory cannot be
    /// created or the file cannot be written.
    pub fn save(&self, config: &FileConfig) -> Result<(), String> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }

        let mut file = std::fs::File::create(&self.path)
            .map_err(|e| format!("cannot create {}: {e}", self.path.display()))?;

        writeln!(file, "# RustRE CLI configuration — auto-generated").map_err(|e| e.to_string())?;
        writeln!(
            file,
            "# Edit manually or via `rustre config set <key> <value>`"
        )
        .map_err(|e| e.to_string())?;
        writeln!(file).map_err(|e| e.to_string())?;

        for (key, value) in config.sorted_pairs() {
            writeln!(file, "{key} = {value}").map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    /// Serialise `config` to an in-memory string (useful for testing).
    #[must_use]
    pub fn to_string(config: &FileConfig) -> String {
        let mut out = String::from("# RustRE CLI configuration\n\n");
        for (key, value) in config.sorted_pairs() {
            out.push_str(&format!("{key} = {value}\n"));
        }
        out
    }

    /// Path this writer will write to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── ConfigValue ──────────────────────────────────────────────────────────

    #[test]
    fn test_parse_value_bool_true() {
        assert_eq!(parse_value("true"), ConfigValue::Bool(true));
    }

    #[test]
    fn test_parse_value_bool_false() {
        assert_eq!(parse_value("false"), ConfigValue::Bool(false));
    }

    #[test]
    fn test_parse_value_int() {
        assert_eq!(parse_value("42"), ConfigValue::Int(42));
        assert_eq!(parse_value("-7"), ConfigValue::Int(-7));
    }

    #[test]
    fn test_parse_value_float() {
        if let ConfigValue::Float(f) = parse_value("3.14") {
            assert!((f - 3.14_f64).abs() < 1e-9);
        } else {
            panic!("expected Float");
        }
    }

    #[test]
    fn test_parse_value_string_unquoted() {
        assert_eq!(
            parse_value("hello"),
            ConfigValue::String("hello".to_string())
        );
    }

    #[test]
    fn test_parse_value_string_double_quoted() {
        assert_eq!(
            parse_value("\"x86_64\""),
            ConfigValue::String("x86_64".to_string())
        );
    }

    #[test]
    fn test_parse_value_string_single_quoted() {
        assert_eq!(
            parse_value("'arm64'"),
            ConfigValue::String("arm64".to_string())
        );
    }

    #[test]
    fn test_config_value_render_round_trip() {
        let cases = vec![
            ConfigValue::Bool(true),
            ConfigValue::Int(99),
            ConfigValue::String("test".to_string()),
        ];
        for cv in cases {
            let rendered = cv.render();
            let parsed = parse_value(&rendered);
            assert_eq!(parsed, cv, "round-trip failed for {cv}");
        }
    }

    // ── ConfigKey ────────────────────────────────────────────────────────────

    #[test]
    fn test_config_key_round_trip() {
        let keys = vec![
            ConfigKey::OutputFormat,
            ConfigKey::Verbosity,
            ConfigKey::ColorEnabled,
            ConfigKey::DefaultArch,
            ConfigKey::YaraRulesPath,
            ConfigKey::MaxDiffFunctions,
            ConfigKey::ScriptLanguage,
            ConfigKey::McpEnabled,
            ConfigKey::McpBind,
            ConfigKey::LogFile,
        ];
        for key in keys {
            let s = key.as_str();
            let back = ConfigKey::from_str(&s);
            assert_eq!(back, key, "round-trip failed for {key}");
        }
    }

    #[test]
    fn test_config_key_custom() {
        let k = ConfigKey::from_str("my.custom.key");
        assert_eq!(k, ConfigKey::Custom("my.custom.key".to_string()));
    }

    // ── FileConfig ───────────────────────────────────────────────────────────

    #[test]
    fn test_file_config_set_get() {
        let mut cfg = FileConfig::new();
        cfg.set(ConfigKey::Verbosity, ConfigValue::Int(2));
        assert_eq!(cfg.get(&ConfigKey::Verbosity), Some(&ConfigValue::Int(2)));
        assert_eq!(cfg.len(), 1);
        assert!(!cfg.is_empty());
    }

    #[test]
    fn test_file_config_remove() {
        let mut cfg = FileConfig::new();
        cfg.set(ConfigKey::ColorEnabled, ConfigValue::Bool(true));
        let removed = cfg.remove(&ConfigKey::ColorEnabled);
        assert!(removed.is_some());
        assert!(cfg.is_empty());
    }

    #[test]
    fn test_file_config_merge_overwrites() {
        let mut base = FileConfig::new();
        base.set(ConfigKey::Verbosity, ConfigValue::Int(1));
        base.set(ConfigKey::ColorEnabled, ConfigValue::Bool(false));

        let mut overlay = FileConfig::new();
        overlay.set(ConfigKey::Verbosity, ConfigValue::Int(3));

        base.merge(overlay);
        assert_eq!(base.get(&ConfigKey::Verbosity), Some(&ConfigValue::Int(3)));
        assert_eq!(
            base.get(&ConfigKey::ColorEnabled),
            Some(&ConfigValue::Bool(false))
        );
    }

    #[test]
    fn test_file_config_sorted_pairs() {
        let mut cfg = FileConfig::new();
        cfg.set(ConfigKey::Verbosity, ConfigValue::Int(1));
        cfg.set(
            ConfigKey::OutputFormat,
            ConfigValue::String("json".to_string()),
        );
        let pairs = cfg.sorted_pairs();
        // Pairs should be sorted by key string.
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
    }

    // ── CliConfigReader ──────────────────────────────────────────────────────

    #[test]
    fn test_reader_missing_file_returns_empty() {
        let reader = CliConfigReader::new("/nonexistent/__rustre_test_cfg.toml");
        let cfg = reader.load().unwrap();
        assert!(cfg.is_empty());
    }

    #[test]
    fn test_reader_parses_key_value_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_cli_config_test.toml");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "# comment").unwrap();
            writeln!(f, "verbosity = 3").unwrap();
            writeln!(f, "color.enabled = false").unwrap();
            writeln!(f, "output.format = csv").unwrap();
        }
        let reader = CliConfigReader::new(&path);
        let cfg = reader.load().unwrap();
        assert_eq!(cfg.get(&ConfigKey::Verbosity), Some(&ConfigValue::Int(3)));
        assert_eq!(
            cfg.get(&ConfigKey::ColorEnabled),
            Some(&ConfigValue::Bool(false))
        );
        assert_eq!(
            cfg.get(&ConfigKey::OutputFormat),
            Some(&ConfigValue::String("csv".to_string()))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_reader_skips_blank_and_comment_lines() {
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_cli_config_blank_test.toml");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f).unwrap();
            writeln!(f, "# comment line").unwrap();
            writeln!(f).unwrap();
            writeln!(f, "verbosity = 1").unwrap();
        }
        let reader = CliConfigReader::new(&path);
        let cfg = reader.load().unwrap();
        assert_eq!(cfg.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    // ── CliConfigWriter ──────────────────────────────────────────────────────

    #[test]
    fn test_writer_to_string() {
        let mut cfg = FileConfig::new();
        cfg.set(ConfigKey::Verbosity, ConfigValue::Int(2));
        let s = CliConfigWriter::to_string(&cfg);
        assert!(s.contains("verbosity = 2"), "output: {s}");
    }

    #[test]
    fn test_writer_save_and_reload() {
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_cli_config_save_test.toml");
        let mut cfg = FileConfig::new();
        cfg.set(
            ConfigKey::DefaultArch,
            ConfigValue::String("arm64".to_string()),
        );
        cfg.set(ConfigKey::McpEnabled, ConfigValue::Bool(true));

        let writer = CliConfigWriter::new(&path);
        writer.save(&cfg).unwrap();

        let reader = CliConfigReader::new(&path);
        let loaded = reader.load().unwrap();
        assert_eq!(
            loaded.get(&ConfigKey::DefaultArch),
            Some(&ConfigValue::String("arm64".to_string()))
        );
        assert_eq!(
            loaded.get(&ConfigKey::McpEnabled),
            Some(&ConfigValue::Bool(true))
        );
        let _ = std::fs::remove_file(&path);
    }
}
