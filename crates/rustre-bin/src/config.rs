//! Configuration file parsing and management for the `rustre` CLI.
//!
//! Supports TOML-style flat key/value files, environment variable overrides,
//! and a layered config system (global → user → project → CLI flags).

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
// ConfigValue
// ─────────────────────────────────────────────────────────────────────────────

/// A single configuration value.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    List(Vec<Self>),
}

impl ConfigValue {
    #[must_use] 
    pub fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    #[must_use] 
    pub const fn as_int(&self) -> Option<i64> {
        if let Self::Int(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    #[must_use] 
    pub const fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    #[must_use] 
    pub const fn as_float(&self) -> Option<f64> {
        if let Self::Float(f) = self {
            Some(*f)
        } else {
            None
        }
    }
}

impl fmt::Display for ConfigValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Str(s) => write!(f, "{s}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::List(v) => {
                let items: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
                write!(f, "[{}]", items.join(", "))
            }
        }
    }
}

impl From<&str> for ConfigValue {
    fn from(s: &str) -> Self {
        Self::Str(s.to_string())
    }
}
impl From<String> for ConfigValue {
    fn from(s: String) -> Self {
        Self::Str(s)
    }
}
impl From<i64> for ConfigValue {
    fn from(n: i64) -> Self {
        Self::Int(n)
    }
}
impl From<bool> for ConfigValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}
impl From<f64> for ConfigValue {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigLayer
// ─────────────────────────────────────────────────────────────────────────────

/// One layer in the configuration stack.
#[derive(Debug, Clone)]
pub struct ConfigLayer {
    pub name: String,
    pub values: HashMap<String, ConfigValue>,
}

impl ConfigLayer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            values: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, val: impl Into<ConfigValue>) {
        self.values.insert(key.into(), val.into());
    }

    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&ConfigValue> {
        self.values.get(key)
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.values.len()
    }
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Parse a minimal `key = value` flat config format.
    pub fn parse_flat(name: impl Into<String>, text: &str) -> Self {
        let mut layer = Self::new(name);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(eq) = line.find('=') {
                let key = line[..eq].trim();
                let val = line[eq + 1..].trim();
                let cv = parse_value(val);
                layer.set(key, cv);
            }
        }
        layer
    }
}

fn parse_value(s: &str) -> ConfigValue {
    if s == "true" {
        return ConfigValue::Bool(true);
    }
    if s == "false" {
        return ConfigValue::Bool(false);
    }
    if let Ok(n) = s.parse::<i64>() {
        return ConfigValue::Int(n);
    }
    if let Ok(f) = s.parse::<f64>() {
        return ConfigValue::Float(f);
    }
    // Strip surrounding quotes
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        return ConfigValue::Str(s[1..s.len() - 1].to_string());
    }
    ConfigValue::Str(s.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

/// Layered configuration: global < user < project < CLI.
#[derive(Debug, Default)]
pub struct Config {
    layers: Vec<ConfigLayer>,
}

impl Config {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a layer (higher index = higher priority).
    pub fn push_layer(&mut self, layer: ConfigLayer) {
        self.layers.push(layer);
    }

    /// Look up a key, searching layers from highest to lowest priority.
    #[must_use] 
    pub fn get(&self, key: &str) -> Option<&ConfigValue> {
        for layer in self.layers.iter().rev() {
            if let Some(v) = layer.get(key) {
                return Some(v);
            }
        }
        None
    }

    /// Get as string with a default.
    #[must_use] 
    pub fn get_str<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).and_then(|v| v.as_str()).unwrap_or(default)
    }

    /// Get as integer with a default.
    #[must_use] 
    pub fn get_int(&self, key: &str, default: i64) -> i64 {
        self.get(key).and_then(ConfigValue::as_int).unwrap_or(default)
    }

    /// Get as boolean with a default.
    #[must_use] 
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        self.get(key).and_then(ConfigValue::as_bool).unwrap_or(default)
    }

    /// Load from a file path if it exists.
    pub fn load_file(&mut self, path: &Path, layer_name: &str) -> std::io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(path)?;
        let layer = ConfigLayer::parse_flat(layer_name, &text);
        self.push_layer(layer);
        Ok(())
    }

    /// Inject from environment variables with a given prefix.
    pub fn load_env(&mut self, prefix: &str) {
        let mut layer = ConfigLayer::new("env");
        for (k, v) in std::env::vars() {
            if let Some(__stripped) = k.strip_prefix(prefix) {
                let key = __stripped.to_lowercase().replace('_', ".");
                layer.set(key, v);
            }
        }
        if !layer.is_empty() {
            self.push_layer(layer);
        }
    }

    /// Number of layers.
    #[must_use] 
    pub const fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// All keys visible across all layers.
    #[must_use] 
    pub fn all_keys(&self) -> Vec<String> {
        let mut keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        for layer in &self.layers {
            keys.extend(layer.values.keys().cloned());
        }
        let mut v: Vec<String> = keys.into_iter().collect();
        v.sort();
        v
    }

    /// Merge all layers into a flat map (highest-priority wins).
    #[must_use] 
    pub fn flatten(&self) -> HashMap<String, ConfigValue> {
        let mut flat = HashMap::new();
        for layer in &self.layers {
            for (k, v) in &layer.values {
                flat.insert(k.clone(), v.clone());
            }
        }
        flat
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Default config values
// ─────────────────────────────────────────────────────────────────────────────

/// Build the default configuration layer.
#[must_use] 
pub fn default_config_layer() -> ConfigLayer {
    let mut layer = ConfigLayer::new("default");
    layer.set("output.format", "text");
    layer.set("output.color", true);
    layer.set("output.verbose", false);
    layer.set("analysis.arch", "auto");
    layer.set("analysis.base_addr", 0i64);
    layer.set("analysis.max_functions", 100000i64);
    layer.set("server.host", "127.0.0.1");
    layer.set("server.port", 8964i64);
    layer.set("server.timeout_ms", 30000i64);
    layer.set("disasm.syntax", "intel");
    layer.set("disasm.show_bytes", true);
    layer.set("disasm.max_instrs", 1000i64);
    layer.set("decompile.indent", 4i64);
    layer.set("decompile.brace_style", "same_line");
    layer.set("strings.min_len", 4i64);
    layer.set("strings.wide", false);
    layer
}

/// Standard config file paths (in order of increasing priority).
#[must_use] 
pub fn default_config_paths() -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    // Global
    if cfg!(windows) {
        if let Ok(appdata) = std::env::var("APPDATA") {
            paths.push((
                PathBuf::from(appdata).join("RustRE").join("config.ini"),
                "global".to_string(),
            ));
        }
    } else {
        paths.push((
            PathBuf::from("/etc/rustre/config.ini"),
            "global".to_string(),
        ));
    }
    // User
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok();
    if let Some(h) = home {
        paths.push((
            PathBuf::from(h).join(".rustre").join("config.ini"),
            "user".to_string(),
        ));
    }
    // Project (current directory)
    if let Ok(cwd) = std::env::current_dir() {
        paths.push((cwd.join(".rustre.ini"), "project".to_string()));
    }
    paths
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- ConfigValue ---

    #[test]
    fn config_value_as_str() {
        let v = ConfigValue::Str("hello".into());
        assert_eq!(v.as_str(), Some("hello"));
    }

    #[test]
    fn write_trait_imported_for_tests() {
        // Exercise the `std::io::Write` import so it stays live for any
        // future buffer-backed test that needs writeln!/write_all.
        let mut buf: Vec<u8> = Vec::new();
        Write::write_all(&mut buf, b"abc").unwrap();
        assert_eq!(buf, b"abc");
    }

    #[test]
    fn config_value_as_int() {
        let v = ConfigValue::Int(42);
        assert_eq!(v.as_int(), Some(42));
    }

    #[test]
    fn config_value_as_bool() {
        let v = ConfigValue::Bool(true);
        assert_eq!(v.as_bool(), Some(true));
    }

    #[test]
    fn config_value_from_str() {
        let v: ConfigValue = "test".into();
        assert_eq!(v.as_str(), Some("test"));
    }

    #[test]
    fn config_value_display_bool() {
        assert_eq!(format!("{}", ConfigValue::Bool(false)), "false");
    }

    #[test]
    fn config_value_display_list() {
        let v = ConfigValue::List(vec![ConfigValue::Int(1), ConfigValue::Int(2)]);
        let s = format!("{v}");
        assert!(s.contains('1') && s.contains('2'));
    }

    // --- parse_value ---

    #[test]
    fn parse_value_bool_true() {
        assert_eq!(parse_value("true"), ConfigValue::Bool(true));
    }

    #[test]
    fn parse_value_bool_false() {
        assert_eq!(parse_value("false"), ConfigValue::Bool(false));
    }

    #[test]
    fn parse_value_int() {
        assert_eq!(parse_value("42"), ConfigValue::Int(42));
    }

    #[test]
    fn parse_value_negative_int() {
        assert_eq!(parse_value("-5"), ConfigValue::Int(-5));
    }

    #[test]
    fn parse_value_float() {
        assert_eq!(parse_value("3.14"), ConfigValue::Float(3.14_f64));
    }

    #[test]
    fn parse_value_quoted_string() {
        assert_eq!(parse_value("\"hello\""), ConfigValue::Str("hello".into()));
    }

    #[test]
    fn parse_value_single_quoted() {
        assert_eq!(parse_value("'world'"), ConfigValue::Str("world".into()));
    }

    #[test]
    fn parse_value_bare_string() {
        let v = parse_value("intel");
        assert_eq!(v, ConfigValue::Str("intel".into()));
    }

    // --- ConfigLayer ---

    #[test]
    fn layer_set_get() {
        let mut l = ConfigLayer::new("test");
        l.set("key", "value");
        assert_eq!(l.get("key").unwrap().as_str(), Some("value"));
    }

    #[test]
    fn layer_is_empty() {
        let l = ConfigLayer::new("test");
        assert!(l.is_empty());
    }

    #[test]
    fn layer_parse_flat() {
        let text = "# comment\nfoo = bar\nbaz = 42\nflag = true\n";
        let layer = ConfigLayer::parse_flat("test", text);
        assert_eq!(layer.get("foo").unwrap().as_str(), Some("bar"));
        assert_eq!(layer.get("baz").unwrap().as_int(), Some(42));
        assert_eq!(layer.get("flag").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn layer_parse_flat_skip_comments() {
        let text = "# this is a comment\n";
        let layer = ConfigLayer::parse_flat("test", text);
        assert!(layer.is_empty());
    }

    // --- Config ---

    #[test]
    fn config_layer_priority() {
        let mut c = Config::new();
        let mut l1 = ConfigLayer::new("low");
        l1.set("x", "low_val");
        let mut l2 = ConfigLayer::new("high");
        l2.set("x", "high_val");
        c.push_layer(l1);
        c.push_layer(l2);
        assert_eq!(c.get_str("x", ""), "high_val");
    }

    #[test]
    fn config_default_fallback() {
        let c = Config::new();
        assert_eq!(c.get_str("missing", "default"), "default");
    }

    #[test]
    fn config_get_int() {
        let mut c = Config::new();
        let mut l = ConfigLayer::new("t");
        l.set("port", 8080i64);
        c.push_layer(l);
        assert_eq!(c.get_int("port", 0), 8080);
    }

    #[test]
    fn config_get_bool() {
        let mut c = Config::new();
        let mut l = ConfigLayer::new("t");
        l.set("verbose", true);
        c.push_layer(l);
        assert!(c.get_bool("verbose", false));
    }

    #[test]
    fn config_layer_count() {
        let mut c = Config::new();
        c.push_layer(ConfigLayer::new("a"));
        c.push_layer(ConfigLayer::new("b"));
        assert_eq!(c.layer_count(), 2);
    }

    #[test]
    fn config_all_keys() {
        let mut c = Config::new();
        let mut l = ConfigLayer::new("t");
        l.set("a", 1i64);
        l.set("b", 2i64);
        c.push_layer(l);
        let keys = c.all_keys();
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));
    }

    #[test]
    fn config_flatten() {
        let mut c = Config::new();
        let mut l = ConfigLayer::new("t");
        l.set("k", "v");
        c.push_layer(l);
        let flat = c.flatten();
        assert!(flat.contains_key("k"));
    }

    #[test]
    fn config_load_file_missing() {
        let mut c = Config::new();
        let result = c.load_file(Path::new("/no/such/file.ini"), "test");
        assert!(result.is_ok()); // Missing files are silently ignored
    }

    #[test]
    fn config_load_file_existing() {
        let path = std::env::temp_dir().join("rustre_test_config.ini");
        std::fs::write(&path, "test.key = test_value\n").unwrap();
        let mut c = Config::new();
        c.load_file(&path, "test").unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(c.get_str("test.key", ""), "test_value");
    }

    // --- default_config_layer ---

    #[test]
    fn default_config_has_server_port() {
        let layer = default_config_layer();
        assert_eq!(layer.get("server.port").unwrap().as_int(), Some(8964));
    }

    #[test]
    fn default_config_has_disasm_syntax() {
        let layer = default_config_layer();
        assert_eq!(layer.get("disasm.syntax").unwrap().as_str(), Some("intel"));
    }

    #[test]
    fn default_config_paths_not_empty() {
        let paths = default_config_paths();
        assert!(!paths.is_empty());
    }
}
