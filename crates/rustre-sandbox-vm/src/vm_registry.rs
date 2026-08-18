//! Virtual Windows registry for sandbox VM environments.
//!
//! Provides an in-memory registry that intercepts guest registry operations,
//! records accesses, enforces policies, and supports snapshot/diff for
//! malware analysis workflows.

use std::collections::HashMap;
use std::fmt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::{bail, Result};

// ---------------------------------------------------------------------------
// Registry value types
// ---------------------------------------------------------------------------

/// Windows registry value data types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegValueKind {
    /// `REG_NONE` — No value type.
    None,
    /// `REG_SZ` — Null-terminated Unicode string.
    Sz,
    /// `REG_EXPAND_SZ` — String with unexpanded environment variables.
    ExpandSz,
    /// `REG_BINARY` — Binary data.
    Binary,
    /// `REG_DWORD` — 32-bit number.
    DWord,
    /// `REG_DWORD_BIG_ENDIAN` — 32-bit number in big-endian format.
    DWordBigEndian,
    /// `REG_LINK` — Symbolic link.
    Link,
    /// `REG_MULTI_SZ` — Array of null-terminated strings.
    MultiSz,
    /// `REG_QWORD` — 64-bit number.
    QWord,
}

impl fmt::Display for RegValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None           => "REG_NONE",
            Self::Sz             => "REG_SZ",
            Self::ExpandSz       => "REG_EXPAND_SZ",
            Self::Binary         => "REG_BINARY",
            Self::DWord          => "REG_DWORD",
            Self::DWordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::Link           => "REG_LINK",
            Self::MultiSz        => "REG_MULTI_SZ",
            Self::QWord          => "REG_QWORD",
        };
        f.write_str(s)
    }
}

/// The data stored in a registry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegData {
    None,
    String(String),
    ExpandString(String),
    Binary(Vec<u8>),
    DWord(u32),
    DWordBigEndian(u32),
    Link(String),
    MultiString(Vec<String>),
    QWord(u64),
}

impl RegData {
    /// Return the corresponding [`RegValueKind`] for this data.
    #[must_use]
    pub const fn kind(&self) -> RegValueKind {
        match self {
            Self::None              => RegValueKind::None,
            Self::String(_)         => RegValueKind::Sz,
            Self::ExpandString(_)   => RegValueKind::ExpandSz,
            Self::Binary(_)         => RegValueKind::Binary,
            Self::DWord(_)          => RegValueKind::DWord,
            Self::DWordBigEndian(_) => RegValueKind::DWordBigEndian,
            Self::Link(_)           => RegValueKind::Link,
            Self::MultiString(_)    => RegValueKind::MultiSz,
            Self::QWord(_)          => RegValueKind::QWord,
        }
    }

    /// Return the string content if this is `REG_SZ`, `REG_EXPAND_SZ`, or `REG_LINK`.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) | Self::ExpandString(s) | Self::Link(s) => Some(s),
            _ => None,
        }
    }

    /// Return the u32 content if this is `REG_DWORD`.
    #[must_use]
    pub const fn as_dword(&self) -> Option<u32> {
        match self { Self::DWord(v) | Self::DWordBigEndian(v) => Some(*v), _ => None }
    }

    /// Return the u64 content if this is `REG_QWORD`.
    #[must_use]
    pub const fn as_qword(&self) -> Option<u64> {
        match self { Self::QWord(v) => Some(*v), _ => None }
    }

    /// Return the binary content if this is `REG_BINARY`.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self { Self::Binary(b) => Some(b), _ => None }
    }

    /// Serialized byte size (approximate).
    #[must_use]
    pub fn byte_size(&self) -> usize {
        match self {
            Self::None              => 0,
            Self::String(s)
            | Self::ExpandString(s)
            | Self::Link(s)         => (s.len() + 1) * 2,
            Self::Binary(b)         => b.len(),
            Self::DWord(_)
            | Self::DWordBigEndian(_) => 4,
            Self::MultiString(v)    => v.iter().map(|s| (s.len() + 1) * 2).sum::<usize>() + 2,
            Self::QWord(_)          => 8,
        }
    }
}

// ---------------------------------------------------------------------------
// VirtualValue
// ---------------------------------------------------------------------------

/// A single named value under a registry key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualValue {
    /// Value name ("" = default value).
    pub name: String,
    /// Value data.
    pub data: RegData,
    /// UNIX timestamp of last modification.
    pub last_write: u64,
}

impl VirtualValue {
    #[must_use]
    pub fn new(name: impl Into<String>, data: RegData) -> Self {
        Self {
            name: name.into(),
            data,
            last_write: current_timestamp(),
        }
    }

    /// Helper: create a `REG_SZ` value.
    #[must_use]
    pub fn sz(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, RegData::String(value.into()))
    }

    /// Helper: create a `REG_DWORD` value.
    #[must_use]
    pub fn dword(name: impl Into<String>, value: u32) -> Self {
        Self::new(name, RegData::DWord(value))
    }

    /// Helper: create a `REG_QWORD` value.
    #[must_use]
    pub fn qword(name: impl Into<String>, value: u64) -> Self {
        Self::new(name, RegData::QWord(value))
    }

    /// Helper: create a `REG_BINARY` value.
    #[must_use]
    pub fn binary(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self::new(name, RegData::Binary(bytes))
    }
}

// ---------------------------------------------------------------------------
// VirtualKey
// ---------------------------------------------------------------------------

/// A registry key node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualKey {
    /// Full path of this key (e.g., `HKLM\SOFTWARE\Microsoft`).
    pub path: String,
    /// Named values stored under this key.
    pub values: HashMap<String, VirtualValue>,
    /// Names of child sub-keys (not the full key objects).
    pub subkeys: Vec<String>,
    /// UNIX timestamp of key creation.
    pub created_at: u64,
    /// UNIX timestamp of last write.
    pub last_write: u64,
    /// Whether this key is volatile (not persisted across reboots).
    pub volatile: bool,
    /// Tags for analysis labeling.
    pub tags: Vec<String>,
}

impl VirtualKey {
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        let now = current_timestamp();
        Self {
            path: path.into(),
            values: HashMap::new(),
            subkeys: Vec::new(),
            created_at: now,
            last_write: now,
            volatile: false,
            tags: Vec::new(),
        }
    }

    /// Set or overwrite a value.
    pub fn set_value(&mut self, value: VirtualValue) {
        self.last_write = current_timestamp();
        self.values.insert(value.name.clone(), value);
    }

    /// Get a value by name.
    #[must_use]
    pub fn get_value(&self, name: &str) -> Option<&VirtualValue> {
        self.values.get(name)
    }

    /// Delete a value by name; returns `true` if it existed.
    pub fn delete_value(&mut self, name: &str) -> bool {
        self.values.remove(name).is_some()
    }

    /// Add a subkey name to this key's listing.
    pub fn add_subkey(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.subkeys.contains(&name) {
            self.subkeys.push(name);
        }
    }

    /// Remove a subkey name.
    pub fn remove_subkey(&mut self, name: &str) -> bool {
        if let Some(pos) = self.subkeys.iter().position(|s| s == name) {
            self.subkeys.remove(pos);
            true
        } else {
            false
        }
    }

    /// Return all value names.
    #[must_use]
    pub fn value_names(&self) -> Vec<&str> {
        self.values.keys().map(std::string::String::as_str).collect()
    }
}

// ---------------------------------------------------------------------------
// Registry operations log
// ---------------------------------------------------------------------------

/// Types of registry operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegOp {
    OpenKey,
    CreateKey,
    DeleteKey,
    QueryValue,
    SetValue,
    DeleteValue,
    EnumSubkeys,
    EnumValues,
}

/// The result of a registry operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegOpResult {
    Success,
    Denied,
    NotFound,
    AlreadyExists,
    Error,
}

/// A logged registry access record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegAccessRecord {
    pub timestamp: u64,
    pub pid: Option<u32>,
    pub op: RegOp,
    pub key_path: String,
    pub value_name: Option<String>,
    pub result: RegOpResult,
}

// ---------------------------------------------------------------------------
// RegistryInterceptor
// ---------------------------------------------------------------------------

/// Intercept action for registry operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegInterceptAction {
    Allow,
    Deny,
    Redirect,
    Shadow,
}

/// A rule that intercepts registry operations on keys matching a path prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegInterceptRule {
    /// Key path prefix to match (case-insensitive).
    pub prefix: String,
    /// Operations to intercept (empty = all).
    pub ops: Vec<RegOp>,
    /// Action to take.
    pub action: RegInterceptAction,
    /// Redirect target key path.
    pub redirect_to: Option<String>,
    /// Rule priority (higher wins).
    pub priority: i32,
}

impl RegInterceptRule {
    #[must_use]
    pub fn new(prefix: impl Into<String>, action: RegInterceptAction) -> Self {
        Self {
            prefix: prefix.into().to_lowercase(),
            ops: Vec::new(),
            action,
            redirect_to: None,
            priority: 0,
        }
    }

    fn matches(&self, key_path: &str, op: RegOp) -> bool {
        let lower = key_path.to_lowercase();
        lower.starts_with(&self.prefix)
            && (self.ops.is_empty() || self.ops.contains(&op))
    }
}

/// Evaluates intercept rules and records registry accesses.
pub struct RegistryInterceptor {
    rules: Vec<RegInterceptRule>,
    log:   Vec<RegAccessRecord>,
}

impl RegistryInterceptor {
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new(), log: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: RegInterceptRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    #[must_use]
    pub fn evaluate(&self, key_path: &str, op: RegOp) -> (RegInterceptAction, Option<String>) {
        for rule in &self.rules {
            if rule.matches(key_path, op) {
                return (rule.action, rule.redirect_to.clone());
            }
        }
        (RegInterceptAction::Allow, None)
    }

    pub fn record(&mut self, pid: Option<u32>, op: RegOp, key_path: String,
                  value_name: Option<String>, result: RegOpResult) {
        self.log.push(RegAccessRecord {
            timestamp: current_timestamp(),
            pid,
            op,
            key_path,
            value_name,
            result,
        });
    }

    #[must_use]
    pub fn all_records(&self) -> &[RegAccessRecord] { &self.log }

    #[must_use]
    pub fn write_records(&self) -> Vec<&RegAccessRecord> {
        self.log.iter().filter(|r| matches!(r.op, RegOp::SetValue | RegOp::CreateKey)).collect()
    }
}

impl Default for RegistryInterceptor {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// VmRegistry
// ---------------------------------------------------------------------------

/// A thread-safe virtual Windows registry for sandbox environments.
///
/// Supports standard key/value CRUD, interception rules, and access logging.
pub struct VmRegistry {
    keys: RwLock<HashMap<String, VirtualKey>>,
    interceptor: RwLock<RegistryInterceptor>,
}

impl VmRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self {
            keys:        RwLock::new(HashMap::new()),
            interceptor: RwLock::new(RegistryInterceptor::new()),
        };
        // Pre-populate root hives via the &mut self helper so the
        // construction path is symmetric with later mutations.
        for hive in &["HKLM", "HKCU", "HKCR", "HKU", "HKCC"] {
            reg.register_hive(hive);
        }
        reg
    }

    /// Register a top-level hive (e.g. `HKLM`). `&mut self` so the
    /// registry can be initialized before being shared.
    pub fn register_hive(&mut self, name: &str) {
        self.keys
            .write()
            .insert(name.to_string(), VirtualKey::new(name));
    }

    // -----------------------------------------------------------------------
    // Intercept rules
    // -----------------------------------------------------------------------

    pub fn add_rule(&self, rule: RegInterceptRule) {
        self.interceptor.write().add_rule(rule);
    }

    // -----------------------------------------------------------------------
    // Key operations
    // -----------------------------------------------------------------------

    fn normalize_path(path: &str) -> String {
        // Normalize backslash/forward slash and uppercase hive.
        path.replace('/', "\\")
    }

    /// Create a key (and all intermediate keys).
    pub fn create_key(&self, path: &str) -> Result<()> {
        let path = Self::normalize_path(path);
        let (action, redirect) = self.interceptor.read().evaluate(&path, RegOp::CreateKey);
        let effective = match action {
            RegInterceptAction::Deny => {
                self.interceptor.write().record(None, RegOp::CreateKey, path.clone(), None, RegOpResult::Denied);
                bail!("create_key denied: {path}");
            }
            RegInterceptAction::Redirect => redirect.unwrap_or_else(|| path.clone()),
            _ => path.clone(),
        };

        let mut keys = self.keys.write();
        // Create key and all ancestors.
        let parts: Vec<&str> = effective.split('\\').collect();
        let mut current = String::new();
        for (i, part) in parts.iter().enumerate() {
            if i == 0 { current = part.to_string(); }
            else { current = format!("{current}\\{part}"); }
            keys.entry(current.clone()).or_insert_with(|| VirtualKey::new(current.clone()));
            // Register as subkey in parent.
            if i > 0 {
                let parent = parts[..i].join("\\");
                if let Some(p) = keys.get_mut(&parent) {
                    p.add_subkey(*part);
                }
            }
        }
        self.interceptor.write().record(None, RegOp::CreateKey, path, None, RegOpResult::Success);
        Ok(())
    }

    /// Delete a key and all its subkeys recursively.
    pub fn delete_key(&self, path: &str) -> Result<()> {
        let path = Self::normalize_path(path);
        let (action, _) = self.interceptor.read().evaluate(&path, RegOp::DeleteKey);
        if action == RegInterceptAction::Deny {
            self.interceptor.write().record(None, RegOp::DeleteKey, path.clone(), None, RegOpResult::Denied);
            bail!("delete_key denied");
        }
        let mut keys = self.keys.write();
        let to_remove: Vec<String> = keys.keys()
            .filter(|k| k.starts_with(&path))
            .cloned()
            .collect();
        if to_remove.is_empty() {
            self.interceptor.write().record(None, RegOp::DeleteKey, path.clone(), None, RegOpResult::NotFound);
            bail!("key not found: {path}");
        }
        for k in to_remove { keys.remove(&k); }
        self.interceptor.write().record(None, RegOp::DeleteKey, path, None, RegOpResult::Success);
        Ok(())
    }

    /// Return `true` if the key exists.
    pub fn key_exists(&self, path: &str) -> bool {
        let path = Self::normalize_path(path);
        self.keys.read().contains_key(&path)
    }

    /// List subkeys of a key.
    pub fn enum_subkeys(&self, path: &str) -> Result<Vec<String>> {
        let path = Self::normalize_path(path);
        let (action, _) = self.interceptor.read().evaluate(&path, RegOp::EnumSubkeys);
        if action == RegInterceptAction::Deny {
            self.interceptor.write().record(None, RegOp::EnumSubkeys, path, None, RegOpResult::Denied);
            bail!("enum_subkeys denied");
        }
        match self.keys.read().get(&path) {
            Some(k) => {
                let mut names = k.subkeys.clone();
                names.sort();
                Ok(names)
            }
            None => bail!("key not found: {path}"),
        }
    }

    // -----------------------------------------------------------------------
    // Value operations
    // -----------------------------------------------------------------------

    /// Set (create or overwrite) a value under a key.
    pub fn set_value(&self, key_path: &str, value: VirtualValue) -> Result<()> {
        let key_path = Self::normalize_path(key_path);
        let vname    = value.name.clone();
        let (action, redirect) = self.interceptor.read().evaluate(&key_path, RegOp::SetValue);
        let effective = match action {
            RegInterceptAction::Deny => {
                self.interceptor.write().record(None, RegOp::SetValue, key_path, Some(vname), RegOpResult::Denied);
                bail!("set_value denied");
            }
            RegInterceptAction::Redirect => redirect.unwrap_or_else(|| key_path.clone()),
            _ => key_path.clone(),
        };

        // Auto-create the key if needed.
        if !self.keys.read().contains_key(&effective) {
            drop(self.keys.read()); // release before create_key acquires write
            self.create_key(&effective)?;
        }

        let mut keys = self.keys.write();
        match keys.get_mut(&effective) {
            Some(k) => {
                k.set_value(value);
                self.interceptor.write().record(None, RegOp::SetValue, key_path,
                    Some(vname), RegOpResult::Success);
                Ok(())
            }
            None => bail!("key not found after creation: {effective}"),
        }
    }

    /// Query a value from a key.
    pub fn query_value(&self, key_path: &str, value_name: &str) -> Result<VirtualValue> {
        let key_path = Self::normalize_path(key_path);
        let (action, redirect) = self.interceptor.read().evaluate(&key_path, RegOp::QueryValue);
        let effective = match action {
            RegInterceptAction::Deny => {
                self.interceptor.write().record(None, RegOp::QueryValue, key_path,
                    Some(value_name.to_string()), RegOpResult::Denied);
                bail!("query_value denied");
            }
            RegInterceptAction::Redirect => redirect.unwrap_or_else(|| key_path.clone()),
            _ => key_path.clone(),
        };

        if let Some(v) = self.keys.read().get(&effective).and_then(|k| k.get_value(value_name)) {
            self.interceptor.write().record(None, RegOp::QueryValue, key_path,
                Some(value_name.to_string()), RegOpResult::Success);
            Ok(v.clone())
        } else {
            self.interceptor.write().record(None, RegOp::QueryValue, key_path,
                Some(value_name.to_string()), RegOpResult::NotFound);
            bail!("value not found: {effective}\\{value_name}")
        }
    }

    /// Delete a value.
    pub fn delete_value(&self, key_path: &str, value_name: &str) -> Result<()> {
        let key_path = Self::normalize_path(key_path);
        let mut keys = self.keys.write();
        match keys.get_mut(&key_path) {
            Some(k) => {
                let removed = k.delete_value(value_name);
                let result = if removed { RegOpResult::Success } else { RegOpResult::NotFound };
                self.interceptor.write().record(None, RegOp::DeleteValue, key_path,
                    Some(value_name.to_string()), result);
                if !removed { bail!("value not found"); }
                Ok(())
            }
            None => bail!("key not found: {key_path}"),
        }
    }

    /// Enumerate value names under a key.
    pub fn enum_values(&self, key_path: &str) -> Result<Vec<String>> {
        let key_path = Self::normalize_path(key_path);
        match self.keys.read().get(&key_path) {
            Some(k) => {
                let mut names: Vec<String> = k.values.keys().cloned().collect();
                names.sort();
                Ok(names)
            }
            None => bail!("key not found: {key_path}"),
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot / diff
    // -----------------------------------------------------------------------

    /// Snapshot all keys and values.
    pub fn snapshot(&self) -> HashMap<String, VirtualKey> {
        self.keys.read().clone()
    }

    /// Diff two snapshots, returning added, modified, and deleted key paths.
    #[must_use] 
    pub fn diff_snapshots(
        before: &HashMap<String, VirtualKey>,
        after:  &HashMap<String, VirtualKey>,
    ) -> RegistryDiff {
        let mut added   = Vec::new();
        let mut deleted = Vec::new();
        let mut modified_keys = Vec::new();
        let mut modified_values: Vec<(String, String)> = Vec::new();

        for (path, key_after) in after {
            match before.get(path) {
                None => added.push(path.clone()),
                Some(key_before) => {
                    for (vname, val_after) in &key_after.values {
                        match key_before.values.get(vname) {
                            None => modified_values.push((path.clone(), vname.clone())),
                            Some(val_before) => {
                                if val_before.data != val_after.data {
                                    modified_values.push((path.clone(), vname.clone()));
                                }
                            }
                        }
                    }
                    if !modified_values.is_empty() {
                        modified_keys.push(path.clone());
                    }
                }
            }
        }

        for path in before.keys() {
            if !after.contains_key(path) {
                deleted.push(path.clone());
            }
        }

        added.sort();
        deleted.sort();
        modified_keys.sort();
        modified_keys.dedup();

        RegistryDiff { added, deleted, modified_keys, modified_values }
    }

    // -----------------------------------------------------------------------
    // Access log
    // -----------------------------------------------------------------------

    pub fn access_log(&self) -> Vec<RegAccessRecord> {
        self.interceptor.read().all_records().to_vec()
    }

    pub fn written_keys(&self) -> Vec<String> {
        self.interceptor.read()
            .write_records()
            .iter()
            .map(|r| r.key_path.clone())
            .collect()
    }

    pub fn total_keys(&self) -> usize { self.keys.read().len() }
}

impl Default for VmRegistry {
    fn default() -> Self { Self::new() }
}

/// Result of comparing two registry snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryDiff {
    /// Keys present in `after` but not in `before`.
    pub added: Vec<String>,
    /// Keys present in `before` but not in `after`.
    pub deleted: Vec<String>,
    /// Keys that exist in both but have modified values.
    pub modified_keys: Vec<String>,
    /// (`key_path`, `value_name`) pairs that were added or changed.
    pub modified_values: Vec<(String, String)>,
}

impl RegistryDiff {
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.deleted.is_empty()
            && self.modified_keys.is_empty()
    }

    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "Registry diff: {} added, {} deleted, {} modified keys",
            self.added.len(), self.deleted.len(), self.modified_keys.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Preset registry layouts
// ---------------------------------------------------------------------------

/// Populate a `VmRegistry` with a minimal Windows registry skeleton.
pub fn windows_registry_skeleton(reg: &VmRegistry) -> Result<()> {
    // Core hive paths.
    reg.create_key("HKLM\\SOFTWARE")?;
    reg.create_key("HKLM\\SOFTWARE\\Microsoft")?;
    reg.create_key("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")?;
    reg.create_key("HKLM\\SYSTEM\\CurrentControlSet\\Services")?;
    reg.create_key("HKCU\\SOFTWARE")?;
    reg.create_key("HKCU\\SOFTWARE\\Microsoft")?;

    // Windows version values.
    reg.set_value(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        VirtualValue::sz("ProductName", "Windows 10 Enterprise"),
    )?;
    reg.set_value(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        VirtualValue::sz("CurrentVersion", "10.0"),
    )?;
    reg.set_value(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        VirtualValue::dword("CurrentMajorVersionNumber", 10),
    )?;
    reg.set_value(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        VirtualValue::dword("CurrentMinorVersionNumber", 0),
    )?;

    // Run key (common persistence location).
    reg.create_key("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")?;
    reg.create_key("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")?;

    // Internet settings.
    reg.create_key("HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\Main")?;
    reg.set_value(
        "HKCU\\SOFTWARE\\Microsoft\\Internet Explorer\\Main",
        VirtualValue::sz("Start Page", "about:blank"),
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_data_kind() {
        assert_eq!(RegData::DWord(1).kind(), RegValueKind::DWord);
        assert_eq!(RegData::String("x".into()).kind(), RegValueKind::Sz);
        assert_eq!(RegData::QWord(9).kind(), RegValueKind::QWord);
    }

    #[test]
    fn reg_data_accessors() {
        let d = RegData::DWord(42);
        assert_eq!(d.as_dword(), Some(42));
        assert_eq!(d.as_str(), None);

        let s = RegData::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));
    }

    #[test]
    fn virtual_key_value_operations() {
        let mut key = VirtualKey::new("HKLM\\Test");
        key.set_value(VirtualValue::dword("Count", 5));
        assert_eq!(key.get_value("Count").unwrap().data.as_dword(), Some(5));
        assert!(key.delete_value("Count"));
        assert!(key.get_value("Count").is_none());
    }

    #[test]
    fn registry_create_and_query() {
        let reg = VmRegistry::new();
        reg.create_key("HKLM\\SOFTWARE\\Acme").unwrap();
        assert!(reg.key_exists("HKLM\\SOFTWARE\\Acme"));
    }

    #[test]
    fn registry_set_and_query_value() {
        let reg = VmRegistry::new();
        reg.create_key("HKCU\\Test").unwrap();
        reg.set_value("HKCU\\Test", VirtualValue::sz("Greeting", "Hello")).unwrap();
        let v = reg.query_value("HKCU\\Test", "Greeting").unwrap();
        assert_eq!(v.data.as_str(), Some("Hello"));
    }

    #[test]
    fn registry_delete_key() {
        let reg = VmRegistry::new();
        reg.create_key("HKCU\\ToDelete").unwrap();
        reg.delete_key("HKCU\\ToDelete").unwrap();
        assert!(!reg.key_exists("HKCU\\ToDelete"));
    }

    #[test]
    fn registry_enum_subkeys() {
        let reg = VmRegistry::new();
        reg.create_key("HKLM\\Parent\\ChildA").unwrap();
        reg.create_key("HKLM\\Parent\\ChildB").unwrap();
        let children = reg.enum_subkeys("HKLM\\Parent").unwrap();
        assert!(children.contains(&"ChildA".to_string()));
        assert!(children.contains(&"ChildB".to_string()));
    }

    #[test]
    fn registry_snapshot_diff() {
        let reg = VmRegistry::new();
        let before = reg.snapshot();
        reg.create_key("HKLM\\New\\Key").unwrap();
        let after = reg.snapshot();
        let diff = VmRegistry::diff_snapshots(&before, &after);
        assert!(!diff.added.is_empty());
        assert!(!diff.is_empty());
    }

    #[test]
    fn registry_intercept_deny() {
        let reg = VmRegistry::new();
        reg.add_rule(RegInterceptRule::new("hkcu\\protected", RegInterceptAction::Deny));
        let result = reg.set_value(
            "HKCU\\Protected",
            VirtualValue::sz("Evil", "payload"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn registry_access_log_records() {
        let reg = VmRegistry::new();
        reg.create_key("HKCU\\Logged").unwrap();
        reg.set_value("HKCU\\Logged", VirtualValue::dword("Val", 1)).unwrap();
        let log = reg.access_log();
        assert!(!log.is_empty());
        assert!(log.iter().any(|r| r.op == RegOp::SetValue));
    }

    #[test]
    fn windows_skeleton_populates_run_key() {
        let reg = VmRegistry::new();
        windows_registry_skeleton(&reg).unwrap();
        assert!(reg.key_exists("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
        let v = reg.query_value(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "ProductName",
        ).unwrap();
        assert_eq!(v.data.as_str(), Some("Windows 10 Enterprise"));
    }

    #[test]
    fn registry_diff_summary() {
        let diff = RegistryDiff {
            added: vec!["A".into()],
            deleted: vec!["B".into(), "C".into()],
            modified_keys: Vec::new(),
            modified_values: Vec::new(),
        };
        assert!(diff.summary().contains("1 added"));
        assert!(diff.summary().contains("2 deleted"));
    }
}
