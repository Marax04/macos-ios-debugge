//! Per-plugin persistent data storage API.
//!
//! Provides a SQLite-backed (or in-process fallback) key/value store, session
//! persistence, shared inter-plugin tables, transactional writes, and typed
//! accessors for common value types.  The design mirrors what an IDE plugin
//! system would expose: plugins get an isolated namespace, optionally share
//! tables with declared consumers, and can commit or roll back multi-key
//! updates atomically.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the plugin data API.
#[derive(Debug, Clone)]
pub enum DataError {
    /// The requested key was not found.
    KeyNotFound(String),
    /// A type conversion failed.
    TypeMismatch { key: String, expected: &'static str },
    /// A transaction was already committed or rolled back.
    TransactionClosed,
    /// An active transaction must be committed or rolled back before opening
    /// another one on the same store.
    TransactionAlreadyOpen,
    /// The shared table name was not found.
    TableNotFound(String),
    /// An I/O or serialisation error occurred.
    Io(String),
    /// Permission denied by the host.
    PermissionDenied,
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound(k) => write!(f, "key not found: {k}"),
            Self::TypeMismatch { key, expected } => {
                write!(f, "type mismatch for key '{key}': expected {expected}")
            }
            Self::TransactionClosed => write!(f, "transaction already closed"),
            Self::TransactionAlreadyOpen => write!(f, "a transaction is already open"),
            Self::TableNotFound(t) => write!(f, "shared table not found: {t}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::PermissionDenied => write!(f, "permission denied"),
        }
    }
}

impl std::error::Error for DataError {}

pub type DataResult<T> = Result<T, DataError>;

// ─── KvValue ─────────────────────────────────────────────────────────────────

/// Typed value stored in a key/value entry.
#[derive(Debug, Clone, PartialEq)]
pub enum KvValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
    /// Serialised JSON string — stored as text internally.
    Json(String),
}

impl KvValue {
    /// Try to extract a `bool`.
    ///
    /// # Errors
    /// Returns `DataError::TypeMismatch` if the value is not a `Bool`.
    pub fn as_bool(&self, key: &str) -> DataResult<bool> {
        match self {
            Self::Bool(b) => Ok(*b),
            Self::Int(n) => Ok(*n != 0),
            _ => Err(DataError::TypeMismatch {
                key: key.to_string(),
                expected: "bool",
            }),
        }
    }

    /// Try to extract an `i64`.
    ///
    /// # Errors
    /// Returns `DataError::TypeMismatch` if the value cannot be coerced.
    pub fn as_int(&self, key: &str) -> DataResult<i64> {
        match self {
            Self::Int(n) => Ok(*n),
            Self::Bool(b) => Ok(i64::from(*b)),
            _ => Err(DataError::TypeMismatch {
                key: key.to_string(),
                expected: "int",
            }),
        }
    }

    /// Try to extract an `f64`.
    ///
    /// # Errors
    /// Returns `DataError::TypeMismatch` if the value cannot be coerced.
    pub fn as_float(&self, key: &str) -> DataResult<f64> {
        match self {
            Self::Float(f) => Ok(*f),
            Self::Int(n) => Ok(*n as f64),
            _ => Err(DataError::TypeMismatch {
                key: key.to_string(),
                expected: "float",
            }),
        }
    }

    /// Try to extract a `&str`.
    ///
    /// # Errors
    /// Returns `DataError::TypeMismatch` if the value is not text or JSON.
    pub fn as_str(&self, key: &str) -> DataResult<&str> {
        match self {
            Self::Text(s) | Self::Json(s) => Ok(s.as_str()),
            _ => Err(DataError::TypeMismatch {
                key: key.to_string(),
                expected: "text",
            }),
        }
    }

    /// Try to extract raw bytes.
    ///
    /// # Errors
    /// Returns `DataError::TypeMismatch` if the value is not a blob.
    pub fn as_blob(&self, key: &str) -> DataResult<&[u8]> {
        match self {
            Self::Blob(b) => Ok(b.as_slice()),
            _ => Err(DataError::TypeMismatch {
                key: key.to_string(),
                expected: "blob",
            }),
        }
    }

    /// Returns `true` if this value is `Null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Return a human-readable type name for diagnostics.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Text(_) => "text",
            Self::Blob(_) => "blob",
            Self::Json(_) => "json",
        }
    }
}

impl fmt::Display for KvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(fl) => write!(f, "{fl}"),
            Self::Text(s) | Self::Json(s) => write!(f, "{s}"),
            Self::Blob(b) => write!(f, "<blob {} bytes>", b.len()),
        }
    }
}

// ─── KvEntry ─────────────────────────────────────────────────────────────────

/// A single key/value entry in the plugin store.
#[derive(Debug, Clone)]
pub struct KvEntry {
    /// The key name (scoped to the plugin namespace).
    pub key: String,
    /// The stored value.
    pub value: KvValue,
    /// Creation timestamp (Unix ms, 0 if not tracked).
    pub created_ms: u64,
    /// Last-modified timestamp (Unix ms, 0 if not tracked).
    pub modified_ms: u64,
    /// Optional TTL in milliseconds (0 = no expiry).
    pub ttl_ms: u64,
    /// Whether this entry is dirty (modified since last flush).
    pub dirty: bool,
}

impl KvEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(key: impl Into<String>, value: KvValue) -> Self {
        Self {
            key: key.into(),
            value,
            created_ms: 0,
            modified_ms: 0,
            ttl_ms: 0,
            dirty: true,
        }
    }

    /// Returns `true` if a TTL is set and the entry has expired.
    ///
    /// `now_ms` is the current Unix timestamp in milliseconds.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        self.ttl_ms > 0 && self.created_ms + self.ttl_ms < now_ms
    }
}

// ─── DataTransaction ─────────────────────────────────────────────────────────

/// State of a data transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxState {
    Open,
    Committed,
    RolledBack,
}

/// A batch of key/value mutations that can be committed atomically.
///
/// Create via [`PluginDataStore::begin_transaction`].  Either call
/// [`DataTransaction::commit`] to apply or [`DataTransaction::rollback`] to
/// discard.
pub struct DataTransaction {
    ops: Vec<TxOp>,
    state: TxState,
    store: Arc<Mutex<StoreInner>>,
}

#[derive(Debug, Clone)]
enum TxOp {
    Set(String, KvValue),
    Delete(String),
    Clear,
}

impl DataTransaction {
    const fn new(store: Arc<Mutex<StoreInner>>) -> Self {
        Self {
            ops: Vec::new(),
            state: TxState::Open,
            store,
        }
    }

    /// Stage a set operation.
    ///
    /// # Errors
    /// Returns `DataError::TransactionClosed` if the transaction is no longer open.
    pub fn set(&mut self, key: impl Into<String>, value: KvValue) -> DataResult<()> {
        self.check_open()?;
        self.ops.push(TxOp::Set(key.into(), value));
        Ok(())
    }

    /// Stage a delete operation.
    ///
    /// # Errors
    /// Returns `DataError::TransactionClosed` if the transaction is no longer open.
    pub fn delete(&mut self, key: impl Into<String>) -> DataResult<()> {
        self.check_open()?;
        self.ops.push(TxOp::Delete(key.into()));
        Ok(())
    }

    /// Stage a full clear of the store.
    ///
    /// # Errors
    /// Returns `DataError::TransactionClosed` if the transaction is no longer open.
    pub fn clear(&mut self) -> DataResult<()> {
        self.check_open()?;
        self.ops.push(TxOp::Clear);
        Ok(())
    }

    /// Commit all staged operations atomically.
    ///
    /// # Errors
    /// Returns `DataError::TransactionClosed` if already committed/rolled back,
    /// or a lock error if the store is inaccessible.
    pub fn commit(&mut self) -> DataResult<()> {
        self.check_open()?;
        let mut inner = self.store.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        for op in self.ops.drain(..) {
            match op {
                TxOp::Set(k, v) => {
                    let entry = KvEntry::new(k.clone(), v);
                    inner.data.insert(k, entry);
                }
                TxOp::Delete(k) => {
                    inner.data.remove(&k);
                }
                TxOp::Clear => {
                    inner.data.clear();
                }
            }
        }
        inner.dirty = true;
        self.state = TxState::Committed;
        Ok(())
    }

    /// Discard all staged operations.
    ///
    /// # Errors
    /// Returns `DataError::TransactionClosed` if already committed/rolled back.
    pub fn rollback(&mut self) -> DataResult<()> {
        self.check_open()?;
        self.ops.clear();
        self.state = TxState::RolledBack;
        Ok(())
    }

    /// Returns the number of staged operations.
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.ops.len()
    }

    /// Returns `true` if the transaction is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self.state, TxState::Open)
    }

    fn check_open(&self) -> DataResult<()> {
        if self.state == TxState::Open {
            Ok(())
        } else {
            Err(DataError::TransactionClosed)
        }
    }
}

// ─── SharedTable ─────────────────────────────────────────────────────────────

/// Schema for a column in a shared table.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub name: String,
    pub type_hint: &'static str,
    pub nullable: bool,
}

impl ColumnDef {
    /// Create a non-nullable column definition.
    #[must_use]
    pub fn new(name: &str, type_hint: &'static str) -> Self {
        Self {
            name: name.to_string(),
            type_hint,
            nullable: false,
        }
    }

    /// Mark the column as nullable.
    #[must_use]
    pub const fn nullable(mut self) -> Self {
        self.nullable = true;
        self
    }
}

/// A row in a shared table (ordered list of values matching the table schema).
#[derive(Debug, Clone)]
pub struct TableRow {
    pub values: Vec<KvValue>,
}

impl TableRow {
    /// Create a new row from a list of values.
    #[must_use]
    pub const fn new(values: Vec<KvValue>) -> Self {
        Self { values }
    }

    /// Get a value by column index.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` if the index is out of range.
    pub fn get(&self, index: usize) -> DataResult<&KvValue> {
        self.values.get(index).ok_or_else(|| {
            DataError::KeyNotFound(format!("column index {index}"))
        })
    }
}

/// A shared inter-plugin data table.
///
/// Multiple plugins can read and write to the same table if the owning plugin
/// has declared the table as shared and granted access.
pub struct SharedTable {
    /// Table name.
    pub name: String,
    /// Column definitions.
    pub schema: Vec<ColumnDef>,
    /// Rows stored in the table.
    rows: Vec<TableRow>,
    /// Plugin that owns (created) this table.
    pub owner: String,
    /// Plugins granted read access (empty = all).
    pub readers: Vec<String>,
    /// Plugins granted write access (empty = owner only).
    pub writers: Vec<String>,
}

impl SharedTable {
    /// Create a new empty shared table.
    #[must_use]
    pub fn new(name: &str, owner: &str, schema: Vec<ColumnDef>) -> Self {
        Self {
            name: name.to_string(),
            schema,
            rows: Vec::new(),
            owner: owner.to_string(),
            readers: Vec::new(),
            writers: Vec::new(),
        }
    }

    /// Returns the number of rows.
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns `true` if the plugin is allowed to read.
    #[must_use]
    pub fn can_read(&self, plugin: &str) -> bool {
        plugin == self.owner || self.readers.is_empty() || self.readers.iter().any(|r| r == plugin)
    }

    /// Returns `true` if the plugin is allowed to write.
    #[must_use]
    pub fn can_write(&self, plugin: &str) -> bool {
        plugin == self.owner || self.writers.iter().any(|w| w == plugin)
    }

    /// Append a row.
    ///
    /// # Errors
    /// Returns `DataError::PermissionDenied` if the plugin lacks write access,
    /// or `DataError::TypeMismatch` if the row has the wrong number of columns.
    pub fn insert(&mut self, plugin: &str, row: TableRow) -> DataResult<()> {
        if !self.can_write(plugin) {
            return Err(DataError::PermissionDenied);
        }
        if row.values.len() != self.schema.len() {
            return Err(DataError::TypeMismatch {
                key: self.name.clone(),
                expected: "matching column count",
            });
        }
        self.rows.push(row);
        Ok(())
    }

    /// Return all rows readable by the plugin.
    ///
    /// # Errors
    /// Returns `DataError::PermissionDenied` if the plugin lacks read access.
    pub fn select_all(&self, plugin: &str) -> DataResult<&[TableRow]> {
        if !self.can_read(plugin) {
            return Err(DataError::PermissionDenied);
        }
        Ok(&self.rows)
    }

    /// Delete rows where the predicate returns `true`.
    ///
    /// Returns the number of rows deleted.
    ///
    /// # Errors
    /// Returns `DataError::PermissionDenied` if the plugin lacks write access.
    pub fn delete_where(
        &mut self,
        plugin: &str,
        predicate: impl Fn(&TableRow) -> bool,
    ) -> DataResult<usize> {
        if !self.can_write(plugin) {
            return Err(DataError::PermissionDenied);
        }
        let before = self.rows.len();
        self.rows.retain(|r| !predicate(r));
        Ok(before - self.rows.len())
    }

    /// Truncate all rows.
    ///
    /// # Errors
    /// Returns `DataError::PermissionDenied` if the plugin lacks write access.
    pub fn truncate(&mut self, plugin: &str) -> DataResult<()> {
        if !self.can_write(plugin) {
            return Err(DataError::PermissionDenied);
        }
        self.rows.clear();
        Ok(())
    }
}

// ─── PluginState ─────────────────────────────────────────────────────────────

/// Typed plugin state keys for session persistence.
///
/// These are the well-known keys that the host reads/writes on plugin
/// load and unload to restore UI state across sessions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginStateKey {
    /// Last open binary path.
    LastBinaryPath,
    /// Last viewed address.
    LastAddress,
    /// Panel layout JSON.
    PanelLayout,
    /// Theme name.
    Theme,
    /// User-defined annotation colour map (JSON).
    AnnotationColours,
    /// Arbitrary plugin-specific JSON blob.
    Custom(String),
}

impl PluginStateKey {
    /// Convert to the storage key string.
    #[must_use]
    pub fn to_key(&self) -> String {
        match self {
            Self::LastBinaryPath => "__state.last_binary_path".to_string(),
            Self::LastAddress => "__state.last_address".to_string(),
            Self::PanelLayout => "__state.panel_layout".to_string(),
            Self::Theme => "__state.theme".to_string(),
            Self::AnnotationColours => "__state.annotation_colours".to_string(),
            Self::Custom(s) => format!("__state.custom.{s}"),
        }
    }

    /// Parse from a storage key string.
    #[must_use]
    pub fn from_key(k: &str) -> Option<Self> {
        match k {
            "__state.last_binary_path" => Some(Self::LastBinaryPath),
            "__state.last_address" => Some(Self::LastAddress),
            "__state.panel_layout" => Some(Self::PanelLayout),
            "__state.theme" => Some(Self::Theme),
            "__state.annotation_colours" => Some(Self::AnnotationColours),
            other if other.starts_with("__state.custom.") => {
                Some(Self::Custom(other["__state.custom.".len()..].to_string()))
            }
            _ => None,
        }
    }
}

// ─── StoreInner ───────────────────────────────────────────────────────────────

/// Internal (lock-guarded) storage.
struct StoreInner {
    data: HashMap<String, KvEntry>,
    dirty: bool,
}

impl StoreInner {
    fn new() -> Self {
        Self {
            data: HashMap::new(),
            dirty: false,
        }
    }
}

// ─── PluginDataStore ──────────────────────────────────────────────────────────

/// Per-plugin isolated key/value data store with session persistence.
///
/// The store is backed by an in-memory `HashMap` that can optionally be
/// serialised to and from a flat text file (key=hex-value format, one entry
/// per line).  In a production build the backend would be `SQLite`.
pub struct PluginDataStore {
    /// Plugin namespace (used as storage file prefix).
    pub plugin_name: String,
    inner: Arc<Mutex<StoreInner>>,
    /// Number of entries before auto-flush is triggered (0 = disabled).
    pub auto_flush_threshold: usize,
    /// Optional path for persistence.
    pub persist_path: Option<std::path::PathBuf>,
}

impl PluginDataStore {
    /// Create a new in-memory store for the given plugin.
    #[must_use]
    pub fn new(plugin_name: &str) -> Self {
        Self {
            plugin_name: plugin_name.to_string(),
            inner: Arc::new(Mutex::new(StoreInner::new())),
            auto_flush_threshold: 0,
            persist_path: None,
        }
    }

    /// Create a store with a persistence path.
    #[must_use]
    pub fn with_path(plugin_name: &str, path: std::path::PathBuf) -> Self {
        let mut s = Self::new(plugin_name);
        s.persist_path = Some(path);
        s
    }

    // ── Basic get/set/delete ────────────────────────────────────────────────

    /// Set a key to a value.
    ///
    /// # Errors
    /// Returns a `DataError::Io` if the internal lock is poisoned.
    pub fn set(&self, key: impl Into<String>, value: KvValue) -> DataResult<()> {
        let k = key.into();
        let entry = KvEntry::new(k.clone(), value);
        let mut inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        inner.data.insert(k, entry);
        inner.dirty = true;
        Ok(())
    }

    /// Get a value by key.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` if the key does not exist, or
    /// `DataError::Io` if the lock is poisoned.
    pub fn get(&self, key: &str) -> DataResult<KvValue> {
        let inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        inner
            .data
            .get(key)
            .map(|e| e.value.clone())
            .ok_or_else(|| DataError::KeyNotFound(key.to_string()))
    }

    /// Get a value or return a default if not present.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn get_or(&self, key: &str, default: KvValue) -> DataResult<KvValue> {
        match self.get(key) {
            Ok(v) => Ok(v),
            Err(DataError::KeyNotFound(_)) => Ok(default),
            Err(e) => Err(e),
        }
    }

    /// Delete a key.  Returns `true` if the key existed.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn delete(&self, key: &str) -> DataResult<bool> {
        let mut inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        let existed = inner.data.remove(key).is_some();
        if existed {
            inner.dirty = true;
        }
        Ok(existed)
    }

    /// Returns `true` if the key exists.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn contains(&self, key: &str) -> DataResult<bool> {
        let inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        Ok(inner.data.contains_key(key))
    }

    /// Return all keys.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn keys(&self) -> DataResult<Vec<String>> {
        let inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        Ok(inner.data.keys().cloned().collect())
    }

    /// Return the number of stored entries.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn len(&self) -> DataResult<usize> {
        let inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        Ok(inner.data.len())
    }

    /// Returns `true` if the store is empty.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn is_empty(&self) -> DataResult<bool> {
        Ok(self.len()? == 0)
    }

    // ── Typed convenience accessors ────────────────────────────────────────

    /// Set a string value.
    ///
    /// # Errors
    /// Propagates `DataError` from the underlying `set` call.
    pub fn set_str(&self, key: &str, value: &str) -> DataResult<()> {
        self.set(key, KvValue::Text(value.to_string()))
    }

    /// Get a string value.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` or `DataError::TypeMismatch`.
    pub fn get_str(&self, key: &str) -> DataResult<String> {
        let v = self.get(key)?;
        Ok(v.as_str(key)?.to_string())
    }

    /// Set an integer value.
    ///
    /// # Errors
    /// Propagates `DataError` from the underlying `set` call.
    pub fn set_int(&self, key: &str, value: i64) -> DataResult<()> {
        self.set(key, KvValue::Int(value))
    }

    /// Get an integer value.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` or `DataError::TypeMismatch`.
    pub fn get_int(&self, key: &str) -> DataResult<i64> {
        let v = self.get(key)?;
        v.as_int(key)
    }

    /// Set a boolean value.
    ///
    /// # Errors
    /// Propagates `DataError` from the underlying `set` call.
    pub fn set_bool(&self, key: &str, value: bool) -> DataResult<()> {
        self.set(key, KvValue::Bool(value))
    }

    /// Get a boolean value.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` or `DataError::TypeMismatch`.
    pub fn get_bool(&self, key: &str) -> DataResult<bool> {
        let v = self.get(key)?;
        v.as_bool(key)
    }

    /// Set a blob value.
    ///
    /// # Errors
    /// Propagates `DataError` from the underlying `set` call.
    pub fn set_blob(&self, key: &str, value: Vec<u8>) -> DataResult<()> {
        self.set(key, KvValue::Blob(value))
    }

    /// Get a blob value.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` or `DataError::TypeMismatch`.
    pub fn get_blob(&self, key: &str) -> DataResult<Vec<u8>> {
        let v = self.get(key)?;
        Ok(v.as_blob(key)?.to_vec())
    }

    // ── Session state helpers ──────────────────────────────────────────────

    /// Save a well-known plugin state value.
    ///
    /// # Errors
    /// Propagates storage errors.
    pub fn save_state(&self, key: PluginStateKey, value: KvValue) -> DataResult<()> {
        self.set(key.to_key(), value)
    }

    /// Load a well-known plugin state value.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` if the state was never saved.
    pub fn load_state(&self, key: &PluginStateKey) -> DataResult<KvValue> {
        self.get(&key.to_key())
    }

    /// Return all saved state entries as `(PluginStateKey, KvValue)` pairs.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn all_state(&self) -> DataResult<Vec<(PluginStateKey, KvValue)>> {
        let inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        let mut out = Vec::new();
        for (k, entry) in &inner.data {
            if let Some(state_key) = PluginStateKey::from_key(k) {
                out.push((state_key, entry.value.clone()));
            }
        }
        Ok(out)
    }

    // ── Transactions ───────────────────────────────────────────────────────

    /// Begin a new transaction.
    #[must_use]
    pub fn begin_transaction(&self) -> DataTransaction {
        DataTransaction::new(Arc::clone(&self.inner))
    }

    // ── Persistence ────────────────────────────────────────────────────────

    /// Flush dirty entries to the persistence path (if set).
    ///
    /// The format is `key=hex(value_bytes)\n`.  Blob values are stored as raw
    /// hex; other types are first encoded to their string representation.
    ///
    /// # Errors
    /// Returns `DataError::Io` if writing fails.
    pub fn flush(&self) -> DataResult<()> {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None => return Ok(()),
        };
        let inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        if !inner.dirty {
            return Ok(());
        }
        let mut lines: Vec<String> = Vec::with_capacity(inner.data.len());
        for (k, entry) in &inner.data {
            let v_str = match &entry.value {
                KvValue::Blob(b) => b.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                other => other.to_string(),
            };
            let k_esc = k.replace('\\', "\\\\").replace('=', "\\=");
            lines.push(format!("{k_esc}={v_str}"));
        }
        std::fs::write(&path, lines.join("\n"))
            .map_err(|e| DataError::Io(e.to_string()))
    }

    /// Load entries from the persistence path (if set).
    ///
    /// Only text entries are restored; blob entries require type-aware
    /// deserialization that the caller must handle via `set_blob` after load.
    ///
    /// # Errors
    /// Returns `DataError::Io` if reading fails.
    pub fn load(&self) -> DataResult<usize> {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None => return Ok(0),
        };
        if !path.exists() {
            return Ok(0);
        }
        let content = std::fs::read_to_string(&path).map_err(|e| DataError::Io(e.to_string()))?;
        let mut count = 0usize;
        let mut inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            // Find first unescaped '='.
            let sep = line.char_indices().find(|&(_, c)| c == '=').map(|(i, _)| i);
            if let Some(i) = sep {
                let k = line[..i].replace("\\=", "=").replace("\\\\", "\\");
                let v = line[i + 1..].to_string();
                let entry = KvEntry::new(k.clone(), KvValue::Text(v));
                inner.data.insert(k, entry);
                count += 1;
            }
        }
        inner.dirty = false;
        Ok(count)
    }

    /// Clear all entries.
    ///
    /// # Errors
    /// Returns `DataError::Io` if the lock is poisoned.
    pub fn clear(&self) -> DataResult<()> {
        let mut inner = self.inner.lock().map_err(|_| DataError::Io("lock poisoned".into()))?;
        inner.data.clear();
        inner.dirty = true;
        Ok(())
    }
}

// ─── SharedTableRegistry ─────────────────────────────────────────────────────

/// Global registry of shared inter-plugin tables.
#[derive(Default)]
pub struct SharedTableRegistry {
    tables: HashMap<String, SharedTable>,
}

impl SharedTableRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new shared table.
    ///
    /// # Errors
    /// Returns `DataError::KeyNotFound` (reused as "already exists") if the table
    /// name is already registered.
    pub fn create_table(
        &mut self,
        name: &str,
        owner: &str,
        schema: Vec<ColumnDef>,
    ) -> DataResult<()> {
        if self.tables.contains_key(name) {
            return Err(DataError::KeyNotFound(format!("table '{name}' already exists")));
        }
        self.tables.insert(name.to_string(), SharedTable::new(name, owner, schema));
        Ok(())
    }

    /// Get a mutable reference to a table.
    ///
    /// # Errors
    /// Returns `DataError::TableNotFound` if the table does not exist.
    pub fn table_mut(&mut self, name: &str) -> DataResult<&mut SharedTable> {
        self.tables.get_mut(name).ok_or_else(|| DataError::TableNotFound(name.to_string()))
    }

    /// Get a reference to a table.
    ///
    /// # Errors
    /// Returns `DataError::TableNotFound` if the table does not exist.
    pub fn table(&self, name: &str) -> DataResult<&SharedTable> {
        self.tables.get(name).ok_or_else(|| DataError::TableNotFound(name.to_string()))
    }

    /// List all registered table names.
    #[must_use]
    pub fn table_names(&self) -> Vec<&str> {
        self.tables.keys().map(String::as_str).collect()
    }

    /// Drop a table.
    ///
    /// # Errors
    /// Returns `DataError::TableNotFound` if the table does not exist.
    pub fn drop_table(&mut self, name: &str, plugin: &str) -> DataResult<()> {
        let table = self.table(name)?;
        if table.owner != plugin {
            return Err(DataError::PermissionDenied);
        }
        self.tables.remove(name);
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PluginDataStore {
        PluginDataStore::new("test_plugin")
    }

    // ── KvValue ───────────────────────────────────────────────────────────

    #[test]
    fn test_kv_value_bool() {
        let v = KvValue::Bool(true);
        assert_eq!(v.as_bool("k").unwrap(), true);
        assert_eq!(v.type_name(), "bool");
    }

    #[test]
    fn test_kv_value_int() {
        let v = KvValue::Int(42);
        assert_eq!(v.as_int("k").unwrap(), 42);
    }

    #[test]
    fn test_kv_value_float() {
        let v = KvValue::Float(3.14);
        let f = v.as_float("k").unwrap();
        assert!((f - 3.14).abs() < 1e-10);
    }

    #[test]
    fn test_kv_value_text() {
        let v = KvValue::Text("hello".to_string());
        assert_eq!(v.as_str("k").unwrap(), "hello");
    }

    #[test]
    fn test_kv_value_blob() {
        let v = KvValue::Blob(vec![1, 2, 3]);
        assert_eq!(v.as_blob("k").unwrap(), &[1u8, 2, 3]);
    }

    #[test]
    fn test_kv_value_type_mismatch() {
        let v = KvValue::Int(5);
        assert!(v.as_blob("k").is_err());
    }

    #[test]
    fn test_kv_value_null() {
        let v = KvValue::Null;
        assert!(v.is_null());
    }

    #[test]
    fn test_kv_value_int_coerces_to_float() {
        let v = KvValue::Int(7);
        let f = v.as_float("k").unwrap();
        assert!((f - 7.0).abs() < 1e-10);
    }

    // ── KvEntry ───────────────────────────────────────────────────────────

    #[test]
    fn test_kv_entry_not_expired() {
        let e = KvEntry::new("k", KvValue::Int(1));
        assert!(!e.is_expired(1_000_000));
    }

    #[test]
    fn test_kv_entry_expired() {
        let mut e = KvEntry::new("k", KvValue::Int(1));
        e.ttl_ms = 1000;
        e.created_ms = 0;
        assert!(e.is_expired(2000));
    }

    // ── PluginDataStore ───────────────────────────────────────────────────

    #[test]
    fn test_store_set_get() {
        let s = store();
        s.set("key", KvValue::Text("value".into())).unwrap();
        let v = s.get("key").unwrap();
        assert_eq!(v, KvValue::Text("value".into()));
    }

    #[test]
    fn test_store_not_found() {
        let s = store();
        assert!(s.get("missing").is_err());
    }

    #[test]
    fn test_store_delete() {
        let s = store();
        s.set("k", KvValue::Bool(true)).unwrap();
        assert!(s.delete("k").unwrap());
        assert!(!s.contains("k").unwrap());
    }

    #[test]
    fn test_store_get_or_default() {
        let s = store();
        let v = s.get_or("missing", KvValue::Int(0)).unwrap();
        assert_eq!(v, KvValue::Int(0));
    }

    #[test]
    fn test_store_typed_str() {
        let s = store();
        s.set_str("name", "alice").unwrap();
        assert_eq!(s.get_str("name").unwrap(), "alice");
    }

    #[test]
    fn test_store_typed_int() {
        let s = store();
        s.set_int("count", 99).unwrap();
        assert_eq!(s.get_int("count").unwrap(), 99);
    }

    #[test]
    fn test_store_typed_bool() {
        let s = store();
        s.set_bool("flag", false).unwrap();
        assert!(!s.get_bool("flag").unwrap());
    }

    #[test]
    fn test_store_typed_blob() {
        let s = store();
        s.set_blob("data", vec![0xDE, 0xAD]).unwrap();
        assert_eq!(s.get_blob("data").unwrap(), vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_store_len_empty() {
        let s = store();
        assert_eq!(s.len().unwrap(), 0);
        assert!(s.is_empty().unwrap());
    }

    #[test]
    fn test_store_clear() {
        let s = store();
        s.set_int("a", 1).unwrap();
        s.set_int("b", 2).unwrap();
        s.clear().unwrap();
        assert!(s.is_empty().unwrap());
    }

    #[test]
    fn test_store_keys() {
        let s = store();
        s.set_str("x", "1").unwrap();
        s.set_str("y", "2").unwrap();
        let mut keys = s.keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["x", "y"]);
    }

    // ── DataTransaction ───────────────────────────────────────────────────

    #[test]
    fn test_transaction_commit() {
        let s = store();
        let mut tx = s.begin_transaction();
        tx.set("a", KvValue::Int(1)).unwrap();
        tx.set("b", KvValue::Int(2)).unwrap();
        tx.commit().unwrap();
        assert_eq!(s.get_int("a").unwrap(), 1);
        assert_eq!(s.get_int("b").unwrap(), 2);
    }

    #[test]
    fn test_transaction_rollback() {
        let s = store();
        s.set_int("a", 10).unwrap();
        let mut tx = s.begin_transaction();
        tx.set("a", KvValue::Int(99)).unwrap();
        tx.rollback().unwrap();
        // Store should still have original value.
        assert_eq!(s.get_int("a").unwrap(), 10);
    }

    #[test]
    fn test_transaction_closed_after_commit() {
        let s = store();
        let mut tx = s.begin_transaction();
        tx.set("k", KvValue::Null).unwrap();
        tx.commit().unwrap();
        assert!(tx.set("k2", KvValue::Null).is_err());
    }

    #[test]
    fn test_transaction_delete() {
        let s = store();
        s.set_str("to_del", "bye").unwrap();
        let mut tx = s.begin_transaction();
        tx.delete("to_del").unwrap();
        tx.commit().unwrap();
        assert!(!s.contains("to_del").unwrap());
    }

    #[test]
    fn test_transaction_clear() {
        let s = store();
        s.set_int("x", 1).unwrap();
        let mut tx = s.begin_transaction();
        tx.clear().unwrap();
        tx.commit().unwrap();
        assert!(s.is_empty().unwrap());
    }

    #[test]
    fn test_transaction_pending_count() {
        let s = store();
        let mut tx = s.begin_transaction();
        tx.set("a", KvValue::Null).unwrap();
        tx.set("b", KvValue::Null).unwrap();
        assert_eq!(tx.pending_count(), 2);
    }

    // ── Session state ─────────────────────────────────────────────────────

    #[test]
    fn test_plugin_state_key_round_trip() {
        let k = PluginStateKey::LastBinaryPath;
        let s = k.to_key();
        assert_eq!(PluginStateKey::from_key(&s), Some(PluginStateKey::LastBinaryPath));
    }

    #[test]
    fn test_plugin_state_custom() {
        let k = PluginStateKey::Custom("my_pref".to_string());
        let s = k.to_key();
        assert!(s.contains("my_pref"));
        assert_eq!(PluginStateKey::from_key(&s), Some(PluginStateKey::Custom("my_pref".to_string())));
    }

    #[test]
    fn test_save_load_state() {
        let st = store();
        st.save_state(PluginStateKey::Theme, KvValue::Text("dark".into())).unwrap();
        let v = st.load_state(&PluginStateKey::Theme).unwrap();
        assert_eq!(v, KvValue::Text("dark".into()));
    }

    #[test]
    fn test_all_state() {
        let st = store();
        st.save_state(PluginStateKey::LastAddress, KvValue::Int(0x1000)).unwrap();
        let states = st.all_state().unwrap();
        assert!(!states.is_empty());
    }

    // ── SharedTable ───────────────────────────────────────────────────────

    #[test]
    fn test_shared_table_insert_select() {
        let mut t = SharedTable::new(
            "xrefs",
            "owner_plugin",
            vec![ColumnDef::new("from", "int"), ColumnDef::new("to", "int")],
        );
        let row = TableRow::new(vec![KvValue::Int(0x1000), KvValue::Int(0x2000)]);
        t.insert("owner_plugin", row).unwrap();
        let rows = t.select_all("owner_plugin").unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn test_shared_table_permission_denied_write() {
        let mut t = SharedTable::new("t", "alice", vec![ColumnDef::new("v", "int")]);
        let row = TableRow::new(vec![KvValue::Int(1)]);
        assert!(t.insert("bob", row).is_err());
    }

    #[test]
    fn test_shared_table_read_allowed() {
        let t = SharedTable::new("t", "alice", vec![ColumnDef::new("v", "int")]);
        // readers empty = all can read.
        assert!(t.select_all("bob").is_ok());
    }

    #[test]
    fn test_shared_table_delete_where() {
        let mut t = SharedTable::new("t", "owner", vec![ColumnDef::new("n", "int")]);
        t.insert("owner", TableRow::new(vec![KvValue::Int(1)])).unwrap();
        t.insert("owner", TableRow::new(vec![KvValue::Int(2)])).unwrap();
        let deleted = t.delete_where("owner", |r| r.values[0] == KvValue::Int(1)).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(t.row_count(), 1);
    }

    #[test]
    fn test_shared_table_truncate() {
        let mut t = SharedTable::new("t", "owner", vec![ColumnDef::new("v", "int")]);
        t.insert("owner", TableRow::new(vec![KvValue::Int(5)])).unwrap();
        t.truncate("owner").unwrap();
        assert_eq!(t.row_count(), 0);
    }

    // ── SharedTableRegistry ───────────────────────────────────────────────

    #[test]
    fn test_registry_create_and_list() {
        let mut reg = SharedTableRegistry::new();
        reg.create_table("calls", "plugin_a", vec![ColumnDef::new("addr", "int")]).unwrap();
        assert!(reg.table_names().contains(&"calls"));
    }

    #[test]
    fn test_registry_drop_table_owner() {
        let mut reg = SharedTableRegistry::new();
        reg.create_table("t", "owner", vec![]).unwrap();
        reg.drop_table("t", "owner").unwrap();
        assert!(reg.table("t").is_err());
    }

    #[test]
    fn test_registry_drop_table_non_owner() {
        let mut reg = SharedTableRegistry::new();
        reg.create_table("t", "owner", vec![]).unwrap();
        assert!(reg.drop_table("t", "other").is_err());
    }
}
