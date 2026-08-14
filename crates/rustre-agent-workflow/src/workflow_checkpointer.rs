//! `workflow_checkpointer` — Durable checkpointing for long-running workflows.
//!
//! Provides [`WorkflowCheckpointer`] which saves and restores [`Checkpoint`]
//! records to/from a SQLite-backed store, enabling crash-recovery and
//! resume-from-last-checkpoint semantics for multi-step RE pipelines.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use thiserror::Error;

type CheckpointRow = (String, String, String, String, String, u32, i64, i64, Option<String>);

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the checkpointer.
#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("database error: {0}")]
    Db(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("checkpoint not found: {0}")]
    NotFound(String),
    #[error("checkpoint already exists: {0}")]
    AlreadyExists(String),
    #[error("invalid checkpoint data: {0}")]
    InvalidData(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<rusqlite::Error> for CheckpointError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e.to_string())
    }
}

impl From<serde_json::Error> for CheckpointError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

// ─── CheckpointStatus ─────────────────────────────────────────────────────────

/// Lifecycle status of a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointStatus {
    /// The checkpoint has been written but the step has not finished.
    Pending,
    /// The step completed successfully.
    Completed,
    /// The step failed; this checkpoint can be used to retry.
    Failed,
    /// The checkpoint has been superseded by a later one.
    Superseded,
    /// The checkpoint was manually invalidated.
    Invalidated,
}

impl fmt::Display for CheckpointStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Superseded => write!(f, "superseded"),
            Self::Invalidated => write!(f, "invalidated"),
        }
    }
}

impl CheckpointStatus {
    /// Parse a status string (lowercase).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "superseded" => Self::Superseded,
            "invalidated" => Self::Invalidated,
            _ => Self::Pending,
        }
    }

    /// Return `true` if the step can be retried from this checkpoint.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Failed | Self::Pending)
    }

    /// Return `true` if the checkpoint represents terminal success.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

// ─── CheckpointData ───────────────────────────────────────────────────────────

/// Arbitrary data stored inside a checkpoint.
///
/// Wraps a JSON `Value` with typed accessor helpers for common RE workflow
/// outputs (binary paths, function lists, disassembly blobs, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointData {
    inner: serde_json::Value,
}

impl CheckpointData {
    /// Create an empty checkpoint data container.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Wrap an existing JSON value.
    #[must_use]
    pub const fn from_value(v: serde_json::Value) -> Self {
        Self { inner: v }
    }

    /// Build from a string-keyed map.
    #[must_use]
    pub fn from_map(map: HashMap<String, serde_json::Value>) -> Self {
        Self {
            inner: serde_json::Value::Object(map.into_iter().collect()),
        }
    }

    /// Get a reference to the raw JSON value.
    #[must_use]
    pub const fn value(&self) -> &serde_json::Value {
        &self.inner
    }

    /// Consume self and return the inner JSON value.
    #[must_use]
    pub fn into_value(self) -> serde_json::Value {
        self.inner
    }

    /// Insert a string field.
    pub fn set_str(&mut self, key: &str, value: impl Into<String>) {
        if let Some(obj) = self.inner.as_object_mut() {
            obj.insert(key.to_string(), serde_json::Value::String(value.into()));
        }
    }

    /// Insert an integer field.
    pub fn set_u64(&mut self, key: &str, value: u64) {
        if let Some(obj) = self.inner.as_object_mut() {
            obj.insert(key.to_string(), serde_json::json!(value));
        }
    }

    /// Insert a boolean field.
    pub fn set_bool(&mut self, key: &str, value: bool) {
        if let Some(obj) = self.inner.as_object_mut() {
            obj.insert(key.to_string(), serde_json::Value::Bool(value));
        }
    }

    /// Insert an arbitrary JSON field.
    pub fn set(&mut self, key: &str, value: serde_json::Value) {
        if let Some(obj) = self.inner.as_object_mut() {
            obj.insert(key.to_string(), value);
        }
    }

    /// Retrieve a string field.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.inner.get(key).and_then(|v| v.as_str())
    }

    /// Retrieve an integer field.
    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.inner.get(key).and_then(serde_json::Value::as_u64)
    }

    /// Retrieve a boolean field.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.inner.get(key).and_then(serde_json::Value::as_bool)
    }

    /// Retrieve an arbitrary JSON field.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.inner.get(key)
    }

    /// Return `true` if the data contains no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            serde_json::Value::Object(m) => m.is_empty(),
            _ => false,
        }
    }

    /// Merge all fields from `other` into `self` (other takes precedence).
    pub fn merge(&mut self, other: &Self) {
        if let (Some(dst), Some(src)) = (self.inner.as_object_mut(), other.inner.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
    }

    /// Serialize to a compact JSON string.
    ///
    /// # Errors
    /// Returns [`CheckpointError::Serialization`] on failure.
    pub fn to_json(&self) -> Result<String, CheckpointError> {
        serde_json::to_string(&self.inner).map_err(CheckpointError::from)
    }

    /// Deserialize from a JSON string.
    ///
    /// # Errors
    /// Returns [`CheckpointError::Serialization`] on failure.
    pub fn from_json(s: &str) -> Result<Self, CheckpointError> {
        let v: serde_json::Value = serde_json::from_str(s)?;
        Ok(Self { inner: v })
    }
}

impl Default for CheckpointData {
    fn default() -> Self {
        Self::empty()
    }
}

// ─── Checkpoint ───────────────────────────────────────────────────────────────

/// A single checkpoint record for a workflow step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Unique identifier for this checkpoint (UUID or `<run_id>:<step_id>`).
    pub id: String,
    /// The workflow run this belongs to.
    pub run_id: String,
    /// The step this checkpoint captures.
    pub step_id: String,
    /// Checkpoint lifecycle status.
    pub status: CheckpointStatus,
    /// Arbitrary step output / state.
    pub data: CheckpointData,
    /// Attempt number (1-indexed).
    pub attempt: u32,
    /// Epoch milliseconds when this checkpoint was created.
    pub created_ms: u64,
    /// Epoch milliseconds when this checkpoint was last updated.
    pub updated_ms: u64,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl Checkpoint {
    /// Create a new pending checkpoint.
    #[must_use]
    pub fn new(
        run_id: impl Into<String>,
        step_id: impl Into<String>,
        attempt: u32,
    ) -> Self {
        let run_id = run_id.into();
        let step_id = step_id.into();
        let id = format!("{run_id}:{step_id}:{attempt}");
        let now = now_ms();
        Self {
            id,
            run_id,
            step_id,
            status: CheckpointStatus::Pending,
            data: CheckpointData::empty(),
            attempt,
            created_ms: now,
            updated_ms: now,
            label: None,
        }
    }

    /// Mark this checkpoint as completed with the given data.
    pub fn complete(&mut self, data: CheckpointData) {
        self.status = CheckpointStatus::Completed;
        self.data = data;
        self.updated_ms = now_ms();
    }

    /// Mark this checkpoint as failed with an error message stored in the data.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.status = CheckpointStatus::Failed;
        self.data.set_str("error", message);
        self.updated_ms = now_ms();
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Return `true` if this checkpoint can be used to resume.
    #[must_use]
    pub fn is_resumable(&self) -> bool {
        self.status == CheckpointStatus::Completed
    }

    /// Return age in milliseconds.
    #[must_use]
    pub fn age_ms(&self) -> u64 {
        now_ms().saturating_sub(self.created_ms)
    }
}

impl fmt::Display for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Checkpoint[{}] run={} step={} attempt={} status={}",
            self.id, self.run_id, self.step_id, self.attempt, self.status
        )
    }
}

// ─── CheckpointFilter ─────────────────────────────────────────────────────────

/// Criteria for querying checkpoints from the store.
#[derive(Debug, Clone, Default)]
pub struct CheckpointFilter {
    /// Filter by run id.
    pub run_id: Option<String>,
    /// Filter by step id.
    pub step_id: Option<String>,
    /// Filter by status.
    pub status: Option<CheckpointStatus>,
    /// Only return checkpoints newer than this epoch ms.
    pub min_age_ms: Option<u64>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

impl CheckpointFilter {
    /// Create a filter for a specific run.
    #[must_use]
    pub fn for_run(run_id: impl Into<String>) -> Self {
        Self {
            run_id: Some(run_id.into()),
            ..Default::default()
        }
    }

    /// Restrict to a specific step within the current run filter.
    #[must_use]
    pub fn step(mut self, step_id: impl Into<String>) -> Self {
        self.step_id = Some(step_id.into());
        self
    }

    /// Restrict to a specific status.
    #[must_use]
    pub const fn with_status(mut self, status: CheckpointStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Restrict to at most `n` results.
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
}

// ─── CheckpointStore ──────────────────────────────────────────────────────────

/// SQLite-backed checkpoint persistence store.
struct CheckpointStore {
    conn: parking_lot::Mutex<Connection>,
}

impl CheckpointStore {
    /// Open a store at the given path (created if necessary).
    fn open(path: &str) -> Result<Self, CheckpointError> {
        let conn = Connection::open(path).map_err(CheckpointError::from)?;
        let store = Self {
            conn: parking_lot::Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory store (testing).
    fn in_memory() -> Result<Self, CheckpointError> {
        let conn = Connection::open_in_memory().map_err(CheckpointError::from)?;
        let store = Self {
            conn: parking_lot::Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), CheckpointError> {
        self.conn.lock().execute_batch(
            "CREATE TABLE IF NOT EXISTS checkpoints (
                id          TEXT PRIMARY KEY,
                run_id      TEXT NOT NULL,
                step_id     TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                data_json   TEXT NOT NULL DEFAULT '{}',
                attempt     INTEGER NOT NULL DEFAULT 1,
                created_ms  INTEGER NOT NULL,
                updated_ms  INTEGER NOT NULL,
                label       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_cp_run ON checkpoints(run_id);
            CREATE INDEX IF NOT EXISTS idx_cp_run_step ON checkpoints(run_id, step_id);
            CREATE INDEX IF NOT EXISTS idx_cp_status ON checkpoints(status);",
        )?;
        Ok(())
    }

    fn save(&self, cp: &Checkpoint) -> Result<(), CheckpointError> {
        let data_json = cp.data.to_json()?;
        let status_str = cp.status.to_string();
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO checkpoints
             (id, run_id, step_id, status, data_json, attempt, created_ms, updated_ms, label)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                cp.id,
                cp.run_id,
                cp.step_id,
                status_str,
                data_json,
                cp.attempt,
                cp.created_ms.cast_signed(),
                cp.updated_ms.cast_signed(),
                cp.label,
            ],
        )?;
        Ok(())
    }

    fn load(&self, id: &str) -> Result<Checkpoint, CheckpointError> {
        let conn = self.conn.lock();
        let row = conn.query_row(
            "SELECT id,run_id,step_id,status,data_json,attempt,created_ms,updated_ms,label
             FROM checkpoints WHERE id=?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        );
        drop(conn);

        match row {
            Err(_) => Err(CheckpointError::NotFound(id.to_string())),
            Ok((id, run_id, step_id, status, data_json, attempt, created_ms, updated_ms, label)) => {
                Ok(Checkpoint {
                    id,
                    run_id,
                    step_id,
                    status: CheckpointStatus::from_str_loose(&status),
                    data: CheckpointData::from_json(&data_json)?,
                    attempt,
                    // Guard against corrupted/malicious negative timestamps in the DB.
                    created_ms: u64::try_from(created_ms).unwrap_or(0),
                    updated_ms: u64::try_from(updated_ms).unwrap_or(0),
                    label,
                })
            }
        }
    }

    fn delete(&self, id: &str) -> Result<bool, CheckpointError> {
        let n = self
            .conn
            .lock()
            .execute("DELETE FROM checkpoints WHERE id=?1", params![id])?;
        Ok(n > 0)
    }

    fn query(&self, filter: &CheckpointFilter) -> Result<Vec<Checkpoint>, CheckpointError> {
        let conn = self.conn.lock();
        let mut sql = String::from(
            "SELECT id,run_id,step_id,status,data_json,attempt,created_ms,updated_ms,label
             FROM checkpoints WHERE 1=1",
        );
        let mut bound: Vec<String> = Vec::new();
        let mut param_idx = 1usize;

        if let Some(ref rid) = filter.run_id {
            let _ = write!(sql, " AND run_id=?{param_idx}");
            bound.push(rid.clone());
            param_idx += 1;
        }
        if let Some(ref sid) = filter.step_id {
            let _ = write!(sql, " AND step_id=?{param_idx}");
            bound.push(sid.clone());
            param_idx += 1;
        }
        if let Some(ref st) = filter.status {
            let _ = write!(sql, " AND status=?{param_idx}");
            bound.push(st.to_string());
            param_idx += 1;
        }
        if let Some(min_ms) = filter.min_age_ms {
            let _ = write!(sql, " AND created_ms >= ?{param_idx}");
            bound.push(min_ms.to_string());
            param_idx += 1;
        }

        let _ = param_idx; // prevent unused warning

        sql.push_str(" ORDER BY created_ms ASC");

        if let Some(n) = filter.limit {
            let _ = write!(sql, " LIMIT {n}");
        }

        let mut stmt = conn.prepare(&sql)?;

        // Build the parameter list dynamically. rusqlite requires `dyn ToSql` slices.
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            bound.iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();

        let collected: Vec<CheckpointRow> = {
            let rows = stmt.query_map(params_refs.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        drop(stmt);
        drop(conn);

        let mut results = Vec::new();
        for row in collected {
            let (id, run_id, step_id, status, data_json, attempt, created_ms, updated_ms, label) =
                row;
            let data = CheckpointData::from_json(&data_json)?;
            results.push(Checkpoint {
                id,
                run_id,
                step_id,
                status: CheckpointStatus::from_str_loose(&status),
                data,
                attempt,
                created_ms: u64::try_from(created_ms).unwrap_or(0),
                updated_ms: u64::try_from(updated_ms).unwrap_or(0),
                label,
            });
        }
        Ok(results)
    }

    fn count_for_run(&self, run_id: &str) -> Result<usize, CheckpointError> {
        let n: i64 = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT COUNT(*) FROM checkpoints WHERE run_id=?1",
                params![run_id],
                |row| row.get(0),
            )?
        };
        Ok(usize::try_from(n).unwrap_or(0))
    }

    fn latest_for_step(
        &self,
        run_id: &str,
        step_id: &str,
    ) -> Result<Checkpoint, CheckpointError> {
        let conn = self.conn.lock();
        let row = conn.query_row(
            "SELECT id,run_id,step_id,status,data_json,attempt,created_ms,updated_ms,label
             FROM checkpoints
             WHERE run_id=?1 AND step_id=?2
             ORDER BY attempt DESC, created_ms DESC
             LIMIT 1",
            params![run_id, step_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        );
        drop(conn);
        match row {
            Err(_) => Err(CheckpointError::NotFound(format!("{run_id}:{step_id}"))),
            Ok((id, run_id, step_id, status, data_json, attempt, created_ms, updated_ms, label)) => {
                Ok(Checkpoint {
                    id,
                    run_id,
                    step_id,
                    status: CheckpointStatus::from_str_loose(&status),
                    data: CheckpointData::from_json(&data_json)?,
                    attempt,
                    created_ms: u64::try_from(created_ms).unwrap_or(0),
                    updated_ms: u64::try_from(updated_ms).unwrap_or(0),
                    label,
                })
            }
        }
    }

    fn delete_for_run(&self, run_id: &str) -> Result<usize, CheckpointError> {
        let n = self.conn.lock().execute(
            "DELETE FROM checkpoints WHERE run_id=?1",
            params![run_id],
        )?;
        Ok(n)
    }
}

// ─── WorkflowCheckpointer ─────────────────────────────────────────────────────

/// High-level checkpointing API for workflow execution.
///
/// Wraps [`CheckpointStore`] with convenience methods suited to step-by-step
/// workflow execution, resume logic, and pruning.
pub struct WorkflowCheckpointer {
    store: CheckpointStore,
    run_id: String,
}

impl WorkflowCheckpointer {
    /// Open (or create) a checkpointer backed by a file-based `SQLite` store.
    ///
    /// # Errors
    /// Returns [`CheckpointError::Db`] if the file cannot be opened.
    pub fn open(path: &str, run_id: impl Into<String>) -> Result<Self, CheckpointError> {
        Ok(Self {
            store: CheckpointStore::open(path)?,
            run_id: run_id.into(),
        })
    }

    /// Create an in-memory checkpointer (useful for tests).
    ///
    /// # Errors
    /// Returns [`CheckpointError::Db`] on failure.
    pub fn in_memory(run_id: impl Into<String>) -> Result<Self, CheckpointError> {
        Ok(Self {
            store: CheckpointStore::in_memory()?,
            run_id: run_id.into(),
        })
    }

    /// Open a checkpointer whose store lives alongside the workflow database.
    ///
    /// If `base_dir` does not exist this returns [`CheckpointError::Io`].
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn from_dir(
        base_dir: &Path,
        run_id: impl Into<String>,
    ) -> Result<Self, CheckpointError> {
        if !base_dir.is_dir() {
            return Err(CheckpointError::Io(format!(
                "directory does not exist: {}",
                base_dir.display()
            )));
        }
        let path = base_dir.join("checkpoints.sqlite");
        Self::open(
            path.to_str()
                .ok_or_else(|| CheckpointError::Io("non-UTF-8 path".to_string()))?,
            run_id,
        )
    }

    /// Return the run id associated with this checkpointer.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    // ─── Writing ──────────────────────────────────────────────────────────────

    /// Create and persist a new pending checkpoint for a step.
    ///
    /// If a checkpoint already exists for the same step and attempt this
    /// returns [`CheckpointError::AlreadyExists`].
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn begin_step(&self, step_id: &str, attempt: u32) -> Result<Checkpoint, CheckpointError> {
        let cp = Checkpoint::new(self.run_id.clone(), step_id, attempt);
        // Check for duplicate.
        if self.store.load(&cp.id).is_ok() {
            return Err(CheckpointError::AlreadyExists(cp.id));
        }
        self.store.save(&cp)?;
        Ok(cp)
    }

    /// Mark a step as completed and persist the resulting data.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn complete_step(
        &self,
        step_id: &str,
        attempt: u32,
        data: CheckpointData,
    ) -> Result<Checkpoint, CheckpointError> {
        let id = format!("{}:{step_id}:{attempt}", self.run_id);
        let mut cp = self
            .store
            .load(&id)
            .unwrap_or_else(|_| Checkpoint::new(self.run_id.clone(), step_id, attempt));
        cp.complete(data);
        self.store.save(&cp)?;
        Ok(cp)
    }

    /// Mark a step as failed and persist the error message.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn fail_step(
        &self,
        step_id: &str,
        attempt: u32,
        message: impl Into<String>,
    ) -> Result<Checkpoint, CheckpointError> {
        let id = format!("{}:{step_id}:{attempt}", self.run_id);
        let mut cp = self
            .store
            .load(&id)
            .unwrap_or_else(|_| Checkpoint::new(self.run_id.clone(), step_id, attempt));
        cp.fail(message);
        self.store.save(&cp)?;
        Ok(cp)
    }

    /// Directly upsert an arbitrary checkpoint (advanced usage).
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn save(&self, cp: &Checkpoint) -> Result<(), CheckpointError> {
        self.store.save(cp)
    }

    // ─── Reading ──────────────────────────────────────────────────────────────

    /// Load a checkpoint by its full id.
    ///
    /// # Errors
    /// Returns [`CheckpointError::NotFound`] if no such checkpoint exists.
    pub fn load(&self, id: &str) -> Result<Checkpoint, CheckpointError> {
        self.store.load(id)
    }

    /// Load the latest checkpoint for a step in this run.
    ///
    /// # Errors
    /// Returns [`CheckpointError::NotFound`] if none exists.
    pub fn latest_for_step(&self, step_id: &str) -> Result<Checkpoint, CheckpointError> {
        self.store.latest_for_step(&self.run_id, step_id)
    }

    /// Check whether a step has been successfully completed.
    #[must_use]
    pub fn is_step_done(&self, step_id: &str) -> bool {
        self.store
            .latest_for_step(&self.run_id, step_id)
            .is_ok_and(|cp| cp.status == CheckpointStatus::Completed)
    }

    /// Retrieve the data stored for a completed step, if any.
    #[must_use]
    pub fn step_data(&self, step_id: &str) -> Option<CheckpointData> {
        self.store
            .latest_for_step(&self.run_id, step_id)
            .ok()
            .filter(|cp| cp.status == CheckpointStatus::Completed)
            .map(|cp| cp.data)
    }

    /// Return all checkpoints for this run.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on database failure.
    pub fn all_checkpoints(&self) -> Result<Vec<Checkpoint>, CheckpointError> {
        self.store
            .query(&CheckpointFilter::for_run(self.run_id.clone()))
    }

    /// Return only completed checkpoints for this run.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on database failure.
    pub fn completed_checkpoints(&self) -> Result<Vec<Checkpoint>, CheckpointError> {
        self.store.query(
            &CheckpointFilter::for_run(self.run_id.clone())
                .with_status(CheckpointStatus::Completed),
        )
    }

    /// Return only failed checkpoints for this run.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on database failure.
    pub fn failed_checkpoints(&self) -> Result<Vec<Checkpoint>, CheckpointError> {
        self.store.query(
            &CheckpointFilter::for_run(self.run_id.clone())
                .with_status(CheckpointStatus::Failed),
        )
    }

    /// Count the total number of checkpoints for this run.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on database failure.
    pub fn count(&self) -> Result<usize, CheckpointError> {
        self.store.count_for_run(&self.run_id)
    }

    // ─── Resumption helpers ───────────────────────────────────────────────────

    /// Compute the list of step ids that still need to be executed.
    ///
    /// `all_steps` is the ordered list of all step ids in the workflow.
    /// A step is considered done if its latest checkpoint has
    /// `CheckpointStatus::Completed`.
    #[must_use]
    pub fn pending_steps<'a>(&self, all_steps: &'a [&str]) -> Vec<&'a str> {
        all_steps
            .iter()
            .filter(|&&sid| !self.is_step_done(sid))
            .copied()
            .collect()
    }

    /// Return the first incomplete step id from `all_steps`, if any.
    #[must_use]
    pub fn resume_from<'a>(&self, all_steps: &'a [&str]) -> Option<&'a str> {
        all_steps.iter().copied().find(|&sid| !self.is_step_done(sid))
    }

    /// Return `true` if all steps in `all_steps` have completed checkpoints.
    #[must_use]
    pub fn is_workflow_complete(&self, all_steps: &[&str]) -> bool {
        all_steps.iter().all(|&sid| self.is_step_done(sid))
    }

    // ─── Pruning / lifecycle ──────────────────────────────────────────────────

    /// Delete all checkpoints for this run.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn purge_run(&self) -> Result<usize, CheckpointError> {
        self.store.delete_for_run(&self.run_id)
    }

    /// Delete a single checkpoint by id.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn delete(&self, id: &str) -> Result<bool, CheckpointError> {
        self.store.delete(id)
    }

    /// Mark all `Pending` or `Failed` checkpoints for this run as `Invalidated`.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn invalidate_incomplete(&self) -> Result<usize, CheckpointError> {
        let all = self.all_checkpoints()?;
        let mut count = 0;
        for mut cp in all {
            if matches!(cp.status, CheckpointStatus::Pending | CheckpointStatus::Failed) {
                cp.status = CheckpointStatus::Invalidated;
                cp.updated_ms = now_ms();
                self.store.save(&cp)?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Supersede the previous checkpoint for a step when retrying.
    ///
    /// Marks all existing checkpoints for the step as `Superseded`, then
    /// returns a fresh `Pending` checkpoint for the new attempt.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn retry_step(
        &self,
        step_id: &str,
        new_attempt: u32,
    ) -> Result<Checkpoint, CheckpointError> {
        let existing = self
            .store
            .query(&CheckpointFilter::for_run(self.run_id.clone()).step(step_id))?;
        for mut old_cp in existing {
            old_cp.status = CheckpointStatus::Superseded;
            old_cp.updated_ms = now_ms();
            self.store.save(&old_cp)?;
        }
        self.begin_step(step_id, new_attempt)
    }

    /// Produce a summary of checkpoint state for this run.
    ///
    /// # Errors
    /// Returns [`CheckpointError`] on failure.
    pub fn summary(&self) -> Result<CheckpointSummary, CheckpointError> {
        let all = self.all_checkpoints()?;
        Ok(CheckpointSummary::from_checkpoints(&self.run_id, &all))
    }
}

// ─── CheckpointSummary ────────────────────────────────────────────────────────

/// High-level summary of checkpoint state for a workflow run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSummary {
    pub run_id: String,
    pub total: usize,
    pub completed: usize,
    pub failed: usize,
    pub pending: usize,
    pub superseded: usize,
    pub invalidated: usize,
    pub step_ids: Vec<String>,
}

impl CheckpointSummary {
    /// Build a summary from a slice of checkpoints.
    #[must_use]
    pub fn from_checkpoints(run_id: &str, checkpoints: &[Checkpoint]) -> Self {
        let mut completed = 0usize;
        let mut failed = 0usize;
        let mut pending = 0usize;
        let mut superseded = 0usize;
        let mut invalidated = 0usize;
        let mut step_ids: Vec<String> = Vec::new();

        for cp in checkpoints {
            match cp.status {
                CheckpointStatus::Completed => completed += 1,
                CheckpointStatus::Failed => failed += 1,
                CheckpointStatus::Pending => pending += 1,
                CheckpointStatus::Superseded => superseded += 1,
                CheckpointStatus::Invalidated => invalidated += 1,
            }
            if !step_ids.contains(&cp.step_id) {
                step_ids.push(cp.step_id.clone());
            }
        }

        Self {
            run_id: run_id.to_string(),
            total: checkpoints.len(),
            completed,
            failed,
            pending,
            superseded,
            invalidated,
            step_ids,
        }
    }

    /// Return `true` if all seen steps are completed.
    #[must_use]
    pub const fn all_completed(&self) -> bool {
        self.failed == 0 && self.pending == 0 && self.completed > 0
    }
}

impl fmt::Display for CheckpointSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CheckpointSummary[{}] total={} completed={} failed={} pending={} superseded={}",
            self.run_id, self.total, self.completed, self.failed, self.pending, self.superseded
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Return current time as epoch milliseconds.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_checkpointer(run_id: &str) -> WorkflowCheckpointer {
        WorkflowCheckpointer::in_memory(run_id).unwrap()
    }

    // ── CheckpointData ────────────────────────────────────────────────────────

    #[test]
    fn checkpoint_data_str_roundtrip() {
        let mut d = CheckpointData::empty();
        d.set_str("binary_path", "/tmp/malware.exe");
        assert_eq!(d.get_str("binary_path"), Some("/tmp/malware.exe"));
        assert!(d.get_str("missing").is_none());
    }

    #[test]
    fn checkpoint_data_u64() {
        let mut d = CheckpointData::empty();
        d.set_u64("func_count", 1234);
        assert_eq!(d.get_u64("func_count"), Some(1234));
    }

    #[test]
    fn checkpoint_data_bool() {
        let mut d = CheckpointData::empty();
        d.set_bool("packed", true);
        assert_eq!(d.get_bool("packed"), Some(true));
    }

    #[test]
    fn checkpoint_data_merge() {
        let mut a = CheckpointData::empty();
        a.set_str("k1", "v1");
        let mut b = CheckpointData::empty();
        b.set_str("k2", "v2");
        b.set_str("k1", "overridden");
        a.merge(&b);
        assert_eq!(a.get_str("k1"), Some("overridden"));
        assert_eq!(a.get_str("k2"), Some("v2"));
    }

    #[test]
    fn checkpoint_data_json_roundtrip() {
        let mut d = CheckpointData::empty();
        d.set_str("x", "hello");
        let json = d.to_json().unwrap();
        let d2 = CheckpointData::from_json(&json).unwrap();
        assert_eq!(d2.get_str("x"), Some("hello"));
    }

    #[test]
    fn checkpoint_data_is_empty() {
        let d = CheckpointData::empty();
        assert!(d.is_empty());
        let mut d2 = CheckpointData::empty();
        d2.set_str("k", "v");
        assert!(!d2.is_empty());
    }

    // ── Checkpoint ────────────────────────────────────────────────────────────

    #[test]
    fn checkpoint_new_is_pending() {
        let cp = Checkpoint::new("run1", "step1", 1);
        assert_eq!(cp.status, CheckpointStatus::Pending);
        assert_eq!(cp.attempt, 1);
        assert!(cp.id.contains("run1"));
        assert!(cp.id.contains("step1"));
    }

    #[test]
    fn checkpoint_complete() {
        let mut cp = Checkpoint::new("run1", "step1", 1);
        let mut data = CheckpointData::empty();
        data.set_str("result", "ok");
        cp.complete(data);
        assert_eq!(cp.status, CheckpointStatus::Completed);
        assert!(cp.is_resumable());
    }

    #[test]
    fn checkpoint_fail() {
        let mut cp = Checkpoint::new("run1", "step1", 1);
        cp.fail("timeout");
        assert_eq!(cp.status, CheckpointStatus::Failed);
        assert!(!cp.is_resumable());
        assert_eq!(cp.data.get_str("error"), Some("timeout"));
    }

    // ── WorkflowCheckpointer ──────────────────────────────────────────────────

    #[test]
    fn begin_and_complete_step() {
        let cp = make_checkpointer("run1");
        cp.begin_step("disasm", 1).unwrap();
        assert!(!cp.is_step_done("disasm"));
        let mut data = CheckpointData::empty();
        data.set_str("functions", "100");
        cp.complete_step("disasm", 1, data).unwrap();
        assert!(cp.is_step_done("disasm"));
    }

    #[test]
    fn begin_duplicate_fails() {
        let cp = make_checkpointer("run1");
        cp.begin_step("step_x", 1).unwrap();
        let err = cp.begin_step("step_x", 1);
        assert!(matches!(err, Err(CheckpointError::AlreadyExists(_))));
    }

    #[test]
    fn fail_step() {
        let cp = make_checkpointer("run1");
        cp.begin_step("step_a", 1).unwrap();
        cp.fail_step("step_a", 1, "agent error").unwrap();
        let failed = cp.failed_checkpoints().unwrap();
        assert_eq!(failed.len(), 1);
        assert!(!cp.is_step_done("step_a"));
    }

    #[test]
    fn step_data_retrieval() {
        let cp = make_checkpointer("run1");
        let mut data = CheckpointData::empty();
        data.set_str("binary_path", "/tmp/test.exe");
        cp.complete_step("load", 1, data).unwrap();
        let retrieved = cp.step_data("load").unwrap();
        assert_eq!(retrieved.get_str("binary_path"), Some("/tmp/test.exe"));
    }

    #[test]
    fn pending_steps_calculation() {
        let cp = make_checkpointer("run1");
        let all = &["load", "disasm", "rename", "report"];
        let mut data = CheckpointData::empty();
        data.set_str("k", "v");
        cp.complete_step("load", 1, data.clone()).unwrap();
        cp.complete_step("disasm", 1, data.clone()).unwrap();
        let pending = cp.pending_steps(all);
        assert_eq!(pending, vec!["rename", "report"]);
    }

    #[test]
    fn resume_from() {
        let cp = make_checkpointer("run1");
        let all = &["a", "b", "c"];
        let mut data = CheckpointData::empty();
        data.set_str("x", "y");
        cp.complete_step("a", 1, data).unwrap();
        assert_eq!(cp.resume_from(all), Some("b"));
    }

    #[test]
    fn is_workflow_complete() {
        let cp = make_checkpointer("run1");
        let all = &["s1", "s2"];
        let data = CheckpointData::empty();
        cp.complete_step("s1", 1, data.clone()).unwrap();
        assert!(!cp.is_workflow_complete(all));
        cp.complete_step("s2", 1, data).unwrap();
        assert!(cp.is_workflow_complete(all));
    }

    #[test]
    fn purge_run() {
        let cp = make_checkpointer("run1");
        cp.begin_step("x", 1).unwrap();
        cp.begin_step("y", 1).unwrap();
        assert_eq!(cp.count().unwrap(), 2);
        let deleted = cp.purge_run().unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(cp.count().unwrap(), 0);
    }

    #[test]
    fn retry_step_supersedes_old() {
        let cp = make_checkpointer("run1");
        cp.begin_step("s1", 1).unwrap();
        cp.fail_step("s1", 1, "err").unwrap();
        cp.retry_step("s1", 2).unwrap();
        // Old checkpoint should be Superseded.
        let old = cp.load("run1:s1:1").unwrap();
        assert_eq!(old.status, CheckpointStatus::Superseded);
        // New checkpoint should be Pending.
        let new_cp = cp.load("run1:s1:2").unwrap();
        assert_eq!(new_cp.status, CheckpointStatus::Pending);
    }

    #[test]
    fn invalidate_incomplete() {
        let cp = make_checkpointer("run1");
        cp.begin_step("s1", 1).unwrap();
        cp.fail_step("s2", 1, "boom").unwrap();
        let count = cp.invalidate_incomplete().unwrap();
        assert_eq!(count, 2);
        let all = cp.all_checkpoints().unwrap();
        assert!(all
            .iter()
            .all(|c| c.status == CheckpointStatus::Invalidated));
    }

    #[test]
    fn summary_all_completed() {
        let cp = make_checkpointer("run1");
        let data = CheckpointData::empty();
        cp.complete_step("s1", 1, data.clone()).unwrap();
        cp.complete_step("s2", 1, data).unwrap();
        let summary = cp.summary().unwrap();
        assert!(summary.all_completed());
        assert_eq!(summary.completed, 2);
        assert_eq!(summary.total, 2);
    }

    #[test]
    fn checkpoint_status_display() {
        assert_eq!(CheckpointStatus::Completed.to_string(), "completed");
        assert_eq!(CheckpointStatus::Failed.to_string(), "failed");
        assert_eq!(CheckpointStatus::Superseded.to_string(), "superseded");
    }

    #[test]
    fn checkpoint_status_retryable() {
        assert!(CheckpointStatus::Failed.is_retryable());
        assert!(CheckpointStatus::Pending.is_retryable());
        assert!(!CheckpointStatus::Completed.is_retryable());
    }
}
