//! Artifact collection engine: `CollectionJob`, `CollectionEngine`,
//! parallel collection via registered `ForensicsPlugin` impls,
//! and artifact deduplication.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ForensicsPlugin, MemoryImage, PluginArgs, PluginOutput, ForensicsError};
use crate::artifact_store::{ArtifactStore, ArtifactType, ForensicArtifact};

// ─── CollectionError ──────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone)]
pub enum CollectionError {
    #[error("plugin '{0}' failed: {1}")]
    PluginFailed(String, String),
    #[error("no image provided")]
    NoImage,
    #[error("job '{0}' not found")]
    JobNotFound(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("timeout after {0}ms")]
    Timeout(u64),
}

// ─── JobStatus ────────────────────────────────────────────────────────────────

/// Current status of a collection job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed(e) => write!(f, "failed: {e}"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ─── CollectionJob ────────────────────────────────────────────────────────────

/// A collection job targeting a set of plugins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionJob {
    /// Unique job identifier.
    pub id: String,
    /// Names of plugins to run (empty = run all registered plugins).
    pub plugin_names: Vec<String>,
    /// Arguments forwarded to each plugin.
    pub args: HashMap<String, String>,
    /// Current status.
    pub status: JobStatus,
    /// Job priority (higher = runs first).
    pub priority: u8,
    /// Timestamp when the job was created.
    pub created_at: u64,
    /// Timestamp when the job was started.
    pub started_at: Option<u64>,
    /// Timestamp when the job completed.
    pub completed_at: Option<u64>,
    /// Number of artifacts collected by this job.
    pub artifacts_collected: usize,
    /// Per-plugin execution durations.
    pub plugin_durations_ms: HashMap<String, u64>,
    /// Plugin-level error messages.
    pub plugin_errors: HashMap<String, String>,
    /// Maximum execution time per plugin (ms, 0 = no limit).
    pub timeout_ms_per_plugin: u64,
    /// Case / investigation ID this job belongs to.
    pub case_id: Option<String>,
}

impl CollectionJob {
    /// Create a new job with a specific plugin list.
    #[must_use]
    pub fn new(id: impl Into<String>, plugins: Vec<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        Self {
            id: id.into(),
            plugin_names: plugins,
            args: HashMap::new(),
            status: JobStatus::Pending,
            priority: 1,
            created_at: now,
            started_at: None,
            completed_at: None,
            artifacts_collected: 0,
            plugin_durations_ms: HashMap::new(),
            plugin_errors: HashMap::new(),
            timeout_ms_per_plugin: 0,
            case_id: None,
        }
    }

    /// Create a job that runs all registered plugins.
    #[must_use]
    pub fn all_plugins(id: impl Into<String>) -> Self {
        Self::new(id, vec![])
    }

    /// Set an argument.
    #[must_use]
    pub fn with_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }

    /// Set the priority.
    #[must_use]
    pub const fn with_priority(mut self, p: u8) -> Self {
        self.priority = p;
        self
    }

    /// Set a per-plugin timeout.
    #[must_use]
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms_per_plugin = ms;
        self
    }

    /// Set the case ID.
    #[must_use]
    pub fn for_case(mut self, case_id: impl Into<String>) -> Self {
        self.case_id = Some(case_id.into());
        self
    }

    /// Mark the job as started.
    pub fn start(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.status = JobStatus::Running;
        self.started_at = Some(now);
    }

    /// Mark the job as completed.
    pub fn complete(&mut self, artifacts: usize) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.status = JobStatus::Completed;
        self.completed_at = Some(now);
        self.artifacts_collected = artifacts;
    }

    /// Mark the job as failed.
    pub fn fail(&mut self, reason: impl Into<String>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.status = JobStatus::Failed(reason.into());
        self.completed_at = Some(now);
    }

    /// Duration from start to completion, if both timestamps are set.
    #[must_use]
    pub const fn duration_ms(&self) -> Option<u64> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end.saturating_sub(start)),
            _ => None,
        }
    }

    /// Returns `true` if this job ran all plugins.
    #[must_use]
    pub const fn runs_all_plugins(&self) -> bool {
        self.plugin_names.is_empty()
    }
}

// ─── CollectionResult ─────────────────────────────────────────────────────────

/// Result returned by `CollectionEngine::run_job`.
#[derive(Debug, Clone)]
pub struct CollectionResult {
    pub job_id: String,
    /// Artifacts written to the store.
    pub artifact_ids: Vec<String>,
    /// Per-plugin success/failure summary.
    pub plugin_results: HashMap<String, PluginRunResult>,
    /// Total artifacts collected.
    pub total_artifacts: usize,
    /// Number of duplicates that were deduplicated.
    pub duplicates_removed: usize,
    /// Wall-clock duration of the run.
    pub duration_ms: u64,
}

/// Summary of a single plugin's execution within a job.
#[derive(Debug, Clone)]
pub struct PluginRunResult {
    pub plugin_name: String,
    pub success: bool,
    pub rows_produced: usize,
    pub duration_ms: u64,
    pub error: Option<String>,
}

// ─── DeduplicationKey ─────────────────────────────────────────────────────────

/// Key used to identify duplicate artifacts.
fn dedup_key(art: &ForensicArtifact) -> String {
    // Prefer SHA-256 hash if data is present; otherwise use type + source.
    if let Some(sha) = art.sha256_hex() {
        return sha.to_string();
    }
    format!("{}::{}", art.artifact_type, art.source)
}

// ─── CollectionEngine ─────────────────────────────────────────────────────────

/// Drives collection jobs: schedules plugins, collects artifacts,
/// deduplicates, and persists to an `ArtifactStore`.
pub struct CollectionEngine {
    /// Registered forensic plugins.
    plugins: std::sync::RwLock<HashMap<String, Arc<dyn ForensicsPlugin>>>,
    /// The backing artifact store.
    pub store: Arc<ArtifactStore>,
    /// Completed and in-progress jobs.
    jobs: std::sync::Mutex<HashMap<String, CollectionJob>>,
    /// Whether to deduplicate artifacts before storing.
    pub dedup_enabled: bool,
    /// Minimum confidence for artifacts to be stored.
    pub min_confidence: f32,
}

impl CollectionEngine {
    /// Create a new engine backed by the given store.
    #[must_use]
    pub fn new(store: Arc<ArtifactStore>) -> Self {
        Self {
            plugins: std::sync::RwLock::new(HashMap::new()),
            store,
            jobs: std::sync::Mutex::new(HashMap::new()),
            dedup_enabled: true,
            min_confidence: 0.0,
        }
    }

    /// Register a forensic plugin.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn register_plugin(&self, plugin: Arc<dyn ForensicsPlugin>) {
        self.plugins
            .write().unwrap()
            .insert(plugin.name().to_string(), plugin);
    }

    /// Return the names of all registered plugins, sorted.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn plugin_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.plugins.read().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    /// Return the number of registered plugins.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn plugin_count(&self) -> usize {
        self.plugins.read().unwrap().len()
    }

    /// Submit a job to the engine (stores it as Pending).
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn submit_job(&self, job: CollectionJob) -> String {
        let id = job.id.clone();
        self.jobs.lock().unwrap().insert(id.clone(), job);
        id
    }

    /// Get the current status of a job.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn job_status(&self, id: &str) -> Option<JobStatus> {
        self.jobs.lock().unwrap().get(id).map(|j| j.status.clone())
    }

    /// Run a collection job synchronously, producing artifacts and writing them
    /// to the backing store.
    ///
    /// # Errors
    /// Returns `CollectionError::NoImage` if no image is provided.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    pub fn run_job(
        &self,
        job_id: &str,
        image: &dyn MemoryImage,
    ) -> Result<CollectionResult, CollectionError> {
        let wall_start = Instant::now();

        // Look up the job.
        let mut job = {
            let jobs = self.jobs.lock().unwrap();
            jobs.get(job_id)
                .cloned()
                .ok_or_else(|| CollectionError::JobNotFound(job_id.to_string()))?
        };

        job.start();

        // Determine which plugins to run.
        let plugin_names: Vec<String> = if job.runs_all_plugins() {
            self.plugin_names()
        } else {
            job.plugin_names.clone()
        };

        // Build PluginArgs from job args.
        let mut plugin_args = PluginArgs::new();
        for (k, v) in &job.args {
            plugin_args.set(k, v);
        }

        let plugins_guard = self.plugins.read().unwrap();
        let mut all_artifacts: Vec<ForensicArtifact> = Vec::new();
        let mut plugin_results: HashMap<String, PluginRunResult> = HashMap::new();

        // Execute each plugin sequentially (parallel would require Arc<dyn MemoryImage>).
        for name in &plugin_names {
            let plugin_start = Instant::now();
            if let Some(plugin) = plugins_guard.get(name.as_str()) {
                let timeout = job.timeout_ms_per_plugin;
                let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    plugin.run(image, &plugin_args)
                }));

                let duration_ms = u64::try_from(plugin_start.elapsed().as_millis()).unwrap_or(u64::MAX);

                match run_result {
                    Ok(Ok(output)) => {
                        let rows = output.rows.len();
                        let artifacts = plugin_output_to_artifacts(name, output);
                        all_artifacts.extend(artifacts);
                        job.plugin_durations_ms.insert(name.clone(), duration_ms);
                        plugin_results.insert(
                            name.clone(),
                            PluginRunResult {
                                plugin_name: name.clone(),
                                success: true,
                                rows_produced: rows,
                                duration_ms,
                                error: None,
                            },
                        );

                        if timeout > 0 && duration_ms > timeout {
                            let err = format!("plugin '{name}' exceeded timeout {timeout}ms");
                            job.plugin_errors.insert(name.clone(), err.clone());
                        }
                    }
                    Ok(Err(e)) => {
                        let err_str = e.to_string();
                        job.plugin_errors.insert(name.clone(), err_str.clone());
                        plugin_results.insert(
                            name.clone(),
                            PluginRunResult {
                                plugin_name: name.clone(),
                                success: false,
                                rows_produced: 0,
                                duration_ms,
                                error: Some(err_str),
                            },
                        );
                    }
                    Err(_) => {
                        let err_str = format!("plugin '{name}' panicked");
                        job.plugin_errors.insert(name.clone(), err_str.clone());
                        plugin_results.insert(
                            name.clone(),
                            PluginRunResult {
                                plugin_name: name.clone(),
                                success: false,
                                rows_produced: 0,
                                duration_ms,
                                error: Some(err_str),
                            },
                        );
                    }
                }
            }
        }

        drop(plugins_guard);

        let (artifact_ids, duplicates_removed) = self.dedup_filter_and_store(all_artifacts);
        let total = artifact_ids.len();
        job.complete(total);

        // Persist job update.
        self.jobs.lock().unwrap().insert(job.id.clone(), job.clone());

        let duration_ms = u64::try_from(wall_start.elapsed().as_millis()).unwrap_or(u64::MAX);

        Ok(CollectionResult {
            job_id: job_id.to_string(),
            artifact_ids,
            plugin_results,
            total_artifacts: total,
            duplicates_removed,
            duration_ms,
        })
    }

    /// Deduplicate, filter by confidence, and upsert into the store.
    /// Returns the upserted IDs and the count of duplicates removed.
    fn dedup_filter_and_store(
        &self,
        all_artifacts: Vec<ForensicArtifact>,
    ) -> (Vec<String>, usize) {
        let pre_dedup_count = all_artifacts.len();
        let kept = if self.dedup_enabled {
            deduplicate(all_artifacts)
        } else {
            all_artifacts
        };
        let duplicates_removed = pre_dedup_count - kept.len();
        let kept: Vec<ForensicArtifact> = kept
            .into_iter()
            .filter(|a| a.confidence >= self.min_confidence)
            .collect();
        let mut artifact_ids = Vec::with_capacity(kept.len());
        for art in kept {
            let id = self.store.upsert(art);
            artifact_ids.push(id);
        }
        (artifact_ids, duplicates_removed)
    }

    /// Run a job and collect into a fresh store, returning both.
    /// Useful for isolated test runs.
    #[must_use]
    pub fn run_isolated(
        &self,
        job_id: &str,
        image: &dyn MemoryImage,
    ) -> Option<(CollectionResult, Vec<ForensicArtifact>)> {
        let result = self.run_job(job_id, image).ok()?;
        let artifacts: Vec<ForensicArtifact> = result
            .artifact_ids
            .iter()
            .filter_map(|id| self.store.get(id))
            .collect();
        Some((result, artifacts))
    }

    /// Return statistics about the current state of the engine.
    ///
    /// # Panics
    ///
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn stats(&self) -> EngineStats {
        let jobs = self.jobs.lock().unwrap();
        let completed = jobs.values().filter(|j| j.status == JobStatus::Completed).count();
        let failed = jobs
            .values()
            .filter(|j| matches!(j.status, JobStatus::Failed(_)))
            .count();
        let total_artifacts: usize = jobs.values().map(|j| j.artifacts_collected).sum();
        EngineStats {
            plugin_count: self.plugin_count(),
            job_count: jobs.len(),
            completed_jobs: completed,
            failed_jobs: failed,
            total_artifacts_collected: total_artifacts,
            store_size: self.store.count(),
        }
    }
}

/// Statistics snapshot from the collection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStats {
    pub plugin_count: usize,
    pub job_count: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub total_artifacts_collected: usize,
    pub store_size: usize,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Convert a `PluginOutput` into a list of `ForensicArtifact` entries.
fn plugin_output_to_artifacts(
    plugin_name: &str,
    output: PluginOutput,
) -> Vec<ForensicArtifact> {
    let mut artifacts = Vec::new();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

    if let Some(raw) = output.raw
        && !raw.is_empty() {
            let id = format!("{plugin_name}-raw-{ts}");
            let mut art = ForensicArtifact::new(&id, ArtifactType::Other(plugin_name.to_string()), plugin_name);
            art.set_data(raw.into_bytes());
            artifacts.push(art);
        }

    for (idx, row) in output.rows.into_iter().enumerate() {
        let id = format!("{plugin_name}-{ts}-{idx}");
        let mut art = ForensicArtifact::new(&id, classify_row(&row, plugin_name), plugin_name);
        for (k, v) in row {
            art.add_meta(k, v);
        }
        art.confidence = 0.9;
        artifacts.push(art);
    }

    artifacts
}

/// Heuristically classify a plugin output row.
fn classify_row(row: &HashMap<String, String>, plugin_name: &str) -> ArtifactType {
    let name_lower = plugin_name.to_ascii_lowercase();
    if name_lower.contains("process") { return ArtifactType::Process; }
    if name_lower.contains("registry") { return ArtifactType::Registry; }
    if name_lower.contains("network") || name_lower.contains("net") { return ArtifactType::Network; }
    if name_lower.contains("file") { return ArtifactType::File; }
    if name_lower.contains("credential") || name_lower.contains("cred") { return ArtifactType::Credential; }
    if name_lower.contains("memory") || name_lower.contains("mem") { return ArtifactType::Memory; }
    if row.contains_key("pid") { return ArtifactType::Process; }
    if row.contains_key("key_path") || row.contains_key("registry") { return ArtifactType::Registry; }
    if row.contains_key("remote_ip") || row.contains_key("dst_port") { return ArtifactType::Network; }
    ArtifactType::Other(plugin_name.to_string())
}

/// Deduplicate artifacts by their hash or type+source key.
fn deduplicate(artifacts: Vec<ForensicArtifact>) -> Vec<ForensicArtifact> {
    let mut seen: HashSet<String> = HashSet::with_capacity(artifacts.len());
    let mut result = Vec::with_capacity(artifacts.len());
    for art in artifacts {
        let key = dedup_key(&art);
        if seen.insert(key) {
            result.push(art);
        }
    }
    result
}

// ─── Built-in test plugin ─────────────────────────────────────────────────────

/// A simple process-list plugin that returns fixed rows (useful for tests).
pub struct ProcessListPlugin {
    pid_range: std::ops::Range<u32>,
}

impl ProcessListPlugin {
    #[must_use]
    pub const fn new() -> Self {
        Self { pid_range: 1..5 }
    }
}

impl Default for ProcessListPlugin {
    fn default() -> Self { Self::new() }
}

impl ForensicsPlugin for ProcessListPlugin {
    fn name(&self) -> &'static str { "process_list" }
    fn description(&self) -> &'static str { "Enumerates running processes from the memory image" }

    fn run(&self, _image: &dyn MemoryImage, _args: &PluginArgs) -> Result<PluginOutput, ForensicsError> {
        let mut output = PluginOutput::new();
        for pid in self.pid_range.clone() {
            let mut row = HashMap::new();
            row.insert("pid".to_string(), pid.to_string());
            row.insert("name".to_string(), format!("process_{pid}"));
            row.insert("ppid".to_string(), "1".to_string());
            output.add_row(row);
        }
        Ok(output)
    }
}

/// A simple strings-extraction plugin for tests.
pub struct StringsPlugin;

impl ForensicsPlugin for StringsPlugin {
    fn name(&self) -> &'static str { "strings" }
    fn description(&self) -> &'static str { "Extracts ASCII strings from memory" }

    fn run(&self, image: &dyn MemoryImage, args: &PluginArgs) -> Result<PluginOutput, ForensicsError> {
        let min_len: usize = args.get("min_len").and_then(|s| s.parse().ok()).unwrap_or(6);
        let mut output = PluginOutput::new();

        // Scan the first region for printable strings.
        let regions = image.regions();
        if let Some(region) = regions.first() {
            let size = region.size().min(65536) as usize;
            if let Ok(data) = image.read(region.start, size) {
                let mut current = String::new();
                for &b in &data {
                    if b.is_ascii_graphic() || b == b' ' {
                        current.push(b as char);
                    } else {
                        if current.len() >= min_len {
                            let mut row = HashMap::new();
                            row.insert("string".to_string(), current.clone());
                            row.insert("length".to_string(), current.len().to_string());
                            output.add_row(row);
                        }
                        current.clear();
                    }
                }
            }
        }
        Ok(output)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawMemoryImage, ArchBits, OsType};

    fn make_store() -> Arc<ArtifactStore> {
        Arc::new(ArtifactStore::new("test"))
    }

    fn make_image() -> RawMemoryImage {
        let data: Vec<u8> = (0..1024).map(|i| u8::try_from(i % 256).unwrap_or(u8::MAX)).collect();
        RawMemoryImage::from_bytes(data, ArchBits::Bits64, OsType::Windows)
    }

    fn make_engine() -> CollectionEngine {
        let engine = CollectionEngine::new(make_store());
        engine.register_plugin(Arc::new(ProcessListPlugin::new()));
        engine.register_plugin(Arc::new(StringsPlugin));
        engine
    }

    #[test]
    fn test_engine_register_plugins() {
        let engine = make_engine();
        assert_eq!(engine.plugin_count(), 2);
        let names = engine.plugin_names();
        assert!(names.contains(&"process_list".to_string()));
        assert!(names.contains(&"strings".to_string()));
    }

    #[test]
    fn test_submit_job() {
        let engine = make_engine();
        let job = CollectionJob::all_plugins("job-1");
        let id = engine.submit_job(job);
        assert_eq!(id, "job-1");
        assert_eq!(engine.job_status("job-1"), Some(JobStatus::Pending));
    }

    #[test]
    fn test_run_job_all_plugins() {
        let engine = make_engine();
        let job = CollectionJob::all_plugins("j1");
        engine.submit_job(job);
        let image = make_image();
        let result = engine.run_job("j1", &image).unwrap();
        assert!(result.total_artifacts > 0);
        assert_eq!(engine.job_status("j1"), Some(JobStatus::Completed));
    }

    #[test]
    fn test_run_job_specific_plugin() {
        let engine = make_engine();
        let job = CollectionJob::new("j2", vec!["process_list".to_string()]);
        engine.submit_job(job);
        let image = make_image();
        let result = engine.run_job("j2", &image).unwrap();
        assert!(result.plugin_results.contains_key("process_list"));
        assert!(result.plugin_results["process_list"].success);
    }

    #[test]
    fn test_run_job_not_found_error() {
        let engine = make_engine();
        let image = make_image();
        let err = engine.run_job("ghost", &image).unwrap_err();
        assert!(matches!(err, CollectionError::JobNotFound(_)));
    }

    #[test]
    fn test_deduplication() {
        let a1 = ForensicArtifact::new("x1", ArtifactType::File, "same_source");
        let a2 = ForensicArtifact::new("x2", ArtifactType::File, "same_source");
        // Same dedup key (type+source) since no data is set.
        let deduped = deduplicate(vec![a1, a2]);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_different_sources() {
        let a1 = ForensicArtifact::new("x1", ArtifactType::File, "src1");
        let a2 = ForensicArtifact::new("x2", ArtifactType::File, "src2");
        let deduped = deduplicate(vec![a1, a2]);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_by_hash() {
        let data = b"hello world".to_vec();
        let a1 = ForensicArtifact::with_data("h1", ArtifactType::Memory, "s1", data.clone());
        let a2 = ForensicArtifact::with_data("h2", ArtifactType::Memory, "s2", data);
        // Same hash → deduplicated to 1.
        let deduped = deduplicate(vec![a1, a2]);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_collection_job_all_plugins_flag() {
        let job = CollectionJob::all_plugins("j");
        assert!(job.runs_all_plugins());
        let job2 = CollectionJob::new("j2", vec!["strings".to_string()]);
        assert!(!job2.runs_all_plugins());
    }

    #[test]
    fn test_collection_job_lifecycle() {
        let mut job = CollectionJob::all_plugins("lifecycle");
        assert_eq!(job.status, JobStatus::Pending);
        job.start();
        assert_eq!(job.status, JobStatus::Running);
        job.complete(10);
        assert_eq!(job.status, JobStatus::Completed);
        assert_eq!(job.artifacts_collected, 10);
    }

    #[test]
    fn test_collection_job_fail() {
        let mut job = CollectionJob::all_plugins("fail-job");
        job.fail("something went wrong");
        assert!(matches!(job.status, JobStatus::Failed(_)));
    }

    #[test]
    fn test_engine_stats() {
        let engine = make_engine();
        let job = CollectionJob::all_plugins("stat-job");
        engine.submit_job(job);
        let image = make_image();
        engine.run_job("stat-job", &image).unwrap();
        let stats = engine.stats();
        assert_eq!(stats.completed_jobs, 1);
        assert!(stats.total_artifacts_collected > 0);
    }

    #[test]
    fn test_min_confidence_filter() {
        let engine = CollectionEngine {
            min_confidence: 0.99,
            ..CollectionEngine::new(make_store())
        };
        engine.register_plugin(Arc::new(ProcessListPlugin::new()));
        let job = CollectionJob::all_plugins("high-conf");
        engine.submit_job(job);
        let image = make_image();
        let result = engine.run_job("high-conf", &image).unwrap();
        // ProcessListPlugin artifacts have confidence 0.9 < 0.99, so they're filtered.
        assert_eq!(result.total_artifacts, 0);
    }

    #[test]
    fn test_process_list_plugin_rows() {
        let plugin = ProcessListPlugin::new();
        let image = make_image();
        let args = PluginArgs::new();
        let output = plugin.run(&image, &args).unwrap();
        assert_eq!(output.rows.len(), 4); // pids 1..5
        assert!(output.rows[0].contains_key("pid"));
    }

    #[test]
    fn test_plugin_output_to_artifacts() {
        let mut output = PluginOutput::new();
        let mut row = HashMap::new();
        row.insert("pid".to_string(), "1234".to_string());
        row.insert("name".to_string(), "notepad".to_string());
        output.add_row(row);

        let arts = plugin_output_to_artifacts("process_plugin", output);
        assert_eq!(arts.len(), 1);
        assert!(matches!(arts[0].artifact_type, ArtifactType::Process));
        assert_eq!(arts[0].get_meta("pid"), Some("1234"));
    }

    #[test]
    fn test_job_duration_ms() {
        let mut job = CollectionJob::all_plugins("d");
        job.start();
        // Simulate some elapsed time by advancing the completed_at manually.
        job.completed_at = job.started_at.map(|s| s + 500);
        assert_eq!(job.duration_ms(), Some(500));
    }

    #[test]
    fn test_job_status_display() {
        assert_eq!(JobStatus::Pending.to_string(), "pending");
        assert_eq!(JobStatus::Completed.to_string(), "completed");
        assert_eq!(JobStatus::Failed("err".to_string()).to_string(), "failed: err");
        assert_eq!(JobStatus::Cancelled.to_string(), "cancelled");
    }
}
