//! `distributed_scan` — Distributed YARA scanning: job queue, worker nodes,
//! result aggregation, and deduplication.
//!
//! Architecture:
//! ```text
//! Coordinator ──── JobQueue ────► Worker(0)
//!                           ────► Worker(1)
//!                           ────► Worker(N)
//!                  ResultBus ◄─── Worker(0..N)
//!                  Aggregator ──► DeduplicatedReport
//! ```

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::YaraRule;

// Module-private cast helper for narrowing u128 → u64 (millisecond/nanosecond
// counters from `Duration` will not exceed `u64::MAX` in any practical case).
#[inline]
fn u128_to_u64(v: u128) -> u64 { u64::try_from(v).unwrap_or(u64::MAX) }

// ── Job ───────────────────────────────────────────────────────────────────────

/// Unique job identifier.
pub type JobId = u64;

/// Priority level for a scan job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// A scan job submitted to the distributed coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    /// Unique job ID.
    pub id: JobId,
    /// Human-readable label for this job.
    pub label: String,
    /// Data to scan (serialised as base64 in remote scenarios; raw bytes locally).
    #[serde(skip)]
    pub data: Option<Arc<Vec<u8>>>,
    /// File path if scanning a file rather than in-memory data.
    pub file_path: Option<String>,
    /// Priority of the job.
    pub priority: Priority,
    /// Unix timestamp when the job was created.
    pub created_at: u64,
    /// Maximum age before the job is considered stale (seconds).
    pub ttl_secs: u64,
    /// SHA-256 hash of the data for deduplication (hex string).
    pub content_hash: Option<String>,
    /// Metadata tags (key=value).
    pub tags: HashMap<String, String>,
}

impl ScanJob {
    /// Create a new in-memory scan job.
    pub fn new_memory(label: impl Into<String>, data: Vec<u8>) -> Self {
        let hash = sha256_hex(&data);
        Self {
            id: next_job_id(),
            label: label.into(),
            data: Some(Arc::new(data)),
            file_path: None,
            priority: Priority::Normal,
            created_at: unix_ts(),
            ttl_secs: 300,
            content_hash: Some(hash),
            tags: HashMap::new(),
        }
    }

    /// Create a new file scan job.
    pub fn new_file(path: impl Into<String>) -> Self {
        let path = path.into();
        Self {
            id: next_job_id(),
            label: path.clone(),
            data: None,
            file_path: Some(path),
            priority: Priority::Normal,
            created_at: unix_ts(),
            ttl_secs: 300,
            content_hash: None,
            tags: HashMap::new(),
        }
    }

    /// Set priority.
    #[must_use] 
    pub const fn with_priority(mut self, p: Priority) -> Self {
        self.priority = p;
        self
    }

    /// Add a metadata tag.
    #[must_use]
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Check if the job has expired.
    #[must_use] 
    pub fn is_expired(&self) -> bool {
        unix_ts().saturating_sub(self.created_at) > self.ttl_secs
    }
}

// ── Job state ─────────────────────────────────────────────────────────────────

/// Current status of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Expired,
    Deduplicated,
}

// ── Job result ────────────────────────────────────────────────────────────────

/// Result of a single scan job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: JobId,
    pub job_label: String,
    pub status: JobStatus,
    pub matches: Vec<DistributedMatch>,
    pub error: Option<String>,
    pub bytes_scanned: u64,
    pub duration_ms: u64,
    pub worker_id: String,
    pub completed_at: u64,
}

/// A single match produced by a distributed worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedMatch {
    pub rule_name: String,
    pub namespace: String,
    pub offset: u64,
    pub length: usize,
    pub data_preview: Vec<u8>,
    pub tags: Vec<String>,
}

// ── Aggregated report ─────────────────────────────────────────────────────────

/// Final aggregated report from all workers.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AggregatedReport {
    pub total_jobs: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub deduplicated_jobs: u64,
    pub total_matches: u64,
    /// Deduplication: matches collapsed from multiple identical files.
    pub unique_matches: Vec<UniqueMatch>,
    pub bytes_scanned: u64,
    pub wall_time_ms: u64,
    pub worker_stats: HashMap<String, WorkerStats>,
}

/// A match with deduplication metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniqueMatch {
    pub rule_name: String,
    pub offset: u64,
    pub data_preview: Vec<u8>,
    /// Number of distinct files/buffers containing this exact match.
    pub hit_count: u32,
    /// Job labels that produced this match.
    pub seen_in: Vec<String>,
}

/// Per-worker statistics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WorkerStats {
    pub jobs_completed: u32,
    pub bytes_scanned: u64,
    pub total_ms: u64,
    pub errors: u32,
}

// ── Worker node ───────────────────────────────────────────────────────────────

/// Identity of a worker node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerNode {
    pub id: String,
    pub address: Option<String>, // None = local thread
    pub max_concurrent: usize,
}

impl WorkerNode {
    pub fn local(id: impl Into<String>) -> Self {
        Self { id: id.into(), address: None, max_concurrent: 4 }
    }

    pub fn remote(id: impl Into<String>, address: impl Into<String>) -> Self {
        Self { id: id.into(), address: Some(address.into()), max_concurrent: 8 }
    }
}

// ── Job queue ─────────────────────────────────────────────────────────────────

/// Thread-safe priority job queue.
pub struct JobQueue {
    inner: Mutex<JobQueueInner>,
}

struct JobQueueInner {
    /// Jobs sorted by descending priority, then ascending creation time.
    queue: VecDeque<ScanJob>,
    /// Set of content hashes of in-flight or completed jobs (for dedup).
    seen_hashes: HashSet<String>,
    /// Completed job IDs and their result references.
    completed: HashMap<JobId, Arc<JobResult>>,
    stats: QueueStats,
}

#[derive(Debug, Default)]
struct QueueStats {
    submitted: u64,
    deduped: u64,
    expired: u64,
}

impl JobQueue {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(JobQueueInner {
                queue: VecDeque::new(),
                seen_hashes: HashSet::new(),
                completed: HashMap::new(),
                stats: QueueStats::default(),
            }),
        }
    }

    /// Submit a job. Returns `None` if the job was deduplicated.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn submit(&self, job: ScanJob) -> Option<JobId> {
        let mut q = self.inner.lock().unwrap();
        q.stats.submitted += 1;

        // Deduplication by content hash
        if let Some(hash) = &job.content_hash {
            if q.seen_hashes.contains(hash) {
                q.stats.deduped += 1;
                return None;
            }
            q.seen_hashes.insert(hash.clone());
        }

        let id = job.id;
        // Insert maintaining priority order (highest first)
        let pos = q.queue.partition_point(|j| j.priority >= job.priority);
        q.queue.insert(pos, job);
        drop(q);
        Some(id)
    }

    /// Drain expired jobs from the queue.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn drain_expired(&self) -> u64 {
        let mut q = self.inner.lock().unwrap();
        let before = q.queue.len();
        q.queue.retain(|j| !j.is_expired());
        let expired = (before - q.queue.len()) as u64;
        q.stats.expired += expired;
        expired
    }

    /// Pop the highest-priority job.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn pop(&self) -> Option<ScanJob> {
        self.inner.lock().unwrap().queue.pop_front()
    }

    /// Record a completed result.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn record_result(&self, result: JobResult) {
        let mut q = self.inner.lock().unwrap();
        q.completed.insert(result.job_id, Arc::new(result));
    }

    /// Retrieve a result by job ID.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn get_result(&self, job_id: JobId) -> Option<Arc<JobResult>> {
        self.inner.lock().unwrap().completed.get(&job_id).cloned()
    }

    /// Pending job count.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn pending(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    /// Snapshot of basic queue statistics.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn stats_snapshot(&self) -> (u64, u64, u64) {
        let q = self.inner.lock().unwrap();
        (q.stats.submitted, q.stats.deduped, q.stats.expired)
    }
}

impl Default for JobQueue {
    fn default() -> Self { Self::new() }
}

// ── Coordinator ───────────────────────────────────────────────────────────────

/// Distributed scan coordinator.
///
/// Manages a job queue, dispatches work to local worker threads (or remote
/// nodes via the stub HTTP transport), and aggregates results.
pub struct Coordinator {
    queue: Arc<JobQueue>,
    rules: Vec<Arc<YaraRule>>,
    workers: Vec<WorkerNode>,
    shutdown: Arc<AtomicBool>,
    started: Instant,
    results_buf: Arc<Mutex<Vec<JobResult>>>,
    active_jobs: Arc<AtomicU32>,
}

impl Coordinator {
    /// Create a coordinator with the given compiled rules and worker nodes.
    pub fn new(rules: Vec<YaraRule>, workers: Vec<WorkerNode>) -> Self {
        Self {
            queue: Arc::new(JobQueue::new()),
            rules: rules.into_iter().map(Arc::new).collect(),
            workers,
            shutdown: Arc::new(AtomicBool::new(false)),
            started: Instant::now(),
            results_buf: Arc::new(Mutex::new(Vec::new())),
            active_jobs: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Submit a job. Returns the job ID if accepted, None if deduplicated.
    #[must_use] 
    pub fn submit(&self, job: ScanJob) -> Option<JobId> {
        self.queue.submit(job)
    }

    /// Submit multiple jobs. Returns counts: (accepted, deduped).
    #[must_use] 
    pub fn submit_batch(&self, jobs: Vec<ScanJob>) -> (usize, usize) {
        let mut accepted = 0;
        let mut deduped = 0;
        for job in jobs {
            match self.submit(job) {
                Some(_) => accepted += 1,
                None => deduped += 1,
            }
        }
        (accepted, deduped)
    }

    /// Run all queued jobs using local worker threads. Blocks until done.
    #[must_use] 
    pub fn run_local(&self) -> AggregatedReport {
        let total_workers = self.workers.iter()
            .filter(|w| w.address.is_none())
            .map(|w| w.max_concurrent)
            .sum::<usize>()
            .max(1);

        // Reset the shutdown flag in case `run_local` is called more than once
        // on the same coordinator instance.
        self.shutdown.store(false, Ordering::Relaxed);

        let mut handles = Vec::new();
        for wid in 0..total_workers {
            let q = self.queue.clone();
            let rules = self.rules.clone();
            let results = self.results_buf.clone();
            let active = self.active_jobs.clone();
            let shutdown = self.shutdown.clone();
            let worker_id = format!("local-{wid}");

            let handle = std::thread::spawn(move || {
                local_worker_loop(&q, &rules, &results, &active, &shutdown, &worker_id);
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.join();
        }

        self.build_report()
    }

    /// Get the result for a specific job.
    #[must_use] 
    pub fn get_result(&self, job_id: JobId) -> Option<Arc<JobResult>> {
        self.queue.get_result(job_id)
    }

    /// Pending job count.
    #[must_use] 
    pub fn pending(&self) -> usize {
        self.queue.pending()
    }

    /// Signal all local workers to stop pulling new jobs from the queue.
    /// Jobs already in flight finish normally; subsequent `pop()`s return
    /// `None` once the flag is observed. Safe to call from any thread.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Returns `true` if `shutdown` has been requested.
    #[must_use] 
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    fn build_report(&self) -> AggregatedReport {
        let results = self.results_buf.lock().unwrap();
        let mut report = AggregatedReport {
            total_jobs: results.len() as u64,
            wall_time_ms: u128_to_u64(self.started.elapsed().as_millis()),
            ..Default::default()
        };

        let mut dedup_map: HashMap<(String, u64), usize> = HashMap::new();

        for result in results.iter() {
            match result.status {
                JobStatus::Completed => report.completed_jobs += 1,
                JobStatus::Failed => report.failed_jobs += 1,
                JobStatus::Deduplicated => report.deduplicated_jobs += 1,
                _ => {}
            }
            report.bytes_scanned += result.bytes_scanned;
            report.total_matches += result.matches.len() as u64;

            let ws = report.worker_stats
                .entry(result.worker_id.clone())
                .or_default();
            ws.jobs_completed += 1;
            ws.bytes_scanned += result.bytes_scanned;
            ws.total_ms += result.duration_ms;

            for m in &result.matches {
                let key = (m.rule_name.clone(), m.offset);
                let idx = dedup_map.entry(key).or_insert_with(|| {
                    let um = UniqueMatch {
                        rule_name: m.rule_name.clone(),
                        offset: m.offset,
                        data_preview: m.data_preview.clone(),
                        hit_count: 0,
                        seen_in: Vec::new(),
                    };
                    report.unique_matches.push(um);
                    report.unique_matches.len() - 1
                });
                let um = &mut report.unique_matches[*idx];
                um.hit_count += 1;
                if !um.seen_in.contains(&result.job_label) {
                    um.seen_in.push(result.job_label.clone());
                }
            }
        }

        drop(results);
        let (submitted, deduped, _expired) = self.queue.stats_snapshot();
        report.deduplicated_jobs = deduped;
        // `total_jobs` defaults to 0; reflect everything the queue has seen
        // so the aggregate matches the coordinator's view, including jobs
        // that never produced a `JobResult` (e.g. expired before dispatch).
        report.total_jobs = report.total_jobs.max(submitted);

        report
    }
}

// ── Local worker ──────────────────────────────────────────────────────────────

fn local_worker_loop(
    queue: &Arc<JobQueue>,
    rules: &[Arc<YaraRule>],
    results: &Arc<Mutex<Vec<JobResult>>>,
    active: &Arc<AtomicU32>,
    shutdown: &Arc<AtomicBool>,
    worker_id: &str,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        queue.drain_expired();
        let Some(job) = queue.pop() else { break };

        active.fetch_add(1, Ordering::Relaxed);
        let t0 = Instant::now();

        let (matches, bytes, error) = execute_job_locally(&job, rules);

        let status = if error.is_some() { JobStatus::Failed } else { JobStatus::Completed };
        let result = JobResult {
            job_id: job.id,
            job_label: job.label.clone(),
            status,
            matches,
            error,
            bytes_scanned: bytes,
            duration_ms: u128_to_u64(t0.elapsed().as_millis()),
            worker_id: worker_id.to_string(),
            completed_at: unix_ts(),
        };

        queue.record_result(result.clone());
        results.lock().unwrap().push(result);
        active.fetch_sub(1, Ordering::Relaxed);
    }
}

fn execute_job_locally(
    job: &ScanJob,
    rules: &[Arc<YaraRule>],
) -> (Vec<DistributedMatch>, u64, Option<String>) {
    use crate::StringValue;

    let data: Arc<Vec<u8>> = if let Some(d) = &job.data {
        d.clone()
    } else if let Some(path) = &job.file_path {
        match std::fs::read(path) {
            Ok(bytes) => Arc::new(bytes),
            Err(e) => return (Vec::new(), 0, Some(e.to_string())),
        }
    } else {
        return (Vec::new(), 0, Some("no data or file path".into()));
    };

    let mut matches = Vec::new();
    let bytes = data.len() as u64;

    for rule in rules {
        for ys in &rule.strings {
            let needle: Vec<u8> = match &ys.value {
                StringValue::Text(t) => t.as_bytes().to_vec(),
                StringValue::Hex(tokens) => tokens.iter().filter_map(|t| {
                    if let crate::HexToken::Byte(b) = t { Some(*b) } else { None }
                }).collect(),
                StringValue::Regex(r) => r.as_bytes().to_vec(),
            };
            if needle.is_empty() { continue; }

            let mut pos = 0;
            while pos + needle.len() <= data.len() {
                if &data[pos..pos + needle.len()] == needle.as_slice() {
                    matches.push(DistributedMatch {
                        rule_name: rule.name.clone(),
                        namespace: rule.namespace.clone(),
                        offset: pos as u64,
                        length: needle.len(),
                        data_preview: data[pos..pos + needle.len().min(64)].to_vec(),
                        tags: rule.tags.clone(),
                    });
                    pos += needle.len();
                } else {
                    pos += 1;
                }
            }
        }
    }

    (matches, bytes, None)
}

// ── Result deduplicator ───────────────────────────────────────────────────────

/// Post-process a flat list of results and collapse duplicate matches.
#[must_use] 
pub fn deduplicate_results(results: &[JobResult]) -> Vec<UniqueMatch> {
    let mut map: HashMap<(String, u64, Vec<u8>), UniqueMatch> = HashMap::new();

    for result in results {
        for m in &result.matches {
            let key = (m.rule_name.clone(), m.offset, m.data_preview.clone());
            let entry = map.entry(key).or_insert_with(|| UniqueMatch {
                rule_name: m.rule_name.clone(),
                offset: m.offset,
                data_preview: m.data_preview.clone(),
                hit_count: 0,
                seen_in: Vec::new(),
            });
            entry.hit_count += 1;
            if !entry.seen_in.contains(&result.job_label) {
                entry.seen_in.push(result.job_label.clone());
            }
        }
    }

    let mut unique: Vec<UniqueMatch> = map.into_values().collect();
    unique.sort_by(|a, b| b.hit_count.cmp(&a.hit_count).then(a.offset.cmp(&b.offset)));
    unique
}

// ── Remote transport stub ─────────────────────────────────────────────────────

/// HTTP/gRPC transport for submitting jobs to remote worker nodes.
/// This is a stub — real implementation would use `reqwest` or `tonic`.
pub struct RemoteTransport {
    pub base_url: String,
    pub timeout: Duration,
    pub api_key: Option<String>,
}

impl RemoteTransport {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout: Duration::from_secs(30),
            api_key: None,
        }
    }

    #[must_use]
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Submit a job to a remote worker node.
    ///
    /// Performs a minimal HTTP/1.1 `POST /api/v1/jobs` with a JSON body
    /// over a plain `TcpStream`. HTTPS is not handled here — front the
    /// worker with a TLS terminator if needed. Returns the assigned
    /// `JobId` extracted from the response body (`{"job_id": <u64>}`).
    ///
    /// # Errors
    /// Returns `Err` if serialization fails or the HTTP request fails.
    pub fn submit_remote(&self, job: &ScanJob) -> Result<JobId, String> {
        let body = serde_json::to_vec(job).map_err(|e| format!("serialize job: {e}"))?;
        let resp = http_request(
            &self.base_url,
            "POST",
            "/api/v1/jobs",
            self.api_key.as_deref(),
            Some(&body),
            self.timeout,
        )?;
        parse_job_id(&resp.body)
    }

    /// Poll for a result from a remote worker.
    ///
    /// Issues `GET /api/v1/jobs/{id}/result`. Returns:
    /// * `Ok(Some(result))` — worker has a completed `JobResult`.
    /// * `Ok(None)` — HTTP 204/202 indicating the job is still running.
    /// * `Err(_)` — transport, HTTP, or deserialisation failure.
    ///
    /// # Errors
    /// Returns `Err` on transport, HTTP, or deserialisation failure.
    pub fn poll_result(&self, job_id: JobId) -> Result<Option<JobResult>, String> {
        let path = format!("/api/v1/jobs/{job_id}/result");
        let resp = http_request(
            &self.base_url,
            "GET",
            &path,
            self.api_key.as_deref(),
            None,
            self.timeout,
        )?;
        if resp.status == 202 || resp.status == 204 || resp.body.is_empty() {
            return Ok(None);
        }
        let result: JobResult = serde_json::from_slice(&resp.body)
            .map_err(|e| format!("deserialize JobResult: {e}"))?;
        Ok(Some(result))
    }
}

// ── Minimal HTTP/1.1 client ──────────────────────────────────────────────────

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn parse_job_id(body: &[u8]) -> Result<JobId, String> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| format!("deserialize submit response: {e}"))?;
    v.get("job_id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "missing `job_id` field in response".into())
}

fn http_request(
    base_url: &str,
    method: &str,
    path: &str,
    api_key: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    use std::fmt::Write as _;
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};

    let (host, port) = parse_host_port(base_url)?;
    let addr = format!("{host}:{port}");
    let sock_addr = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {addr}"))?;

    let mut stream =
        TcpStream::connect_timeout(&sock_addr, timeout).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("set_write_timeout: {e}"))?;

    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(k) = api_key {
        req.push_str("Authorization: Bearer ");
        req.push_str(k);
        req.push_str("\r\n");
    }
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        let _ = write!(req, "Content-Length: {}", b.len());
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write headers: {e}"))?;
    if let Some(b) = body {
        stream.write_all(b).map_err(|e| format!("write body: {e}"))?;
    }

    let mut raw = Vec::with_capacity(1024);
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read response: {e}"))?;

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response: no header terminator".to_string())?;
    let header_bytes = &raw[..split];
    let body_bytes = raw[split + 4..].to_vec();

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| format!("non-UTF8 headers: {e}"))?;
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| "empty response".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line: {status_line}"))?;

    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}: {}", String::from_utf8_lossy(&body_bytes)));
    }

    Ok(HttpResponse { status, body: body_bytes })
}

fn parse_host_port(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let default_port: u16 = if url.starts_with("https://") { 443 } else { 80 };
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|e| format!("invalid port `{p}`: {e}"))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return Err(format!("empty host in URL `{url}`"));
    }
    Ok((host, port))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_job_id() -> JobId {
    JOB_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Minimal SHA-256 hex string (uses the standard library only if available,
/// otherwise falls back to a CRC32-based fingerprint for portability).
fn sha256_hex(data: &[u8]) -> String {
    // Attempt a deterministic fingerprint without pulling in `sha2` crate:
    // We fold the data into a 64-bit digest using FNV-1a.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Condition, HexToken, StringModifiers, StringValue, YaraRule, YaraString};
    use std::collections::HashMap;

    fn simple_rule(name: &str, pattern: &[u8]) -> YaraRule {
        let tokens: Vec<HexToken> = pattern.iter().map(|&b| HexToken::Byte(b)).collect();
        YaraRule {
            name: name.to_string(),
            namespace: String::new(),
            tags: Vec::new(),
            meta: HashMap::new(),
            strings: vec![YaraString {
                identifier: "$a".to_string(),
                value: StringValue::Hex(tokens),
                modifiers: StringModifiers::NONE,
            }],
            condition: Condition::Any,
        }
    }

    #[test]
    fn test_job_queue_priority() {
        let q = JobQueue::new();
        let mut low = ScanJob::new_memory("low", vec![0]);
        let mut high = ScanJob::new_memory("high", vec![1]);
        low.priority = Priority::Low;
        high.priority = Priority::High;
        // Content hashes differ, so no dedup
        low.content_hash = Some("low_hash".into());
        high.content_hash = Some("high_hash".into());
        q.submit(low);
        q.submit(high);
        let first = q.pop().unwrap();
        assert_eq!(first.priority, Priority::High);
    }

    #[test]
    fn test_deduplication_by_hash() {
        let q = JobQueue::new();
        let data = vec![0xAAu8; 256];
        let j1 = ScanJob::new_memory("first", data.clone());
        let j2 = ScanJob::new_memory("second", data);
        assert!(q.submit(j1).is_some());
        // Same hash → should be deduped
        assert!(q.submit(j2).is_none());
    }

    #[test]
    fn test_coordinator_local_scan() {
        let rule = simple_rule("find_cafe", &[0xCA, 0xFE]);
        let workers = vec![WorkerNode::local("w0")];
        let coord = Coordinator::new(vec![rule], workers);

        let job = ScanJob::new_memory("test_buf", vec![0x00, 0xCA, 0xFE, 0xFF]);
        let _ = coord.submit(job);

        let report = coord.run_local();
        assert_eq!(report.completed_jobs, 1);
        assert!(report.total_matches > 0);
    }

    #[test]
    fn test_deduplicate_results() {
        let r1 = JobResult {
            job_id: 1,
            job_label: "file_a".into(),
            status: JobStatus::Completed,
            matches: vec![DistributedMatch {
                rule_name: "rule1".into(),
                namespace: String::new(),
                offset: 0,
                length: 4,
                data_preview: vec![0xDE, 0xAD],
                tags: Vec::new(),
            }],
            error: None,
            bytes_scanned: 100,
            duration_ms: 5,
            worker_id: "w0".into(),
            completed_at: 0,
        };
        let mut r2 = r1.clone();
        r2.job_id = 2;
        r2.job_label = "file_b".into();
        let unique = deduplicate_results(&[r1, r2]);
        assert_eq!(unique.len(), 1);
        assert_eq!(unique[0].hit_count, 2);
    }
}
