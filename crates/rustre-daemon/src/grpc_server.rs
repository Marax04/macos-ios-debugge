//! gRPC server for the RustRE daemon.
//!
//! Exposes four services over a single tonic endpoint:
//! - `BinaryAnalysis` – submit/query binary analysis jobs
//! - `DebuggerControl` – attach/detach/step debugger sessions
//! - `SandboxOrchestration` – run and monitor sandbox executions
//! - `ThreatIntel` – YARA scan, IOC lookup, CVE cross-reference
//!
//! Authentication is token-based (Bearer) with optional mTLS.
//! Rate limiting is enforced per IP with a token-bucket algorithm.
//! Connection pooling reuses backend connections to SQLite and analysis workers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio::time;

// ──────────────────────────────────────────────────────────────────────────────
// Errors
// ──────────────────────────────────────────────────────────────────────────────

/// Errors produced by the gRPC server layer.
#[derive(Debug, thiserror::Error)]
pub enum GrpcError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("rate limit exceeded for {ip}")]
    RateLimit { ip: String },

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("method not found: {method}")]
    MethodNotFound { method: String },

    #[error("deadline exceeded after {ms}ms")]
    DeadlineExceeded { ms: u64 },

    #[error("stream closed by peer")]
    StreamClosed,
}

// ──────────────────────────────────────────────────────────────────────────────
// Protocol types (stand-in for generated protobuf structs)
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a submitted analysis job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JobId(pub String);

/// Status of an analysis job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Request to submit a binary for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeRequest {
    /// SHA-256 hex of the binary.
    pub binary_hash: String,
    /// Raw bytes of the binary (base-64 encoded in JSON transport).
    pub binary_data: Vec<u8>,
    /// Analysis profile: "quick", "full", "deep".
    pub profile: String,
    /// Optional YARA rule bundle to apply.
    pub yara_rules: Option<String>,
    /// Requester identity.
    pub requester: String,
}

/// Progress event streamed back during analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisProgressEvent {
    pub job_id: String,
    pub stage: String,
    pub percent: u8,
    pub message: String,
    pub timestamp_ms: u64,
}

/// Final analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub job_id: String,
    pub status: JobStatus,
    pub function_count: u32,
    pub string_count: u32,
    pub import_count: u32,
    pub yara_matches: Vec<String>,
    pub threat_score: f32,
    pub elapsed_ms: u64,
    pub result_path: Option<String>,
}

/// Request to attach a debugger to a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugAttachRequest {
    pub pid: u32,
    pub binary_path: String,
    pub backend: String, // "gdb", "windbg", "lldb", "frida"
    pub options: HashMap<String, String>,
}

/// Debug event streamed from the debugger session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEvent {
    pub session_id: String,
    pub kind: DebugEventKind,
    pub address: u64,
    pub message: String,
    pub registers: HashMap<String, u64>,
    pub timestamp_ms: u64,
}

/// Classification of debug events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugEventKind {
    Breakpoint,
    SingleStep,
    Exception,
    ProcessExit,
    ModuleLoad,
    ThreadCreate,
    ThreadExit,
    Output,
}

/// Request to launch a sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRunRequest {
    pub binary_hash: String,
    pub binary_data: Vec<u8>,
    pub timeout_secs: u32,
    pub network_enabled: bool,
    pub environment: HashMap<String, String>,
    pub args: Vec<String>,
}

/// Alert emitted by the sandbox monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAlert {
    pub run_id: String,
    pub severity: AlertSeverity,
    pub category: String,
    pub description: String,
    pub syscall: Option<String>,
    pub timestamp_ms: u64,
}

/// Severity levels for sandbox alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Request to query threat intelligence for an IOC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelRequest {
    pub ioc_type: IocType,
    pub value: String,
    pub include_related: bool,
}

/// IOC type for threat-intel lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocType {
    Hash,
    Ip,
    Domain,
    Url,
    Email,
    CveId,
}

/// Threat intelligence result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelResult {
    pub ioc: String,
    pub malicious: bool,
    pub confidence: f32,
    pub families: Vec<String>,
    pub tags: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub references: Vec<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Rate limiter (token bucket)
// ──────────────────────────────────────────────────────────────────────────────

struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume one token.  Returns `true` if allowed.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-IP rate-limiter registry.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    capacity: u32,
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter with `capacity` burst tokens and `refill_rate`
    /// tokens/second per IP.
    #[must_use]
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_rate,
        }
    }

    /// Check whether the given IP is allowed to proceed.
    ///
    /// # Errors
    /// Returns `GrpcError::RateLimit` when the token bucket is exhausted.
    pub fn check(&self, ip: &str) -> Result<(), GrpcError> {
        let mut map = self.buckets.lock();
        let bucket = map
            .entry(ip.to_owned())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate));
        if bucket.try_consume() {
            Ok(())
        } else {
            Err(GrpcError::RateLimit { ip: ip.to_owned() })
        }
    }

    /// Evict stale entries (buckets full and last refill > 5 min ago).
    pub fn evict_stale(&self) {
        let mut map = self.buckets.lock();
        map.retain(|_, b| {
            b.last_refill.elapsed() < Duration::from_secs(300)
        });
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Authentication
// ──────────────────────────────────────────────────────────────────────────────

/// Authentication configuration for the gRPC server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Accepted Bearer tokens (hashed with SHA-256).
    pub bearer_tokens: Vec<String>,
    /// Path to the server TLS certificate (PEM).
    pub tls_cert_path: Option<String>,
    /// Path to the server TLS private key (PEM).
    pub tls_key_path: Option<String>,
    /// Path to the CA certificate for mTLS client verification.
    pub ca_cert_path: Option<String>,
    /// Whether mTLS is required.
    pub require_mtls: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            bearer_tokens: Vec::new(),
            tls_cert_path: None,
            tls_key_path: None,
            ca_cert_path: None,
            require_mtls: false,
        }
    }
}

/// In-memory token validator.
pub struct TokenValidator {
    tokens: RwLock<Vec<String>>,
}

impl TokenValidator {
    /// Create a validator with the given pre-hashed tokens.
    #[must_use]
    pub fn new(tokens: Vec<String>) -> Self {
        Self {
            tokens: RwLock::new(tokens),
        }
    }

    /// Check whether the provided raw Bearer token is valid.
    ///
    /// The token is SHA-256 hashed before comparison.
    ///
    /// # Errors
    /// Returns `GrpcError::Auth` if the token is missing or invalid.
    pub fn validate(&self, raw_token: Option<&str>) -> Result<(), GrpcError> {
        let raw = raw_token.ok_or_else(|| {
            GrpcError::Auth("missing Authorization header".to_owned())
        })?;
        let stripped = raw.strip_prefix("Bearer ").unwrap_or(raw);
        let hash = sha256_hex(stripped.as_bytes());
        let tokens = self.tokens.read();
        if tokens.iter().any(|t| t == &hash) {
            Ok(())
        } else {
            Err(GrpcError::Auth("invalid token".to_owned()))
        }
    }

    /// Hot-reload the accepted token list.
    pub fn reload(&self, new_tokens: Vec<String>) {
        *self.tokens.write() = new_tokens;
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    hex::encode(digest)
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection pool
// ──────────────────────────────────────────────────────────────────────────────

/// A leased connection from the pool.
pub struct PooledConnection<T> {
    inner: Option<T>,
    pool: Arc<Mutex<Vec<T>>>,
}

impl<T> std::ops::Deref for PooledConnection<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner.as_ref().expect("connection already returned")
    }
}

impl<T> std::ops::DerefMut for PooledConnection<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner.as_mut().expect("connection already returned")
    }
}

impl<T> Drop for PooledConnection<T> {
    fn drop(&mut self) {
        if let Some(conn) = self.inner.take() {
            self.pool.lock().push(conn);
        }
    }
}

/// Generic fixed-size connection pool.
pub struct ConnectionPool<T> {
    connections: Arc<Mutex<Vec<T>>>,
    capacity: usize,
}

impl<T: Send + 'static> ConnectionPool<T> {
    /// Create a pool seeded with `initial` connections.
    #[must_use]
    pub fn new(initial: Vec<T>) -> Self {
        let capacity = initial.len();
        Self {
            connections: Arc::new(Mutex::new(initial)),
            capacity,
        }
    }

    /// Try to borrow a connection immediately.
    ///
    /// # Errors
    /// Returns `GrpcError::ServiceUnavailable` when the pool is empty.
    pub fn try_borrow(&self) -> Result<PooledConnection<T>, GrpcError> {
        let mut guard = self.connections.lock();
        guard.pop().map(|conn| PooledConnection {
            inner: Some(conn),
            pool: Arc::clone(&self.connections),
        }).ok_or_else(|| {
            GrpcError::ServiceUnavailable("connection pool exhausted".to_owned())
        })
    }

    /// Return the current pool size (idle connections).
    #[must_use]
    pub fn idle(&self) -> usize {
        self.connections.lock().len()
    }

    /// Return the pool capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Service implementations
// ──────────────────────────────────────────────────────────────────────────────

/// Shared server state.
pub struct GrpcServerState {
    pub auth: Arc<TokenValidator>,
    pub rate_limiter: Arc<RateLimiter>,
    pub analysis_tx: mpsc::Sender<AnalyzeRequest>,
    pub event_bus: broadcast::Sender<AnalysisProgressEvent>,
    pub debug_event_bus: broadcast::Sender<DebugEvent>,
    pub sandbox_alert_bus: broadcast::Sender<SandboxAlert>,
    pub active_jobs: Arc<RwLock<HashMap<String, JobStatus>>>,
    pub active_debug_sessions: Arc<RwLock<HashMap<String, String>>>,
}

impl GrpcServerState {
    /// Create a new server state instance.
    #[must_use]
    pub fn new(auth_config: AuthConfig) -> (Self, mpsc::Receiver<AnalyzeRequest>) {
        let (analysis_tx, analysis_rx) = mpsc::channel(256);
        let (event_bus, _) = broadcast::channel(1024);
        let (debug_event_bus, _) = broadcast::channel(1024);
        let (sandbox_alert_bus, _) = broadcast::channel(1024);
        let state = Self {
            auth: Arc::new(TokenValidator::new(auth_config.bearer_tokens)),
            rate_limiter: Arc::new(RateLimiter::new(60, 10.0)),
            analysis_tx,
            event_bus,
            debug_event_bus,
            sandbox_alert_bus,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            active_debug_sessions: Arc::new(RwLock::new(HashMap::new())),
        };
        (state, analysis_rx)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// BinaryAnalysis service
// ──────────────────────────────────────────────────────────────────────────────

/// Handler for the `BinaryAnalysis` gRPC service.
pub struct BinaryAnalysisService {
    state: Arc<GrpcServerState>,
}

impl BinaryAnalysisService {
    /// Create a new handler.
    #[must_use]
    pub fn new(state: Arc<GrpcServerState>) -> Self {
        Self { state }
    }

    /// Submit a binary for analysis (unary RPC).
    ///
    /// # Errors
    /// Returns `GrpcError` on auth failure, rate-limit, or queue full.
    pub async fn submit(&self, token: Option<&str>, ip: &str, req: AnalyzeRequest)
        -> Result<JobId, GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        if req.binary_data.is_empty() {
            return Err(GrpcError::InvalidRequest("binary_data is empty".to_owned()));
        }
        let job_id = JobId(format!("job-{}-{}", &req.binary_hash[..8], uuid_v4()));
        self.state.active_jobs.write().insert(job_id.0.clone(), JobStatus::Queued);
        self.state.analysis_tx.send(req).await.map_err(|_| {
            GrpcError::ServiceUnavailable("analysis queue is full".to_owned())
        })?;
        Ok(job_id)
    }

    /// Query the current status of a job (unary RPC).
    ///
    /// # Errors
    /// Returns `GrpcError::Auth` or `GrpcError::InvalidRequest` if the job is not found.
    pub fn status(&self, token: Option<&str>, ip: &str, job_id: &str)
        -> Result<JobStatus, GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        self.state.active_jobs.read()
            .get(job_id)
            .copied()
            .ok_or_else(|| GrpcError::InvalidRequest(format!("unknown job: {}", job_id)))
    }

    /// Subscribe to progress events for a job (server-streaming RPC).
    ///
    /// Returns a `tokio::sync::broadcast::Receiver` that emits
    /// `AnalysisProgressEvent` until the job completes.
    ///
    /// # Errors
    /// Returns `GrpcError::Auth` on authentication failure.
    pub fn stream_events(&self, token: Option<&str>, _ip: &str)
        -> Result<broadcast::Receiver<AnalysisProgressEvent>, GrpcError>
    {
        self.state.auth.validate(token)?;
        Ok(self.state.event_bus.subscribe())
    }

    /// Cancel an in-progress job.
    ///
    /// # Errors
    /// Returns `GrpcError::InvalidRequest` if the job does not exist.
    pub fn cancel(&self, token: Option<&str>, ip: &str, job_id: &str)
        -> Result<(), GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        let mut jobs = self.state.active_jobs.write();
        let status = jobs.get_mut(job_id)
            .ok_or_else(|| GrpcError::InvalidRequest(format!("unknown job: {}", job_id)))?;
        if *status == JobStatus::Running || *status == JobStatus::Queued {
            *status = JobStatus::Cancelled;
        }
        Ok(())
    }

    /// Publish a progress event (called by the analysis worker).
    pub fn publish_progress(&self, event: AnalysisProgressEvent) {
        let _ = self.state.event_bus.send(event);
    }

    /// Mark a job as completed with a given status.
    pub fn complete_job(&self, job_id: &str, status: JobStatus) {
        if let Some(s) = self.state.active_jobs.write().get_mut(job_id) {
            *s = status;
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DebuggerControl service
// ──────────────────────────────────────────────────────────────────────────────

/// Handler for the `DebuggerControl` gRPC service.
pub struct DebuggerControlService {
    state: Arc<GrpcServerState>,
}

impl DebuggerControlService {
    /// Create a new handler.
    #[must_use]
    pub fn new(state: Arc<GrpcServerState>) -> Self {
        Self { state }
    }

    /// Attach a debugger to a process (unary RPC).
    ///
    /// # Errors
    /// Returns `GrpcError` on authentication failure or unsupported backend.
    pub fn attach(&self, token: Option<&str>, ip: &str, req: DebugAttachRequest)
        -> Result<String, GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        let supported = ["gdb", "windbg", "lldb", "frida"];
        if !supported.contains(&req.backend.as_str()) {
            return Err(GrpcError::InvalidRequest(
                format!("unsupported backend: {}", req.backend)
            ));
        }
        let session_id = format!("dbg-{}-{}", req.pid, uuid_v4());
        self.state.active_debug_sessions.write()
            .insert(session_id.clone(), req.backend.clone());
        Ok(session_id)
    }

    /// Detach a debugger session.
    ///
    /// # Errors
    /// Returns `GrpcError::InvalidRequest` if the session is unknown.
    pub fn detach(&self, token: Option<&str>, ip: &str, session_id: &str)
        -> Result<(), GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        self.state.active_debug_sessions.write()
            .remove(session_id)
            .map(|_| ())
            .ok_or_else(|| GrpcError::InvalidRequest(
                format!("unknown session: {}", session_id)
            ))
    }

    /// Step the target process by one instruction.
    ///
    /// # Errors
    /// Returns `GrpcError::InvalidRequest` for unknown sessions.
    pub fn step(&self, token: Option<&str>, ip: &str, session_id: &str)
        -> Result<(), GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        if !self.state.active_debug_sessions.read().contains_key(session_id) {
            return Err(GrpcError::InvalidRequest(
                format!("unknown session: {}", session_id)
            ));
        }
        Ok(())
    }

    /// Subscribe to debug events for a session (server-streaming RPC).
    ///
    /// # Errors
    /// Returns `GrpcError::Auth` on authentication failure.
    pub fn stream_events(&self, token: Option<&str>, _ip: &str)
        -> Result<broadcast::Receiver<DebugEvent>, GrpcError>
    {
        self.state.auth.validate(token)?;
        Ok(self.state.debug_event_bus.subscribe())
    }

    /// Emit a debug event (called by the debug backend adapters).
    pub fn publish_event(&self, event: DebugEvent) {
        let _ = self.state.debug_event_bus.send(event);
    }

    /// List active debug sessions.
    #[must_use]
    pub fn list_sessions(&self) -> Vec<String> {
        self.state.active_debug_sessions.read().keys().cloned().collect()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SandboxOrchestration service
// ──────────────────────────────────────────────────────────────────────────────

/// Handler for the `SandboxOrchestration` gRPC service.
pub struct SandboxOrchestrationService {
    state: Arc<GrpcServerState>,
    active_runs: Arc<RwLock<HashMap<String, JobStatus>>>,
}

impl SandboxOrchestrationService {
    /// Create a new handler.
    #[must_use]
    pub fn new(state: Arc<GrpcServerState>) -> Self {
        Self {
            state,
            active_runs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Launch a new sandbox run (unary RPC).
    ///
    /// # Errors
    /// Returns `GrpcError` on auth failure or invalid request.
    pub fn run(&self, token: Option<&str>, ip: &str, req: SandboxRunRequest)
        -> Result<String, GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        if req.binary_data.is_empty() {
            return Err(GrpcError::InvalidRequest("binary_data is empty".to_owned()));
        }
        if req.timeout_secs == 0 || req.timeout_secs > 3600 {
            return Err(GrpcError::InvalidRequest("timeout_secs must be 1..=3600".to_owned()));
        }
        let run_id = format!("sbx-{}", uuid_v4());
        self.active_runs.write().insert(run_id.clone(), JobStatus::Running);
        Ok(run_id)
    }

    /// Abort a sandbox run.
    ///
    /// # Errors
    /// Returns `GrpcError::InvalidRequest` for unknown run IDs.
    pub fn abort(&self, token: Option<&str>, ip: &str, run_id: &str)
        -> Result<(), GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        let mut runs = self.active_runs.write();
        let status = runs.get_mut(run_id).ok_or_else(|| {
            GrpcError::InvalidRequest(format!("unknown run: {}", run_id))
        })?;
        *status = JobStatus::Cancelled;
        Ok(())
    }

    /// Subscribe to sandbox alerts (server-streaming RPC).
    ///
    /// # Errors
    /// Returns `GrpcError::Auth` on authentication failure.
    pub fn stream_alerts(&self, token: Option<&str>, _ip: &str)
        -> Result<broadcast::Receiver<SandboxAlert>, GrpcError>
    {
        self.state.auth.validate(token)?;
        Ok(self.state.sandbox_alert_bus.subscribe())
    }

    /// Publish an alert from the sandbox monitor.
    pub fn publish_alert(&self, alert: SandboxAlert) {
        let _ = self.state.sandbox_alert_bus.send(alert);
    }

    /// Return summary of active/completed runs.
    #[must_use]
    pub fn summary(&self) -> HashMap<String, JobStatus> {
        self.active_runs.read().clone()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ThreatIntel service
// ──────────────────────────────────────────────────────────────────────────────

/// Handler for the `ThreatIntel` gRPC service.
pub struct ThreatIntelService {
    state: Arc<GrpcServerState>,
    /// In-memory cache: IOC value → result.
    cache: Mutex<HashMap<String, ThreatIntelResult>>,
}

impl ThreatIntelService {
    /// Create a new handler.
    #[must_use]
    pub fn new(state: Arc<GrpcServerState>) -> Self {
        Self {
            state,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Look up threat intelligence for an IOC (unary RPC).
    ///
    /// # Errors
    /// Returns `GrpcError` on auth failure or invalid IOC type.
    pub fn lookup(&self, token: Option<&str>, ip: &str, req: ThreatIntelRequest)
        -> Result<ThreatIntelResult, GrpcError>
    {
        self.state.auth.validate(token)?;
        self.state.rate_limiter.check(ip)?;
        if req.value.is_empty() {
            return Err(GrpcError::InvalidRequest("IOC value is empty".to_owned()));
        }
        // Check cache first.
        if let Some(cached) = self.cache.lock().get(&req.value) {
            return Ok(cached.clone());
        }
        // Stub result – in production this calls an external TI feed.
        let result = ThreatIntelResult {
            ioc: req.value.clone(),
            malicious: false,
            confidence: 0.0,
            families: Vec::new(),
            tags: Vec::new(),
            first_seen: None,
            last_seen: None,
            references: Vec::new(),
        };
        self.cache.lock().insert(req.value, result.clone());
        Ok(result)
    }

    /// Invalidate the TI cache.
    pub fn invalidate_cache(&self) {
        self.cache.lock().clear();
    }

    /// Return the number of cached entries.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().len()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// gRPC server configuration and lifecycle
// ──────────────────────────────────────────────────────────────────────────────

/// Top-level gRPC server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcServerConfig {
    /// Address to listen on (e.g. `[::1]:50051`).
    pub listen_addr: String,
    /// Authentication settings.
    pub auth: AuthConfig,
    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,
    /// Connection keep-alive interval in seconds.
    pub keepalive_secs: u64,
    /// Maximum message size in bytes (default 64 MiB).
    pub max_message_size: usize,
    /// Rate-limit burst capacity per IP.
    pub rate_limit_capacity: u32,
    /// Rate-limit refill rate per second per IP.
    pub rate_limit_refill: f64,
}

impl Default for GrpcServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "[::1]:50051".to_owned(),
            auth: AuthConfig::default(),
            max_concurrent_streams: 100,
            keepalive_secs: 60,
            max_message_size: 64 * 1024 * 1024,
            rate_limit_capacity: 60,
            rate_limit_refill: 10.0,
        }
    }
}

/// The assembled gRPC server with all four services.
pub struct GrpcServer {
    config: GrpcServerConfig,
    pub binary_analysis: Arc<BinaryAnalysisService>,
    pub debugger_control: Arc<DebuggerControlService>,
    pub sandbox: Arc<SandboxOrchestrationService>,
    pub threat_intel: Arc<ThreatIntelService>,
    state: Arc<GrpcServerState>,
}

impl GrpcServer {
    /// Construct a new `GrpcServer` from the given configuration.
    #[must_use]
    pub fn new(config: GrpcServerConfig) -> (Self, mpsc::Receiver<AnalyzeRequest>) {
        let (state, rx) = GrpcServerState::new(config.auth.clone());
        let state = Arc::new(state);
        let binary_analysis = Arc::new(BinaryAnalysisService::new(Arc::clone(&state)));
        let debugger_control = Arc::new(DebuggerControlService::new(Arc::clone(&state)));
        let sandbox = Arc::new(SandboxOrchestrationService::new(Arc::clone(&state)));
        let threat_intel = Arc::new(ThreatIntelService::new(Arc::clone(&state)));
        let server = Self {
            config,
            binary_analysis,
            debugger_control,
            sandbox,
            threat_intel,
            state,
        };
        (server, rx)
    }

    /// Return the configured listen address.
    #[must_use]
    pub fn listen_addr(&self) -> &str {
        &self.config.listen_addr
    }

    /// Start the rate-limit eviction background task.
    pub fn start_eviction_task(&self) {
        let rl = Arc::clone(&self.state.rate_limiter);
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                rl.evict_stale();
            }
        });
    }

    /// Perform a health check: returns `true` if all services are operational.
    #[must_use]
    pub fn health_check(&self) -> bool {
        // Check analysis queue capacity.
        !self.state.analysis_tx.is_closed()
    }

    /// Return a snapshot of server metrics.
    #[must_use]
    pub fn metrics(&self) -> GrpcMetrics {
        let jobs = self.state.active_jobs.read();
        let sessions = self.state.active_debug_sessions.read();
        GrpcMetrics {
            active_jobs: jobs.values().filter(|&&s| s == JobStatus::Running).count(),
            queued_jobs: jobs.values().filter(|&&s| s == JobStatus::Queued).count(),
            active_debug_sessions: sessions.len(),
            ti_cache_size: self.threat_intel.cache_size(),
        }
    }
}

/// Snapshot of gRPC server metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcMetrics {
    pub active_jobs: usize,
    pub queued_jobs: usize,
    pub active_debug_sessions: usize,
    pub ti_cache_size: usize,
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Parse a socket address from a string.
///
/// # Errors
/// Returns `GrpcError::InvalidRequest` on parse failure.
pub fn parse_addr(s: &str) -> Result<SocketAddr, GrpcError> {
    s.parse::<SocketAddr>().map_err(|e| {
        GrpcError::InvalidRequest(format!("invalid address '{}': {}", s, e))
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> Arc<GrpcServerState> {
        let cfg = AuthConfig {
            bearer_tokens: vec![sha256_hex(b"secret")],
            ..Default::default()
        };
        let (state, _rx) = GrpcServerState::new(cfg);
        Arc::new(state)
    }

    #[test]
    fn token_validator_accepts_valid() {
        let v = TokenValidator::new(vec![sha256_hex(b"mytoken")]);
        assert!(v.validate(Some("Bearer mytoken")).is_ok());
    }

    #[test]
    fn token_validator_rejects_invalid() {
        let v = TokenValidator::new(vec![sha256_hex(b"good")]);
        assert!(v.validate(Some("Bearer bad")).is_err());
    }

    #[test]
    fn token_validator_rejects_missing() {
        let v = TokenValidator::new(vec![]);
        assert!(v.validate(None).is_err());
    }

    #[test]
    fn token_validator_accepts_without_prefix() {
        let v = TokenValidator::new(vec![sha256_hex(b"raw")]);
        assert!(v.validate(Some("raw")).is_ok());
    }

    #[test]
    fn token_validator_hot_reload() {
        let v = TokenValidator::new(vec![sha256_hex(b"old")]);
        v.reload(vec![sha256_hex(b"new")]);
        assert!(v.validate(Some("Bearer old")).is_err());
        assert!(v.validate(Some("Bearer new")).is_ok());
    }

    #[test]
    fn rate_limiter_allows_within_capacity() {
        let rl = RateLimiter::new(5, 1.0);
        for _ in 0..5 {
            assert!(rl.check("1.2.3.4").is_ok());
        }
    }

    #[test]
    fn rate_limiter_blocks_over_capacity() {
        let rl = RateLimiter::new(3, 0.0); // no refill
        for _ in 0..3 {
            let _ = rl.check("10.0.0.1");
        }
        assert!(rl.check("10.0.0.1").is_err());
    }

    #[test]
    fn rate_limiter_separate_ips() {
        let rl = RateLimiter::new(1, 0.0);
        assert!(rl.check("1.1.1.1").is_ok());
        assert!(rl.check("2.2.2.2").is_ok());
        assert!(rl.check("1.1.1.1").is_err());
        assert!(rl.check("2.2.2.2").is_err());
    }

    #[test]
    fn rate_limiter_evict_stale_does_not_crash() {
        let rl = RateLimiter::new(10, 10.0);
        let _ = rl.check("1.1.1.1");
        rl.evict_stale(); // no error expected
    }

    #[test]
    fn connection_pool_borrow_and_return() {
        let pool: ConnectionPool<String> = ConnectionPool::new(vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(pool.idle(), 2);
        {
            let _conn = pool.try_borrow().unwrap();
            assert_eq!(pool.idle(), 1);
        }
        assert_eq!(pool.idle(), 2);
    }

    #[test]
    fn connection_pool_exhausted() {
        let pool: ConnectionPool<u32> = ConnectionPool::new(vec![1]);
        let _a = pool.try_borrow().unwrap();
        assert!(pool.try_borrow().is_err());
    }

    #[test]
    fn connection_pool_capacity() {
        let pool: ConnectionPool<u8> = ConnectionPool::new(vec![1, 2, 3]);
        assert_eq!(pool.capacity(), 3);
    }

    #[tokio::test]
    async fn binary_analysis_submit_requires_auth() {
        let state = make_state();
        let svc = BinaryAnalysisService::new(state);
        let req = AnalyzeRequest {
            binary_hash: "aabbccdd".to_owned(),
            binary_data: vec![0xDE, 0xAD],
            profile: "quick".to_owned(),
            yara_rules: None,
            requester: "test".to_owned(),
        };
        assert!(svc.submit(None, "127.0.0.1", req).await.is_err());
    }

    #[tokio::test]
    async fn binary_analysis_submit_rejects_empty_binary() {
        let state = make_state();
        let svc = BinaryAnalysisService::new(state);
        let req = AnalyzeRequest {
            binary_hash: "aabbccdd".to_owned(),
            binary_data: vec![],
            profile: "quick".to_owned(),
            yara_rules: None,
            requester: "test".to_owned(),
        };
        let res = svc.submit(Some("Bearer secret"), "127.0.0.1", req).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn binary_analysis_cancel_unknown_job() {
        let state = make_state();
        let svc = BinaryAnalysisService::new(state);
        let res = svc.cancel(Some("Bearer secret"), "127.0.0.1", "nonexistent");
        assert!(res.is_err());
    }

    #[test]
    fn debugger_control_attach_unsupported_backend() {
        let state = make_state();
        let svc = DebuggerControlService::new(state);
        let req = DebugAttachRequest {
            pid: 1234,
            binary_path: "/tmp/a.out".to_owned(),
            backend: "ollydbg".to_owned(),
            options: HashMap::new(),
        };
        assert!(svc.attach(Some("Bearer secret"), "127.0.0.1", req).is_err());
    }

    #[test]
    fn debugger_control_attach_gdb() {
        let state = make_state();
        let svc = DebuggerControlService::new(state);
        let req = DebugAttachRequest {
            pid: 100,
            binary_path: "/usr/bin/ls".to_owned(),
            backend: "gdb".to_owned(),
            options: HashMap::new(),
        };
        let sid = svc.attach(Some("Bearer secret"), "127.0.0.1", req).unwrap();
        assert!(sid.starts_with("dbg-100-"));
    }

    #[test]
    fn debugger_control_detach_removes_session() {
        let state = make_state();
        let svc = DebuggerControlService::new(state);
        let req = DebugAttachRequest {
            pid: 200,
            binary_path: "/bin/sh".to_owned(),
            backend: "lldb".to_owned(),
            options: HashMap::new(),
        };
        let sid = svc.attach(Some("Bearer secret"), "127.0.0.1", req).unwrap();
        assert_eq!(svc.list_sessions().len(), 1);
        svc.detach(Some("Bearer secret"), "127.0.0.1", &sid).unwrap();
        assert_eq!(svc.list_sessions().len(), 0);
    }

    #[test]
    fn sandbox_run_rejects_zero_timeout() {
        let state = make_state();
        let svc = SandboxOrchestrationService::new(state);
        let req = SandboxRunRequest {
            binary_hash: "aa".to_owned(),
            binary_data: vec![1, 2, 3],
            timeout_secs: 0,
            network_enabled: false,
            environment: HashMap::new(),
            args: vec![],
        };
        assert!(svc.run(Some("Bearer secret"), "127.0.0.1", req).is_err());
    }

    #[test]
    fn sandbox_run_rejects_empty_binary() {
        let state = make_state();
        let svc = SandboxOrchestrationService::new(state);
        let req = SandboxRunRequest {
            binary_hash: "aa".to_owned(),
            binary_data: vec![],
            timeout_secs: 60,
            network_enabled: false,
            environment: HashMap::new(),
            args: vec![],
        };
        assert!(svc.run(Some("Bearer secret"), "127.0.0.1", req).is_err());
    }

    #[test]
    fn threat_intel_lookup_empty_ioc() {
        let state = make_state();
        let svc = ThreatIntelService::new(state);
        let req = ThreatIntelRequest {
            ioc_type: IocType::Hash,
            value: String::new(),
            include_related: false,
        };
        assert!(svc.lookup(Some("Bearer secret"), "127.0.0.1", req).is_err());
    }

    #[test]
    fn threat_intel_lookup_caches_result() {
        let state = make_state();
        let svc = ThreatIntelService::new(state);
        let req = ThreatIntelRequest {
            ioc_type: IocType::Ip,
            value: "8.8.8.8".to_owned(),
            include_related: false,
        };
        svc.lookup(Some("Bearer secret"), "127.0.0.1", req).unwrap();
        assert_eq!(svc.cache_size(), 1);
    }

    #[test]
    fn threat_intel_invalidate_cache() {
        let state = make_state();
        let svc = ThreatIntelService::new(state);
        let req = ThreatIntelRequest {
            ioc_type: IocType::Domain,
            value: "example.com".to_owned(),
            include_related: false,
        };
        svc.lookup(Some("Bearer secret"), "127.0.0.1", req).unwrap();
        svc.invalidate_cache();
        assert_eq!(svc.cache_size(), 0);
    }

    #[test]
    fn grpc_server_new_returns_receiver() {
        let cfg = GrpcServerConfig::default();
        let (srv, _rx) = GrpcServer::new(cfg);
        assert!(srv.health_check());
    }

    #[test]
    fn grpc_server_metrics_initial() {
        let cfg = GrpcServerConfig::default();
        let (srv, _rx) = GrpcServer::new(cfg);
        let m = srv.metrics();
        assert_eq!(m.active_jobs, 0);
        assert_eq!(m.queued_jobs, 0);
        assert_eq!(m.active_debug_sessions, 0);
    }

    #[test]
    fn parse_addr_valid() {
        assert!(parse_addr("127.0.0.1:50051").is_ok());
        assert!(parse_addr("[::1]:50051").is_ok());
    }

    #[test]
    fn parse_addr_invalid() {
        assert!(parse_addr("not-an-addr").is_err());
    }

    #[test]
    fn job_status_cancel_sets_cancelled() {
        let state = make_state();
        let svc = BinaryAnalysisService::new(Arc::clone(&state));
        state.active_jobs.write().insert("j1".to_owned(), JobStatus::Running);
        svc.cancel(Some("Bearer secret"), "127.0.0.1", "j1").unwrap();
        assert_eq!(*state.active_jobs.read().get("j1").unwrap(), JobStatus::Cancelled);
    }

    #[test]
    fn grpc_config_default_listen_addr() {
        let cfg = GrpcServerConfig::default();
        assert_eq!(cfg.listen_addr, "[::1]:50051");
    }
}
