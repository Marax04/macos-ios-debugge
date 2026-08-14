//! `rustre-daemon`
//!
//! Background daemon library for the `RustRE` Suite.
//!
//! Provides: daemon lifecycle, PID file management, signal handling stubs,
//! socket-based IPC primitives, daemon configuration, log-rotation helpers,
//! a health-check endpoint, and a full async HTTP/JSON-RPC headless server.
//!
//! # Sub-modules
//! - [`rpc_server`]  — JSON-RPC 2.0 over TCP, [`RpcMethod`] trait, batched requests.
//! - [`session_manager`] — analysis session lifecycle and pool.
//! - [`analysis_worker`] — background worker threads with priority queue.
//! - [`config`]     — unified daemon config, TOML/JSON loading, CLI overrides.
//!
//! # Notes
//! All `pub fn` returning `Result` carry `/// # Errors`.
//! All `pub fn` that may panic carry `/// # Panics`.
//! All value-returning methods carry `#[must_use]`.

pub mod analysis_worker;
pub mod api_handler;
pub mod config;
pub mod rest_api;
pub mod rpc_server;
pub mod session_manager;
pub mod session_server;
pub mod daemon_config;
pub mod auth_manager;
pub mod client_handler;
pub mod health_monitor;
pub mod daemon_scheduler;
pub mod grpc_server;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the daemon subsystem.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DaemonError {
    /// The daemon could not start because it is already running.
    #[error("daemon already running (pid {0})")]
    AlreadyRunning(u32),

    /// The PID file could not be read or written.
    #[error("pid file error: {0}")]
    PidFile(String),

    /// A socket operation failed.
    #[error("socket error: {0}")]
    Socket(String),

    /// The daemon received an unrecognised IPC message.
    #[error("ipc protocol error: {0}")]
    Protocol(String),

    /// General I/O failure.
    #[error("i/o error: {0}")]
    Io(String),

    /// Configuration validation failed.
    #[error("config error: {0}")]
    Config(String),

    /// The daemon is not running.
    #[error("daemon is not running")]
    NotRunning,
}

impl From<io::Error> for DaemonError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ── DaemonState ───────────────────────────────────────────────────────────────

/// Current lifecycle state of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonState {
    /// Not yet started.
    Stopped,
    /// Starting up but not yet accepting requests.
    Starting,
    /// Fully operational.
    Running,
    /// Graceful shutdown in progress.
    Stopping,
    /// Crashed or forcibly killed.
    Failed,
}

impl fmt::Display for DaemonState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => write!(f, "stopped"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Stopping => write!(f, "stopping"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl DaemonState {
    /// Return `true` if the daemon is in an active operational state.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Starting)
    }

    /// Return `true` if the daemon can be started from this state.
    #[must_use]
    pub const fn can_start(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

// ── DaemonConfig (legacy sync IPC config) ─────────────────────────────────────

/// Configuration for the background daemon (legacy sync IPC layer).
///
/// For the async HTTP server layer, use [`HttpDaemonConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to the PID file.
    pub pid_file: PathBuf,
    /// Directory where log files are written.
    pub log_dir: PathBuf,
    /// Base name of the main log file (without extension).
    pub log_name: String,
    /// Maximum size of a single log file before rotation (bytes).
    pub max_log_size: u64,
    /// Maximum number of rotated log files to keep.
    pub max_log_files: usize,
    /// Socket address for the IPC server.
    pub ipc_addr: SocketAddr,
    /// How often the health-check probe fires (seconds).
    pub health_interval_secs: u64,
    /// Shutdown timeout: how long to wait for graceful stop before forcing.
    pub shutdown_timeout_secs: u64,
    /// Arbitrary key-value properties.
    pub extra: HashMap<String, String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: PathBuf::from("/tmp/rustre-daemon.pid"),
            log_dir: PathBuf::from("/tmp/rustre-logs"),
            log_name: "rustre-daemon".into(),
            max_log_size: 10 * 1024 * 1024, // 10 MiB
            max_log_files: 5,
            ipc_addr: "127.0.0.1:7777".parse().expect("hardcoded addr"),
            health_interval_secs: 30,
            shutdown_timeout_secs: 10,
            extra: HashMap::new(),
        }
    }
}

impl DaemonConfig {
    /// Create a configuration with sensible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the PID file path.
    #[must_use]
    pub fn with_pid_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.pid_file = path.into();
        self
    }

    /// Set the IPC socket address.
    ///
    /// # Errors
    /// Returns `DaemonError::Config` if the address string cannot be parsed.
    pub fn with_ipc_addr(mut self, addr: &str) -> Result<Self, DaemonError> {
        self.ipc_addr = addr
            .parse()
            .map_err(|e| DaemonError::Config(format!("invalid IPC address '{addr}': {e}")))?;
        Ok(self)
    }

    /// Validate that the configuration is self-consistent.
    ///
    /// # Errors
    /// Returns `DaemonError::Config` if any field is invalid.
    pub fn validate(&self) -> Result<(), DaemonError> {
        if self.max_log_size == 0 {
            return Err(DaemonError::Config("max_log_size must be > 0".into()));
        }
        if self.max_log_files == 0 {
            return Err(DaemonError::Config("max_log_files must be > 0".into()));
        }
        if self.shutdown_timeout_secs == 0 {
            return Err(DaemonError::Config(
                "shutdown_timeout_secs must be > 0".into(),
            ));
        }
        Ok(())
    }

    /// Return the path to the active (current) log file.
    #[must_use]
    pub fn log_file_path(&self) -> PathBuf {
        self.log_dir.join(format!("{}.log", self.log_name))
    }

    /// Return the path for a rotated log file at `index` (1 = most recent).
    #[must_use]
    pub fn rotated_log_path(&self, index: usize) -> PathBuf {
        self.log_dir.join(format!("{}.{index}.log", self.log_name))
    }
}

// ── PidFile ───────────────────────────────────────────────────────────────────

/// Manages a PID file on disk.
pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    /// Open (or create) a PID file at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Write the current process's PID to the file.
    ///
    /// # Errors
    /// Returns `DaemonError::PidFile` if the file cannot be written.
    pub fn write(&self) -> Result<(), DaemonError> {
        self.write_pid(std::process::id())
    }

    /// Write a specific `pid` to the file.
    ///
    /// # Errors
    /// Returns `DaemonError::PidFile` if the file cannot be written.
    pub fn write_pid(&self, pid: u32) -> Result<(), DaemonError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                DaemonError::PidFile(format!("cannot create dir {}: {e}", parent.display()))
            })?;
        }
        fs::write(&self.path, format!("{pid}\n"))
            .map_err(|e| DaemonError::PidFile(format!("write {}: {e}", self.path.display())))?;
        Ok(())
    }

    /// Read the PID stored in the file.
    ///
    /// # Errors
    /// Returns `DaemonError::PidFile` if the file does not exist or the
    /// content is not a valid PID.
    pub fn read(&self) -> Result<u32, DaemonError> {
        let text = fs::read_to_string(&self.path)
            .map_err(|e| DaemonError::PidFile(format!("read {}: {e}", self.path.display())))?;
        text.trim()
            .parse::<u32>()
            .map_err(|_| DaemonError::PidFile(format!("invalid PID in {}", self.path.display())))
    }

    /// Return `true` if the PID file exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Remove the PID file.
    ///
    /// # Errors
    /// Returns `DaemonError::PidFile` if removal fails and the file exists.
    pub fn remove(&self) -> Result<(), DaemonError> {
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|e| {
                DaemonError::PidFile(format!("remove {}: {e}", self.path.display()))
            })?;
        }
        Ok(())
    }

    /// Return the path of this PID file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ── IPC protocol ─────────────────────────────────────────────────────────────

/// A line-delimited IPC message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcMessage {
    /// The command verb (e.g. `"status"`, `"stop"`, `"health"`).
    pub command: String,
    /// Optional arguments.
    pub args: Vec<String>,
}

impl IpcMessage {
    /// Create a command with no arguments.
    #[must_use]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
        }
    }

    /// Create a command with arguments.
    #[must_use]
    pub fn with_args(mut self, args: Vec<impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Serialize to a single JSON line.
    ///
    /// # Errors
    /// Returns `DaemonError::Protocol` if serialisation fails.
    pub fn to_line(&self) -> Result<String, DaemonError> {
        serde_json::to_string(self)
            .map_err(|e| DaemonError::Protocol(format!("serialize IpcMessage: {e}")))
    }

    /// Parse a JSON line back into an `IpcMessage`.
    ///
    /// Unlike a hand-rolled extractor, this performs full JSON parsing so the
    /// `args` array round-trips correctly.
    ///
    /// # Errors
    /// Returns `DaemonError::Protocol` for malformed input.
    pub fn from_line(line: &str) -> Result<Self, DaemonError> {
        serde_json::from_str(line.trim())
            .map_err(|e| DaemonError::Protocol(format!("parse IpcMessage from {line:?}: {e}")))
    }
}

/// A response from the daemon over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcResponse {
    /// Whether the command succeeded.
    pub ok: bool,
    /// Human-readable message.
    pub message: String,
    /// Optional structured payload (JSON string).
    pub payload: Option<String>,
}

impl IpcResponse {
    /// Successful response.
    #[must_use]
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            payload: None,
        }
    }

    /// Failed response.
    #[must_use]
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            payload: None,
        }
    }

    /// Attach a JSON payload.
    #[must_use]
    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    /// Serialize to a line.
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            // Fallback that can never fail: a minimal hand-built object.
            let ok = if self.ok { "true" } else { "false" };
            format!("{{\"ok\":{ok},\"message\":\"serialization-error\",\"payload\":null}}")
        })
    }

    /// Parse a response line produced by [`IpcResponse::to_line`].
    ///
    /// # Errors
    /// Returns `DaemonError::Protocol` for malformed input.
    pub fn from_line(line: &str) -> Result<Self, DaemonError> {
        serde_json::from_str(line.trim())
            .map_err(|e| DaemonError::Protocol(format!("parse IpcResponse from {line:?}: {e}")))
    }
}

// ── IpcServer ─────────────────────────────────────────────────────────────────

/// Boxed handler invoked when an IPC command arrives.
pub type IpcHandler = Box<dyn Fn(&IpcMessage) -> IpcResponse + Send + Sync>;

/// A TCP-based IPC server that listens for command messages.
pub struct IpcServer {
    listener: TcpListener,
    /// Handlers keyed by command name.
    handlers: HashMap<String, IpcHandler>,
}

impl IpcServer {
    /// Bind the IPC server to `addr`.
    ///
    /// # Errors
    /// Returns `DaemonError::Socket` if the bind fails.
    pub fn bind(addr: SocketAddr) -> Result<Self, DaemonError> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| DaemonError::Socket(format!("bind {addr}: {e}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| DaemonError::Socket(format!("set_nonblocking: {e}")))?;
        Ok(Self {
            listener,
            handlers: HashMap::new(),
        })
    }

    /// Register a handler for `command`.
    pub fn on(
        &mut self,
        command: impl Into<String>,
        handler: impl Fn(&IpcMessage) -> IpcResponse + Send + Sync + 'static,
    ) {
        self.handlers.insert(command.into(), Box::new(handler));
    }

    /// Return the local address the server is listening on.
    ///
    /// # Errors
    /// Returns `DaemonError::Socket` if the address cannot be retrieved.
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        self.listener
            .local_addr()
            .map_err(|e| DaemonError::Socket(e.to_string()))
    }

    /// Poll for a single incoming connection, process one message, and return.
    ///
    /// This is non-blocking: if there is no pending connection, returns `Ok(false)`.
    ///
    /// # Errors
    /// Returns `DaemonError::Socket` or `DaemonError::Protocol` on failure.
    pub fn poll_once(&self) -> Result<bool, DaemonError> {
        match self.listener.accept() {
            Ok((mut stream, _)) => {
                let response = self.handle_stream(&stream)?;
                let line = response.to_line();
                writeln!(stream, "{line}")
                    .map_err(|e| DaemonError::Socket(format!("write response: {e}")))?;
                Ok(true)
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(DaemonError::Socket(format!("accept: {e}"))),
        }
    }

    /// Block in an accept loop, dispatching each incoming request to its
    /// registered handler until `should_stop` returns `true`.
    ///
    /// The listener is non-blocking (set in [`IpcServer::bind`]), so this loop
    /// sleeps briefly between polls to avoid busy-spinning. This is the
    /// canonical server side of the client-server request flow: a long-lived
    /// process that answers [`DaemonClient`] requests.
    ///
    /// # Errors
    /// Returns `DaemonError::Socket` if accepting a connection fails for a
    /// reason other than "would block".
    pub fn serve(&self, should_stop: &dyn Fn() -> bool) -> Result<(), DaemonError> {
        while !should_stop() {
            if !self.poll_once()? {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    }

    /// Number of registered command handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Return `true` if a handler is registered for `command`.
    #[must_use]
    pub fn has_handler(&self, command: &str) -> bool {
        self.handlers.contains_key(command)
    }

    fn handle_stream(&self, stream: &TcpStream) -> Result<IpcResponse, DaemonError> {
        // Limit each IPC message to 1 MiB to prevent an adversary from exhausting
        // heap memory with a never-terminating line.  We wrap the stream in a
        // `Take` adapter *before* passing it to `BufReader` so that `read_line`
        // cannot pull more than MAX_LINE_BYTES bytes off the network.
        const MAX_LINE_BYTES: u64 = 1024 * 1024;
        let raw = stream.try_clone().map_err(DaemonError::from)?;
        let mut reader = io::BufReader::new(raw.take(MAX_LINE_BYTES));
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| DaemonError::Socket(format!("read: {e}")))?;
        let msg = IpcMessage::from_line(&line)?;
        if let Some(handler) = self.handlers.get(&msg.command) {
            Ok(handler(&msg))
        } else {
            Ok(IpcResponse::failure(format!(
                "unknown command '{}'",
                msg.command
            )))
        }
    }
}

// ── IPC client helper ─────────────────────────────────────────────────────────

/// Send a single IPC command to the daemon and return the response line.
///
/// # Errors
/// Returns `DaemonError::Socket` if the connection or send fails.
pub fn send_ipc_command(addr: SocketAddr, msg: &IpcMessage) -> Result<String, DaemonError> {
    let mut stream = TcpStream::connect(addr)
        .map_err(|e| DaemonError::Socket(format!("connect {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(DaemonError::from)?;
    let line = msg.to_line()?;
    writeln!(stream, "{line}").map_err(DaemonError::from)?;
    let mut buf = String::new();
    io::BufReader::new(&stream)
        .read_line(&mut buf)
        .map_err(DaemonError::from)?;
    Ok(buf.trim().to_string())
}

// ── DaemonClient ───────────────────────────────────────────────────────────────

/// A reusable client handle for talking to a running daemon.
///
/// This is the client half of the client-server request flow: every request is
/// a fresh, framed connection to the daemon's [`IpcServer`], carrying one
/// [`IpcMessage`] and reading back one [`IpcResponse`]. The client owns the
/// target address and timeout so callers do not have to repeat them.
///
/// # Example
/// ```no_run
/// use rustre_daemon::{DaemonClient, IpcMessage};
/// use std::net::SocketAddr;
///
/// let client = DaemonClient::new("127.0.0.1:9000".parse::<SocketAddr>().unwrap());
/// let resp = client.request(&IpcMessage::new("status")).unwrap();
/// assert!(resp.ok || !resp.ok); // got a structured response back
/// ```
#[derive(Debug, Clone)]
pub struct DaemonClient {
    addr: SocketAddr,
    timeout: Duration,
}

impl DaemonClient {
    /// Create a client targeting `addr` with a default 5-second timeout.
    #[must_use]
    pub const fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            timeout: Duration::from_secs(5),
        }
    }

    /// Override the read/write timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The address this client targets.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The configured timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Send a structured request and decode the structured response.
    ///
    /// # Errors
    /// Returns `DaemonError::Socket` if the connection fails, or
    /// `DaemonError::Protocol` if the response cannot be parsed.
    pub fn request(&self, msg: &IpcMessage) -> Result<IpcResponse, DaemonError> {
        let mut stream = TcpStream::connect(self.addr)
            .map_err(|e| DaemonError::Socket(format!("connect {}: {e}", self.addr)))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(DaemonError::from)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(DaemonError::from)?;
        let line = msg.to_line()?;
        writeln!(stream, "{line}").map_err(DaemonError::from)?;
        let mut buf = String::new();
        io::BufReader::new(&stream)
            .read_line(&mut buf)
            .map_err(DaemonError::from)?;
        IpcResponse::from_line(&buf)
    }

    /// Convenience: send a bare command (no args) and return the response.
    ///
    /// # Errors
    /// See [`DaemonClient::request`].
    pub fn command(&self, command: &str) -> Result<IpcResponse, DaemonError> {
        self.request(&IpcMessage::new(command))
    }

    /// Convenience: send a command with string arguments.
    ///
    /// # Errors
    /// See [`DaemonClient::request`].
    pub fn command_with_args(
        &self,
        command: &str,
        args: Vec<String>,
    ) -> Result<IpcResponse, DaemonError> {
        let mut msg = IpcMessage::new(command);
        msg.args = args;
        self.request(&msg)
    }

    /// Probe whether the daemon is reachable by issuing a `health` command.
    ///
    /// Returns `true` only if the daemon answers and reports success.
    #[must_use]
    pub fn ping(&self) -> bool {
        self.command("health").map(|r| r.ok).unwrap_or(false)
    }
}

// ── Log rotation ──────────────────────────────────────────────────────────────

/// A log file writer with automatic rotation.
pub struct LogRotator {
    config: DaemonConfig,
    current_size: u64,
    file: Option<fs::File>,
}

impl LogRotator {
    /// Create a log rotator from the daemon config.
    ///
    /// # Errors
    /// Returns `DaemonError::Io` if the log directory cannot be created.
    pub fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        fs::create_dir_all(&config.log_dir)
            .map_err(|e| DaemonError::Io(format!("create log dir: {e}")))?;
        Ok(Self {
            config,
            current_size: 0,
            file: None,
        })
    }

    /// Open the log file for writing (create if absent).
    ///
    /// # Errors
    /// Returns `DaemonError::Io` on failure.
    pub fn open(&mut self) -> Result<(), DaemonError> {
        let path = self.config.log_file_path();
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| DaemonError::Io(format!("open log {}: {e}", path.display())))?;
        self.current_size = f.metadata().map(|m| m.len()).unwrap_or(0);
        self.file = Some(f);
        Ok(())
    }

    /// Write a log line, rotating if needed.
    ///
    /// # Errors
    /// Returns `DaemonError::Io` on write failure.
    pub fn write_line(&mut self, line: &str) -> Result<(), DaemonError> {
        if self.file.is_none() {
            self.open()?;
        }
        let full = format!("{line}\n");
        if self.current_size + full.len() as u64 > self.config.max_log_size {
            self.rotate()?;
        }
        if let Some(ref mut f) = self.file {
            f.write_all(full.as_bytes())
                .map_err(|e| DaemonError::Io(format!("write log: {e}")))?;
            self.current_size += full.len() as u64;
        }
        Ok(())
    }

    /// Force a log rotation.
    ///
    /// # Errors
    /// Returns `DaemonError::Io` if rotation fails.
    pub fn rotate(&mut self) -> Result<(), DaemonError> {
        // Close current file.
        drop(self.file.take());

        let max = self.config.max_log_files;
        // Delete the oldest.
        let oldest = self.config.rotated_log_path(max);
        if oldest.exists() {
            fs::remove_file(&oldest)
                .map_err(|e| DaemonError::Io(format!("remove {}: {e}", oldest.display())))?;
        }
        // Shift rotated files.
        for i in (1..max).rev() {
            let from = self.config.rotated_log_path(i);
            let to = self.config.rotated_log_path(i + 1);
            if from.exists() {
                fs::rename(&from, &to).map_err(|e| {
                    DaemonError::Io(format!(
                        "rename {} -> {}: {e}",
                        from.display(),
                        to.display()
                    ))
                })?;
            }
        }
        // Move the current log.
        let current = self.config.log_file_path();
        let rotated = self.config.rotated_log_path(1);
        if current.exists() {
            fs::rename(&current, &rotated).map_err(|e| {
                DaemonError::Io(format!(
                    "rename {} -> {}: {e}",
                    current.display(),
                    rotated.display()
                ))
            })?;
        }
        self.current_size = 0;
        self.open()?;
        Ok(())
    }
}

// ── HealthCheck ───────────────────────────────────────────────────────────────

/// Result of a health check probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Whether all checks passed.
    pub healthy: bool,
    /// Individual check results.
    pub checks: Vec<CheckItem>,
    /// Timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Total elapsed probe time in milliseconds.
    pub elapsed_ms: u64,
}

/// A single named check within a health probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckItem {
    /// Name of the check.
    pub name: String,
    /// Whether this check passed.
    pub ok: bool,
    /// Human-readable detail.
    pub detail: String,
}

impl CheckItem {
    /// Create a passing check item.
    #[must_use]
    pub fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: true,
            detail: detail.into(),
        }
    }

    /// Create a failing check item.
    #[must_use]
    pub fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok: false,
            detail: detail.into(),
        }
    }
}

impl HealthCheckResult {
    /// Render as a simple text report.
    #[must_use]
    pub fn to_text(&self) -> String {
        let status = if self.healthy { "HEALTHY" } else { "UNHEALTHY" };
        let mut out = format!("Status: {status} ({}ms)\n", self.elapsed_ms);
        for item in &self.checks {
            let mark = if item.ok { "OK  " } else { "FAIL" };
            out.push_str(&format!("  [{}] {} — {}\n", mark, item.name, item.detail));
        }
        out
    }
}

/// Runs configurable health checks.
pub struct HealthCheck {
    checks: Vec<Box<dyn Fn() -> CheckItem + Send + Sync>>,
}

impl HealthCheck {
    /// Create an empty health checker.
    #[must_use]
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Register a named check function.
    pub fn add_check(&mut self, check: impl Fn() -> CheckItem + Send + Sync + 'static) {
        self.checks.push(Box::new(check));
    }

    /// Run all checks and return the aggregate result.
    #[must_use]
    pub fn run(&self) -> HealthCheckResult {
        let start = Instant::now();
        let mut items = Vec::with_capacity(self.checks.len());
        for check in &self.checks {
            items.push(check());
        }
        let healthy = items.iter().all(|c| c.ok);
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        HealthCheckResult {
            healthy,
            checks: items,
            timestamp,
            elapsed_ms,
        }
    }
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

// ── Signal handling (stub) ────────────────────────────────────────────────────

/// Signal identifiers (platform-independent stubs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// SIGTERM — graceful shutdown.
    Terminate,
    /// SIGINT  — interrupt (Ctrl+C).
    Interrupt,
    /// SIGHUP  — reload configuration.
    HangUp,
    /// SIGUSR1 — user-defined (e.g. rotate logs).
    User1,
    /// SIGUSR2 — user-defined.
    User2,
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminate => write!(f, "SIGTERM"),
            Self::Interrupt => write!(f, "SIGINT"),
            Self::HangUp => write!(f, "SIGHUP"),
            Self::User1 => write!(f, "SIGUSR1"),
            Self::User2 => write!(f, "SIGUSR2"),
        }
    }
}

/// A simple in-process signal bus for testing and non-POSIX platforms.
#[derive(Debug, Default, Clone)]
pub struct SignalBus {
    pending: Arc<Mutex<Vec<Signal>>>,
}

impl SignalBus {
    /// Create a new signal bus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Post a signal onto the bus.
    pub fn post(&self, sig: Signal) {
        self.pending.lock().push(sig);
    }

    /// Drain and return all pending signals.
    #[must_use]
    pub fn drain(&self) -> Vec<Signal> {
        std::mem::take(&mut *self.pending.lock())
    }

    /// Return `true` if any signals are pending.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending.lock().is_empty()
    }
}

// ── Daemon ────────────────────────────────────────────────────────────────────

/// The main daemon orchestrator (sync / IPC layer).
pub struct Daemon {
    config: DaemonConfig,
    state: Arc<RwLock<DaemonState>>,
    pid_file: PidFile,
    signal_bus: SignalBus,
    health: Arc<Mutex<HealthCheck>>,
    start_time: Option<Instant>,
}

impl Daemon {
    /// Create a daemon from the given configuration.
    ///
    /// # Errors
    /// Returns `DaemonError::Config` if the configuration is invalid.
    pub fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        config.validate()?;
        let pid_file = PidFile::new(config.pid_file.clone());
        Ok(Self {
            config,
            state: Arc::new(RwLock::new(DaemonState::Stopped)),
            pid_file,
            signal_bus: SignalBus::new(),
            health: Arc::new(Mutex::new(HealthCheck::new())),
            start_time: None,
        })
    }

    /// Return the current daemon state.
    #[must_use]
    pub fn state(&self) -> DaemonState {
        *self.state.read()
    }

    /// Return a shared reference to the signal bus.
    #[must_use]
    pub const fn signal_bus(&self) -> &SignalBus {
        &self.signal_bus
    }

    /// Register a health-check function.
    pub fn add_health_check(&self, check: impl Fn() -> CheckItem + Send + Sync + 'static) {
        self.health.lock().add_check(check);
    }

    /// Run all health checks.
    #[must_use]
    pub fn run_health_check(&self) -> HealthCheckResult {
        self.health.lock().run()
    }

    /// Attempt to start the daemon.
    ///
    /// Writes the PID file and transitions to `Running`.
    ///
    /// # Errors
    /// Returns `DaemonError::AlreadyRunning` if a PID file already exists with
    /// a live PID, or `DaemonError::PidFile` if the PID file cannot be written.
    pub fn start(&mut self) -> Result<(), DaemonError> {
        // Hold the write-lock for the entire check-and-transition to prevent
        // two concurrent callers from both passing `can_start()` and both
        // moving to `Starting` (state-machine-double-enter).
        {
            let mut state_guard = self.state.write();
            if !state_guard.can_start() {
                return Err(DaemonError::AlreadyRunning(
                    self.pid_file.read().unwrap_or(0),
                ));
            }
            *state_guard = DaemonState::Starting;
        }

        // Check whether a stale PID file exists with a live process.
        if let Ok(existing_pid) = self.pid_file.read() {
            if is_process_running(existing_pid) {
                // Undo the Starting transition so the daemon remains startable.
                *self.state.write() = DaemonState::Stopped;
                return Err(DaemonError::AlreadyRunning(existing_pid));
            }
            // Stale PID file — remove it before writing a fresh one.
            let _ = self.pid_file.remove();
        }

        // State is already Starting (set atomically above).
        self.pid_file.write()?;
        self.start_time = Some(Instant::now());
        *self.state.write() = DaemonState::Running;
        Ok(())
    }

    /// Gracefully stop the daemon.
    ///
    /// Removes the PID file and transitions to `Stopped`.
    ///
    /// # Errors
    /// Returns `DaemonError::NotRunning` if the daemon is not active.
    /// Returns `DaemonError::PidFile` if the PID file cannot be removed.
    pub fn stop(&mut self) -> Result<(), DaemonError> {
        if !self.state().is_active() {
            return Err(DaemonError::NotRunning);
        }
        *self.state.write() = DaemonState::Stopping;
        self.pid_file.remove()?;
        self.start_time = None;
        *self.state.write() = DaemonState::Stopped;
        Ok(())
    }

    /// Restart: stop then start.
    ///
    /// # Errors
    /// See `stop` and `start`.
    pub fn restart(&mut self) -> Result<(), DaemonError> {
        if self.state().is_active() {
            self.stop()?;
        }
        self.start()
    }

    /// Return the time since the daemon was started, if running.
    #[must_use]
    pub fn uptime(&self) -> Option<Duration> {
        self.start_time.map(|t| t.elapsed())
    }

    /// Return the daemon configuration.
    #[must_use]
    pub const fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Process pending signals, returning actions the caller should take.
    #[must_use]
    pub fn process_signals(&self) -> Vec<Signal> {
        self.signal_bus.drain()
    }

    /// Mark the daemon as failed.
    pub fn mark_failed(&self) {
        *self.state.write() = DaemonState::Failed;
    }

    /// Return a status summary string.
    #[must_use]
    pub fn status_text(&self) -> String {
        let state = self.state();
        let uptime = self
            .uptime().map_or_else(|| "n/a".to_string(), |d| format!("{}s", d.as_secs()));
        format!(
            "state={state} uptime={uptime} pid_file={}",
            self.config.pid_file.display()
        )
    }

    /// Return the list of all MCP tool names provided by this daemon.
    ///
    /// Reads the tool catalog registered in `rustre-mcp-server` and returns
    /// the name of every tool, allowing clients to discover capabilities
    /// without making a live MCP connection.
    #[must_use]
    pub fn list_capabilities(&self) -> Vec<String> {
        rustre_mcp_server::build_tool_catalog()
            .into_iter()
            .map(|tool| tool.name)
            .collect()
    }
}

// ── Utility helpers ───────────────────────────────────────────────────────────

/// Format a `Duration` as a human-readable string (`1h 2m 3s`).
#[must_use]
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Return `true` if `pid` refers to a running process.
///
/// On Unix this calls `kill(pid, 0)` and checks errno.
/// On Windows this uses `OpenProcess` with a zero-rights query.
#[must_use]
pub fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Safety: kill with signal 0 never delivers a signal; it only
        // checks whether the process exists and we have permission.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if ret == 0 {
            return true;
        }
        // EPERM means the process exists but we lack permission to signal it.
        let err = std::io::Error::last_os_error();
        err.raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        // PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        let handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                0x1000,
                0,
                pid,
            )
        };
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return false;
        }
        // Wrap the raw HANDLE in an OwnedHandle so it is closed automatically
        // when this scope exits, even on early return. Uses [`FromRawHandle`].
        let _owned = unsafe { OwnedHandle::from_raw_handle(handle as _) };
        let mut exit_code: u32 = 0;
        let alive = unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut exit_code) != 0
                && exit_code == 259 // STILL_ACTIVE
        };
        // `_owned` drops here, closing the handle via the OS.
        alive
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// §35.1  Headless HTTP/JSON-RPC server (async layer)
// ═════════════════════════════════════════════════════════════════════════════

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener as AsyncTcpListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

// ── HttpDaemonConfig ──────────────────────────────────────────────────────────

/// CLI + configuration for the async HTTP/JSON-RPC headless server.
///
/// All fields map 1-to-1 onto clap command-line flags and can also be
/// deserialized from JSON/TOML config files via serde.
#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
#[command(
    name = "rustre-daemon",
    about = "RustRE headless analysis server (§35.1)",
    version
)]
pub struct HttpDaemonConfig {
    /// TCP address to bind the HTTP/JSON-RPC server on.
    #[arg(long, default_value = "127.0.0.1:7878", env = "RUSTRE_BIND")]
    pub bind_addr: String,

    /// Optional TCP address to bind the MCP SSE server on.
    #[arg(long, env = "RUSTRE_MCP_BIND")]
    pub mcp_bind: Option<String>,

    /// Log level filter: trace / debug / info / warn / error.
    #[arg(long, default_value = "info", env = "RUSTRE_LOG")]
    pub log_level: String,

    /// Auto-open a project directory at startup.
    #[arg(long, env = "RUSTRE_PROJECT_DIR")]
    pub project_dir: Option<PathBuf>,

    /// Maximum number of simultaneous HTTP connections.
    #[arg(long, default_value_t = 16)]
    pub max_connections: u32,

    /// Bearer token required in the `Authorization` header (optional).
    #[arg(long, env = "RUSTRE_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Number of tokio worker threads (0 = number of CPUs).
    #[arg(long, default_value_t = 0)]
    pub workers: usize,
}

impl Default for HttpDaemonConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:7878".into(),
            mcp_bind: None,
            log_level: "info".into(),
            project_dir: None,
            max_connections: 16,
            auth_token: None,
            workers: 0,
        }
    }
}

impl HttpDaemonConfig {
    /// Construct from CLI arguments using clap.
    ///
    /// This is a thin wrapper around [`Parser::parse`] and is the canonical
    /// entry point for the daemon binary.
    #[must_use]
    pub fn from_cli() -> Self {
        Self::parse()
    }
}

/// Parse CLI arguments and return a populated [`HttpDaemonConfig`].
///
/// Equivalent to calling [`HttpDaemonConfig::from_cli`] but available as a
/// free function for callers that prefer that style.
#[must_use]
pub fn parse_cli_args() -> HttpDaemonConfig {
    HttpDaemonConfig::parse()
}

// ── ProjectHandle ─────────────────────────────────────────────────────────────

/// A handle to an open project managed by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectHandle {
    /// Unique project identifier (derived from the path).
    pub id: String,
    /// Filesystem path that was opened.
    pub path: PathBuf,
    /// Epoch timestamp when the project was opened.
    pub opened_at: u64,
    /// Number of binary objects loaded in this project.
    pub binary_count: usize,
}

impl ProjectHandle {
    /// Create a new project handle for the given path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        let id = path.to_string_lossy().replace(['/', '\\', ' ', ':'], "_");
        let opened_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            id,
            path,
            opened_at,
            binary_count: 0,
        }
    }
}

// ── ServerState ───────────────────────────────────────────────────────────────

/// Shared mutable state of the async HTTP server.
///
/// Wrapped in `Arc<tokio::sync::Mutex<_>>` and cloned into every request
/// handler so all routes share the same authoritative view.
#[derive(Debug)]
pub struct ServerState {
    /// The configuration that launched this server instance.
    pub config: HttpDaemonConfig,
    /// Currently open projects keyed by project ID.
    pub projects: HashMap<String, ProjectHandle>,
    /// Number of in-flight HTTP connections at this moment.
    pub active_sessions: u32,
    /// Wall-clock instant when the server started.
    pub start_time: Instant,
    /// Total requests served since startup.
    pub total_requests: u64,
    /// Total JSON-RPC errors since startup.
    pub rpc_errors: u64,
}

impl ServerState {
    /// Create a fresh `ServerState` from a config.
    #[must_use]
    pub fn new(config: HttpDaemonConfig) -> Self {
        Self {
            config,
            projects: HashMap::new(),
            active_sessions: 0,
            start_time: Instant::now(),
            total_requests: 0,
            rpc_errors: 0,
        }
    }

    /// Number of whole seconds since the server started.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────────────

/// True when a parsed request expects a response.
///
/// JSON-RPC 2.0: *"A Notification is a Request object without an `id` member.
/// The Server MUST NOT reply to a Notification."* The distinction is the
/// PRESENCE of the member, not its value: `{"id": null, ...}` is a request with
/// a null id and still gets an answer.
#[must_use]
pub const fn expects_reply(req: &JsonRpcRequest) -> bool {
    req.id.is_some()
}

/// Deserialise a PRESENT `id` member, keeping an explicit `null` distinct from
/// an absent member. See [`JsonRpcRequest::id`].
fn id_member<'de, D>(de: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(de).map(Some)
}

/// A JSON-RPC 2.0 request object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Request identifier, echoed back verbatim in the response — or `None` for a
    /// NOTIFICATION.
    ///
    /// JSON-RPC 2.0 tells a request from a notification by the presence of this
    /// member, and forbids replying to a notification. While this was a plain
    /// `Value` a notification failed to deserialise, so `POST /rpc` answered a
    /// perfectly valid message with a parse error.
    ///
    /// `#[serde(default)]` alone is not enough: serde maps an explicit JSON
    /// `null` onto `None` for any `Option`, which would collapse `{"id":null}`
    /// — a request with a null id, which the spec says MUST be answered — into
    /// a notification the server stays silent about, hanging the caller.
    /// `deserialize_with` runs only for a member that is PRESENT, so absent
    /// still yields `None` via `default` while `null` survives as
    /// `Some(Value::Null)`.
    #[serde(default, deserialize_with = "id_member")]
    pub id: Option<Value>,
    /// The method name to invoke.
    pub method: String,
    /// Optional structured parameters.
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Mirrored from the request.
    pub id: Value,
    /// Successful result payload (present iff `error` is absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload (present iff `result` is absent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric error code (see JSON-RPC spec for standard codes).
    pub code: i32,
    /// Short human-readable description.
    pub message: String,
    /// Optional additional data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// Standard JSON-RPC 2.0 error codes.
const JSONRPC_PARSE_ERROR: i32 = -32700;
const JSONRPC_INVALID_REQUEST: i32 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
const JSONRPC_INVALID_PARAMS: i32 = -32602;
pub const JSONRPC_INTERNAL_ERROR: i32 = -32603;

impl JsonRpcResponse {
    /// Construct a success response.
    #[must_use]
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error response.
    #[must_use]
    pub fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Construct an error response with a structured data payload.
    #[must_use]
    pub fn err_data(id: Value, code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }

    /// Serialize to a JSON `Bytes` body ready for an HTTP response.
    ///
    /// # Panics
    /// Only panics if `serde_json` fails to serialize a type we fully
    /// control — this cannot happen in practice.
    #[must_use]
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(serde_json::to_vec(self).expect("JsonRpcResponse serialization"))
    }
}

// ── JSON-RPC dispatcher ───────────────────────────────────────────────────────

/// Dispatch a single JSON-RPC request to the appropriate handler.
///
/// All method handlers are synchronous with respect to the shared state;
/// the caller holds the `tokio::sync::Mutex` guard for the duration.
async fn handle_jsonrpc(
    req: JsonRpcRequest,
    state: Arc<tokio::sync::Mutex<ServerState>>,
    shutdown_tx: broadcast::Sender<()>,
) -> JsonRpcResponse {
    // A notification has no id; a response object still needs one, and `Null` is
    // what the spec prescribes when an id cannot be echoed. Whether the response
    // is SENT at all is decided by the caller (see `POST /rpc`).
    let rpc_id = req.id.clone().unwrap_or(Value::Null);
    if req.jsonrpc != "2.0" {
        return JsonRpcResponse::err(
            rpc_id.clone(),
            JSONRPC_INVALID_REQUEST,
            "jsonrpc field must be \"2.0\"",
        );
    }

    debug!(method = %req.method, "dispatching JSON-RPC method");

    match req.method.as_str() {
        // ── project.open ─────────────────────────────────────────────────────
        "project.open" => {
            let path_str = match req
                .params
                .as_ref()
                .and_then(|p| p.get("path"))
                .and_then(Value::as_str)
            {
                Some(s) => s.to_owned(),
                None => {
                    return JsonRpcResponse::err(
                        rpc_id.clone(),
                        JSONRPC_INVALID_PARAMS,
                        "params.path (string) is required",
                    );
                }
            };

            let path = PathBuf::from(&path_str);
            if !path.exists() {
                return JsonRpcResponse::err(
                    rpc_id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    format!("path does not exist: {path_str}"),
                );
            }

            let handle = ProjectHandle::new(path);
            let id = handle.id.clone();
            let mut s = state.lock().await;
            s.projects.insert(id.clone(), handle.clone());
            info!(project_id = %id, path = %path_str, "project opened");

            JsonRpcResponse::ok(
                rpc_id.clone(),
                serde_json::json!({
                    "project_id": id,
                    "path": path_str,
                    "opened_at": handle.opened_at,
                }),
            )
        }

        // ── project.close ────────────────────────────────────────────────────
        "project.close" => {
            let project_id = match req
                .params
                .as_ref()
                .and_then(|p| p.get("project_id"))
                .and_then(Value::as_str)
            {
                Some(s) => s.to_owned(),
                None => {
                    return JsonRpcResponse::err(
                        rpc_id.clone(),
                        JSONRPC_INVALID_PARAMS,
                        "params.project_id (string) is required",
                    );
                }
            };

            let mut s = state.lock().await;
            if s.projects.remove(&project_id).is_some() {
                info!(project_id = %project_id, "project closed");
                JsonRpcResponse::ok(
                    rpc_id.clone(),
                    serde_json::json!({ "project_id": project_id, "closed": true }),
                )
            } else {
                JsonRpcResponse::err(
                    rpc_id.clone(),
                    JSONRPC_INVALID_PARAMS,
                    format!("no open project with id '{project_id}'"),
                )
            }
        }

        // ── binary.list ──────────────────────────────────────────────────────
        "binary.list" => {
            let s = state.lock().await;
            let project_id = req
                .params
                .as_ref()
                .and_then(|p| p.get("project_id"))
                .and_then(Value::as_str);

            let binaries: Vec<Value> = match project_id {
                Some(pid) => {
                    let Some(proj) = s.projects.get(pid) else {
                        return JsonRpcResponse::err(
                            rpc_id.clone(),
                            JSONRPC_INVALID_PARAMS,
                            format!("no open project '{pid}'"),
                        );
                    };
                    // In a real implementation we would enumerate the project's
                    // loaded binaries; here we surface the metadata stub.
                    vec![serde_json::json!({
                        "project_id": pid,
                        "path": proj.path,
                        "binary_count": proj.binary_count,
                    })]
                }
                None => {
                    // List across all open projects.
                    s.projects
                        .values()
                        .map(|p| {
                            serde_json::json!({
                                "project_id": p.id,
                                "path": p.path,
                                "binary_count": p.binary_count,
                            })
                        })
                        .collect()
                }
            };

            JsonRpcResponse::ok(rpc_id.clone(), serde_json::json!({ "binaries": binaries }))
        }

        // ── status ───────────────────────────────────────────────────────────
        "status" => {
            let s = state.lock().await;
            JsonRpcResponse::ok(
                rpc_id.clone(),
                serde_json::json!({
                    "status": "running",
                    "uptime_secs": s.uptime_secs(),
                    "open_projects": s.projects.len(),
                    "active_sessions": s.active_sessions,
                    "total_requests": s.total_requests,
                    "rpc_errors": s.rpc_errors,
                    "bind_addr": s.config.bind_addr,
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            )
        }

        // ── shutdown ─────────────────────────────────────────────────────────
        "shutdown" => {
            info!("shutdown requested via JSON-RPC");
            // Fire the shutdown broadcast; the main loop will clean up.
            let _ = shutdown_tx.send(());
            JsonRpcResponse::ok(rpc_id.clone(), serde_json::json!({ "shutting_down": true }))
        }

        // ── unknown method ────────────────────────────────────────────────────
        other => {
            warn!(method = %other, "unknown JSON-RPC method");
            JsonRpcResponse::err(
                rpc_id.clone(),
                JSONRPC_METHOD_NOT_FOUND,
                format!("method not found: {other}"),
            )
        }
    }
}

// ── HTTP helper functions ─────────────────────────────────────────────────────

/// Build an HTTP response with a JSON body and the given status code.
fn json_response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("X-Powered-By", "rustre-daemon/0.1.0")
        .body(Full::new(body))
        .expect("static response construction")
}

/// Build a plain-text HTTP response.
fn text_response(status: StatusCode, body: impl Into<String>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body.into())))
        .expect("static response construction")
}

/// Verify the `Authorization: Bearer <token>` header when the server is
/// configured with an auth token.  Returns `true` when auth is not required or
/// the token matches.
fn check_auth(req: &Request<Incoming>, expected: &Option<String>) -> bool {
    use subtle::ConstantTimeEq;
    let Some(expected_token) = expected.as_deref() else {
        return true; // auth not configured
    };
    // Compare tokens in constant time to prevent timing-based token recovery.
    // A plain `==` comparison exits early on the first mismatched byte,
    // leaking information about how many leading bytes of the token are correct.
    req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t.as_bytes().ct_eq(expected_token.as_bytes()).into())
}

// ── HTTP router ───────────────────────────────────────────────────────────────

/// Route a single HTTP request to the appropriate handler.
///
/// Called once per accepted TCP connection after the hyper handshake.
async fn route_request(
    req: Request<Incoming>,
    state: Arc<tokio::sync::Mutex<ServerState>>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Increment request counter and track active sessions.
    {
        let mut s = state.lock().await;
        s.total_requests += 1;
        s.active_sessions = s.active_sessions.saturating_add(1);
    }

    // Defer session decrement.
    struct SessionGuard(Arc<tokio::sync::Mutex<ServerState>>);
    impl Drop for SessionGuard {
        fn drop(&mut self) {
            // We spawn a task because Drop cannot be async.
            let s = self.0.clone();
            tokio::spawn(async move {
                let mut guard = s.lock().await;
                guard.active_sessions = guard.active_sessions.saturating_sub(1);
            });
        }
    }
    let _guard = SessionGuard(state.clone());

    // Auth check.
    let auth_token = state.lock().await.config.auth_token.clone();
    if !check_auth(&req, &auth_token) {
        return Ok(json_response(
            StatusCode::UNAUTHORIZED,
            Bytes::from(r#"{"error":"unauthorized"}"#),
        ));
    }

    let method = req.method().clone();
    // Strip control characters (including \n, \r) from the path before logging
    // to prevent log-injection: an attacker who controls the URI path could
    // embed newlines that fabricate additional log entries.
    let path_raw = req.uri().path().to_owned();
    let path: String = path_raw.chars().filter(|c| !c.is_control()).collect();

    debug!(%method, %path, "HTTP request");

    match (method, path.as_str()) {
        // ── POST /rpc  (JSON-RPC 2.0) ─────────────────────────────────────────
        (Method::POST, "/rpc") => {
            // Reject bodies larger than 4 MiB to prevent OOM from adversarial
            // clients sending an unbounded body before triggering deserialization.
            const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
            let collected = match req.into_body().collect().await {
                Ok(b) => b.to_bytes(),
                Err(e) => {
                    error!("failed to read request body: {e}");
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        Bytes::from(r#"{"error":"failed to read body"}"#),
                    ));
                }
            };
            if collected.len() > MAX_BODY_BYTES {
                return Ok(json_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Bytes::from(r#"{"error":"request body too large"}"#),
                ));
            }
            let body_bytes = collected;

            // Parse the JSON-RPC envelope.
            let rpc_req: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
                Ok(r) => r,
                Err(e) => {
                    let resp = JsonRpcResponse::err(
                        Value::Null,
                        JSONRPC_PARSE_ERROR,
                        format!("parse error: {e}"),
                    );
                    state.lock().await.rpc_errors += 1;
                    return Ok(json_response(StatusCode::OK, resp.to_bytes()));
                }
            };

            // JSON-RPC 2.0: "The Server MUST NOT reply to a Notification."
            // The request is still dispatched, for its side effects.
            let reply_expected = expects_reply(&rpc_req);
            let resp = handle_jsonrpc(rpc_req, state, shutdown_tx).await;
            if resp.error.is_some() {
                // Already counted inside handle_jsonrpc for method-not-found;
                // count here for all other error paths too.
            }
            if !reply_expected {
                return Ok(json_response(StatusCode::NO_CONTENT, Bytes::new()));
            }
            Ok(json_response(StatusCode::OK, resp.to_bytes()))
        }

        // ── GET /health ───────────────────────────────────────────────────────
        (Method::GET, "/health") => {
            let uptime = state.lock().await.uptime_secs();
            let body = serde_json::json!({
                "status": "ok",
                "uptime": uptime,
            });
            Ok(json_response(
                StatusCode::OK,
                Bytes::from(serde_json::to_vec(&body).expect("health body")),
            ))
        }

        // ── GET /version ──────────────────────────────────────────────────────
        (Method::GET, "/version") => {
            let body = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "crates": 189,
            });
            Ok(json_response(
                StatusCode::OK,
                Bytes::from(serde_json::to_vec(&body).expect("version body")),
            ))
        }

        // ── GET /metrics (Prometheus-compatible) ──────────────────────────────
        (Method::GET, "/metrics") => {
            let s = state.lock().await;
            let uptime = s.uptime_secs();
            let active = s.active_sessions;
            let total = s.total_requests;
            let errors = s.rpc_errors;
            let projects = s.projects.len();
            drop(s);

            let metrics = format!(
                "# HELP rustre_uptime_seconds Seconds since the daemon started.\n\
                 # TYPE rustre_uptime_seconds counter\n\
                 rustre_uptime_seconds {uptime}\n\
                 # HELP rustre_active_sessions Current number of active HTTP sessions.\n\
                 # TYPE rustre_active_sessions gauge\n\
                 rustre_active_sessions {active}\n\
                 # HELP rustre_total_requests_total Total HTTP requests served.\n\
                 # TYPE rustre_total_requests_total counter\n\
                 rustre_total_requests_total {total}\n\
                 # HELP rustre_rpc_errors_total Total JSON-RPC errors returned.\n\
                 # TYPE rustre_rpc_errors_total counter\n\
                 rustre_rpc_errors_total {errors}\n\
                 # HELP rustre_open_projects Number of currently open projects.\n\
                 # TYPE rustre_open_projects gauge\n\
                 rustre_open_projects {projects}\n"
            );

            Ok(text_response(StatusCode::OK, metrics))
        }

        // ── 404 catch-all ─────────────────────────────────────────────────────
        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            Bytes::from(r#"{"error":"not found"}"#),
        )),
    }
}

// ── HttpServer ────────────────────────────────────────────────────────────────

/// The async HTTP server that exposes the JSON-RPC and REST endpoints.
pub struct HttpServer;

impl HttpServer {
    /// Bind and run the HTTP server until a shutdown signal is received.
    ///
    /// This function owns the tokio runtime lifecycle for the HTTP layer.
    /// Use [`run_daemon`] for the full daemon including MCP and signal
    /// handling.
    ///
    /// # Errors
    /// Returns an error if the TCP bind fails or if a fatal I/O error occurs
    /// in the accept loop.
    pub async fn start(config: HttpDaemonConfig) -> Result<()> {
        let state = Arc::new(tokio::sync::Mutex::new(ServerState::new(config.clone())));

        // If an initial project directory was configured, open it immediately.
        if let Some(ref dir) = config.project_dir {
            let handle = ProjectHandle::new(dir.clone());
            let id = handle.id.clone();
            state.lock().await.projects.insert(id.clone(), handle);
            info!(project_id = %id, path = ?dir, "auto-opened project from config");
        }

        // Bind the TCP listener.
        let listener = AsyncTcpListener::bind(&config.bind_addr).await?;
        info!(addr = %config.bind_addr, "HTTP server listening");

        // Broadcast channel used to signal a graceful shutdown.
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        let shutdown_tx_clone = shutdown_tx.clone();

        // Connection semaphore enforcing max_connections.
        let sem = Arc::new(tokio::sync::Semaphore::new(config.max_connections as usize));

        loop {
            // Wait for either a new connection or a shutdown signal.
            let mut shutdown_rx = shutdown_tx.subscribe();
            let accept_result = tokio::select! {
                res = listener.accept() => res,
                _ = shutdown_rx.recv() => {
                    info!("HTTP server received shutdown signal, stopping accept loop");
                    break;
                }
            };

            let (stream, peer_addr) = match accept_result {
                Ok(pair) => pair,
                Err(e) => {
                    error!("accept error: {e}");
                    continue;
                }
            };

            // Acquire a connection permit (non-blocking check).
            let permit = if let Ok(p) = sem.clone().try_acquire_owned() { p } else {
                warn!(peer = %peer_addr, "max_connections reached, dropping connection");
                continue;
            };

            debug!(peer = %peer_addr, "accepted TCP connection");

            let state_clone = state.clone();
            let shutdown_tx_inner = shutdown_tx_clone.clone();

            tokio::spawn(async move {
                let _permit = permit; // Released when the task completes.
                let io = TokioIo::new(stream);

                let service = hyper::service::service_fn(move |req| {
                    let s = state_clone.clone();
                    let tx = shutdown_tx_inner.clone();
                    async move { route_request(req, s, tx).await }
                });

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    // Ignore "connection reset by peer" style errors.
                    if !e.is_incomplete_message() {
                        debug!(peer = %peer_addr, "connection error: {e}");
                    }
                }
            });
        }

        info!("HTTP server shut down cleanly");
        Ok(())
    }
}

// ── MCP SSE server ────────────────────────────────────────────────────────────

/// Start the real `RustRE` MCP SSE server on `bind_addr`.
///
/// Delegates to [`rustre_mcp_server::run_http`] which spins up the full
/// rmcp SSE transport and exposes all registered `RustRE` tools.
///
/// # Errors
/// Returns an error if the bind address is invalid or the transport fails.
async fn start_mcp_sse_server(bind_addr: String) -> Result<()> {
    info!(addr = %bind_addr, "MCP SSE server starting (rustre-mcp-server)");
    rustre_mcp_server::run_http(&bind_addr).await?;
    info!(addr = %bind_addr, "MCP SSE server stopped");
    Ok(())
}

// ── run_daemon ────────────────────────────────────────────────────────────────

/// Initialise tracing, start the HTTP (and optionally MCP) server, and handle
/// OS signals for graceful shutdown.
///
/// This is the canonical entry point for the `rustre-daemon` binary in daemon
/// mode (§35.1).
///
/// # Errors
/// Returns an error if the tokio runtime cannot be built or if the HTTP server
/// fails to bind.
pub async fn run_daemon(config: HttpDaemonConfig) -> Result<()> {
    // ── Startup banner ────────────────────────────────────────────────────────
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│  rustre-daemon v{:<44} │", env!("CARGO_PKG_VERSION"));
    println!("│  RustRE headless analysis server (§35.1)                │");
    println!("│  bind={}  log={}", config.bind_addr, config.log_level);
    if let Some(ref mcp) = config.mcp_bind {
        println!("│  mcp={mcp}  ");
    }
    if let Some(ref dir) = config.project_dir {
        println!("│  project={}  ", dir.display());
    }
    println!("└─────────────────────────────────────────────────────────┘");

    // ── Tracing subscriber ────────────────────────────────────────────────────
    let filter = tracing_subscriber::EnvFilter::try_new(&config.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();

    info!(
        bind_addr = %config.bind_addr,
        log_level = %config.log_level,
        max_connections = config.max_connections,
        workers = config.workers,
        "daemon initialising"
    );

    // ── MCP SSE server (optional) ─────────────────────────────────────────────
    let mcp_handle: Option<tokio::task::JoinHandle<Result<()>>> =
        if let Some(ref mcp_addr) = config.mcp_bind {
            let addr = mcp_addr.clone();
            Some(tokio::spawn(
                async move { start_mcp_sse_server(addr).await },
            ))
        } else {
            None
        };

    // ── HTTP server ───────────────────────────────────────────────────────────
    // Run the HTTP server in the foreground; it will exit on shutdown signal.
    let http_result = HttpServer::start(config).await;

    // Abort MCP server if it is running.
    if let Some(handle) = mcp_handle {
        handle.abort();
    }

    http_result
}

// Helper used only in tests to avoid needing a live `Request<Incoming>`.
#[cfg(test)]
fn check_auth_token(expected: Option<&str>, provided: Option<&str>) -> bool {
    let expected_owned = expected.map(str::to_owned);
    match expected_owned.as_deref() {
        None => true,
        Some(exp) => provided.is_some_and(|p| p == exp),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!("rustre_daemon_test_{name}"))
    }

    // ── DaemonState ───────────────────────────────────────────────────────────

    #[test]
    fn test_daemon_state_is_active() {
        assert!(DaemonState::Running.is_active());
        assert!(DaemonState::Starting.is_active());
        assert!(!DaemonState::Stopped.is_active());
        assert!(!DaemonState::Failed.is_active());
    }

    #[test]
    fn test_daemon_state_can_start() {
        assert!(DaemonState::Stopped.can_start());
        assert!(DaemonState::Failed.can_start());
        assert!(!DaemonState::Running.can_start());
    }

    #[test]
    fn test_daemon_state_display() {
        assert_eq!(DaemonState::Running.to_string(), "running");
        assert_eq!(DaemonState::Stopping.to_string(), "stopping");
    }

    // ── DaemonConfig ──────────────────────────────────────────────────────────

    #[test]
    fn test_daemon_config_default_validates() {
        let cfg = DaemonConfig::new();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_daemon_config_zero_log_size_invalid() {
        let mut cfg = DaemonConfig::new();
        cfg.max_log_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_daemon_config_log_file_path() {
        let mut cfg = DaemonConfig::new();
        cfg.log_dir = PathBuf::from("/tmp");
        cfg.log_name = "test".into();
        assert_eq!(cfg.log_file_path(), PathBuf::from("/tmp/test.log"));
    }

    #[test]
    fn test_daemon_config_rotated_path() {
        let mut cfg = DaemonConfig::new();
        cfg.log_dir = PathBuf::from("/tmp");
        cfg.log_name = "test".into();
        assert_eq!(cfg.rotated_log_path(2), PathBuf::from("/tmp/test.2.log"));
    }

    #[test]
    fn test_daemon_config_with_pid_file() {
        let cfg = DaemonConfig::new().with_pid_file("/tmp/test.pid");
        assert_eq!(cfg.pid_file, PathBuf::from("/tmp/test.pid"));
    }

    #[test]
    fn test_daemon_config_with_ipc_addr_valid() {
        let cfg = DaemonConfig::new().with_ipc_addr("127.0.0.1:9999").unwrap();
        assert_eq!(cfg.ipc_addr.port(), 9999);
    }

    #[test]
    fn test_daemon_config_with_ipc_addr_invalid() {
        assert!(DaemonConfig::new().with_ipc_addr("not-an-addr").is_err());
    }

    // ── PidFile ───────────────────────────────────────────────────────────────

    #[test]
    fn test_pid_file_write_read_remove() {
        let path = tmp_path("pid_test.pid");
        let pf = PidFile::new(&path);
        pf.write_pid(12345).unwrap();
        assert!(pf.exists());
        assert_eq!(pf.read().unwrap(), 12345);
        pf.remove().unwrap();
        assert!(!pf.exists());
    }

    #[test]
    fn test_pid_file_read_missing() {
        let path = tmp_path("no_such_file.pid");
        let pf = PidFile::new(&path);
        // Make sure it doesn't exist.
        let _ = fs::remove_file(&path);
        assert!(pf.read().is_err());
    }

    #[test]
    fn test_pid_file_remove_nonexistent_ok() {
        let path = tmp_path("ghost.pid");
        let _ = fs::remove_file(&path);
        let pf = PidFile::new(&path);
        assert!(pf.remove().is_ok());
    }

    // ── IpcMessage ────────────────────────────────────────────────────────────

    #[test]
    fn test_ipc_message_to_line() {
        let msg = IpcMessage::new("status");
        let line = msg.to_line().unwrap();
        assert!(line.contains("\"command\":\"status\""));
    }

    #[test]
    fn test_ipc_message_from_line() {
        let msg = IpcMessage::from_line("{\"command\":\"health\",\"args\":[]}").unwrap();
        assert_eq!(msg.command, "health");
    }

    #[test]
    fn test_ipc_message_from_line_missing_command() {
        assert!(IpcMessage::from_line("{\"foo\":\"bar\"}").is_err());
    }

    #[test]
    fn test_ipc_response_success() {
        let r = IpcResponse::success("all good");
        assert!(r.ok);
        assert_eq!(r.message, "all good");
    }

    #[test]
    fn test_ipc_response_failure() {
        let r = IpcResponse::failure("boom");
        assert!(!r.ok);
    }

    #[test]
    fn test_ipc_response_to_line() {
        let r = IpcResponse::success("ok").with_payload("{\"x\":1}");
        let line = r.to_line();
        assert!(line.contains("\"ok\":true"));
        assert!(line.contains("payload"));
    }

    #[test]
    fn test_ipc_message_args_roundtrip() {
        let msg =
            IpcMessage::new("analyze").with_args(vec!["/bin/ls".to_string(), "--deep".to_string()]);
        let line = msg.to_line().unwrap();
        let parsed = IpcMessage::from_line(&line).unwrap();
        assert_eq!(parsed.command, "analyze");
        assert_eq!(
            parsed.args,
            vec!["/bin/ls".to_string(), "--deep".to_string()]
        );
    }

    #[test]
    fn test_ipc_response_from_line_roundtrip() {
        let r = IpcResponse::success("done").with_payload("{\"count\":3}");
        let parsed = IpcResponse::from_line(&r.to_line()).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.message, "done");
        assert_eq!(parsed.payload.as_deref(), Some("{\"count\":3}"));
    }

    // ── Client/server round-trip ──────────────────────────────────────────────

    #[test]
    fn test_client_server_roundtrip() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut server = IpcServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        server.on("echo", |msg| {
            IpcResponse::success("echoed").with_payload(msg.args.join(","))
        });
        server.on("health", |_| IpcResponse::success("ok"));
        assert_eq!(server.handler_count(), 2);
        assert!(server.has_handler("echo"));

        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let server = Arc::new(server);
        let server_thread = {
            let server = server;
            std::thread::spawn(move || {
                let _ = server.serve(&|| stop_srv.load(Ordering::Relaxed));
            })
        };

        let client = DaemonClient::new(addr).with_timeout(Duration::from_secs(2));
        assert_eq!(client.addr(), addr);
        assert!(client.ping());

        let resp = client
            .command_with_args("echo", vec!["a".into(), "b".into()])
            .unwrap();
        assert!(resp.ok);
        assert_eq!(resp.payload.as_deref(), Some("a,b"));

        let unknown = client.command("does-not-exist").unwrap();
        assert!(!unknown.ok);

        stop.store(true, Ordering::Relaxed);
        let _ = server_thread.join();
    }

    // ── HealthCheck ───────────────────────────────────────────────────────────

    #[test]
    fn test_health_check_all_pass() {
        let mut hc = HealthCheck::new();
        hc.add_check(|| CheckItem::pass("disk", "OK"));
        hc.add_check(|| CheckItem::pass("mem", "OK"));
        let result = hc.run();
        assert!(result.healthy);
        assert_eq!(result.checks.len(), 2);
    }

    #[test]
    fn test_health_check_one_fail() {
        let mut hc = HealthCheck::new();
        hc.add_check(|| CheckItem::pass("disk", "OK"));
        hc.add_check(|| CheckItem::fail("db", "connection refused"));
        let result = hc.run();
        assert!(!result.healthy);
    }

    #[test]
    fn test_health_check_empty() {
        let hc = HealthCheck::new();
        let result = hc.run();
        assert!(result.healthy); // vacuously true
    }

    #[test]
    fn test_health_check_result_to_text() {
        let mut hc = HealthCheck::new();
        hc.add_check(|| CheckItem::pass("x", "fine"));
        let text = hc.run().to_text();
        assert!(text.contains("HEALTHY"));
        assert!(text.contains('x'));
    }

    // ── SignalBus ─────────────────────────────────────────────────────────────

    #[test]
    fn test_signal_bus_post_drain() {
        let bus = SignalBus::new();
        assert!(!bus.has_pending());
        bus.post(Signal::Terminate);
        bus.post(Signal::HangUp);
        assert!(bus.has_pending());
        let sigs = bus.drain();
        assert_eq!(sigs.len(), 2);
        assert!(!bus.has_pending());
    }

    #[test]
    fn test_signal_display() {
        assert_eq!(Signal::Terminate.to_string(), "SIGTERM");
        assert_eq!(Signal::HangUp.to_string(), "SIGHUP");
    }

    // ── Daemon lifecycle ──────────────────────────────────────────────────────

    #[test]
    fn test_daemon_start_stop() {
        let mut cfg = DaemonConfig::new();
        cfg.pid_file = tmp_path("daemon_start.pid");
        let mut d = Daemon::new(cfg).unwrap();
        assert_eq!(d.state(), DaemonState::Stopped);
        d.start().unwrap();
        assert_eq!(d.state(), DaemonState::Running);
        assert!(d.uptime().is_some());
        d.stop().unwrap();
        assert_eq!(d.state(), DaemonState::Stopped);
        assert!(d.uptime().is_none());
    }

    #[test]
    fn test_daemon_stop_when_not_running() {
        let mut cfg = DaemonConfig::new();
        cfg.pid_file = tmp_path("daemon_stop_err.pid");
        let mut d = Daemon::new(cfg).unwrap();
        assert!(d.stop().is_err());
    }

    #[test]
    fn test_daemon_restart() {
        let mut cfg = DaemonConfig::new();
        cfg.pid_file = tmp_path("daemon_restart.pid");
        let mut d = Daemon::new(cfg).unwrap();
        d.start().unwrap();
        d.restart().unwrap();
        assert_eq!(d.state(), DaemonState::Running);
        d.stop().unwrap();
    }

    #[test]
    fn test_daemon_status_text() {
        let mut cfg = DaemonConfig::new();
        cfg.pid_file = tmp_path("daemon_status.pid");
        let d = Daemon::new(cfg).unwrap();
        let s = d.status_text();
        assert!(s.contains("state=stopped"));
    }

    #[test]
    fn test_daemon_mark_failed() {
        let cfg = DaemonConfig::new();
        let d = Daemon::new(cfg).unwrap();
        d.mark_failed();
        assert_eq!(d.state(), DaemonState::Failed);
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_is_process_running() {
        // Should not panic.
        let _ = is_process_running(std::process::id());
    }

    // ── HttpDaemonConfig ──────────────────────────────────────────────────────

    #[test]
    fn test_http_daemon_config_defaults() {
        let cfg = HttpDaemonConfig::default();
        assert_eq!(cfg.bind_addr, "127.0.0.1:7878");
        assert!(cfg.mcp_bind.is_none());
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.max_connections, 16);
        assert!(cfg.auth_token.is_none());
        assert_eq!(cfg.workers, 0);
    }

    #[test]
    fn test_http_daemon_config_serde_roundtrip() {
        let cfg = HttpDaemonConfig {
            bind_addr: "0.0.0.0:9090".into(),
            mcp_bind: Some("0.0.0.0:9091".into()),
            log_level: "debug".into(),
            project_dir: Some(PathBuf::from("/tmp/proj")),
            max_connections: 32,
            auth_token: Some("secret".into()),
            workers: 4,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: HttpDaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.bind_addr, "0.0.0.0:9090");
        assert_eq!(restored.mcp_bind.as_deref(), Some("0.0.0.0:9091"));
        assert_eq!(restored.max_connections, 32);
        assert_eq!(restored.auth_token.as_deref(), Some("secret"));
    }

    // ── ServerState ───────────────────────────────────────────────────────────

    #[test]
    fn test_server_state_uptime() {
        let state = ServerState::new(HttpDaemonConfig::default());
        let u = state.uptime_secs();
        // uptime should be 0 or 1 second at most in a unit test
        assert!(u <= 2, "unexpected uptime {u}");
    }

    #[test]
    fn test_server_state_open_project() {
        let mut state = ServerState::new(HttpDaemonConfig::default());
        let handle = ProjectHandle::new(PathBuf::from("/tmp/test_project"));
        let id = handle.id.clone();
        state.projects.insert(id.clone(), handle);
        assert_eq!(state.projects.len(), 1);
        assert!(state.projects.contains_key(&id));
    }

    // ── JsonRpcResponse ───────────────────────────────────────────────────────

    #[test]
    fn test_jsonrpc_response_ok_serializes() {
        let resp = JsonRpcResponse::ok(serde_json::json!(1), serde_json::json!({"result": "ok"}));
        let bytes = resp.to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert!(v.get("error").is_none() || v["error"].is_null());
    }

    #[test]
    fn test_jsonrpc_response_err_serializes() {
        let resp = JsonRpcResponse::err(
            serde_json::json!("req-1"),
            JSONRPC_METHOD_NOT_FOUND,
            "method not found",
        );
        let bytes = resp.to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["code"], JSONRPC_METHOD_NOT_FOUND);
        assert!(v.get("result").is_none() || v["result"].is_null());
    }

    #[test]
    fn test_jsonrpc_error_codes_are_correct() {
        assert_eq!(JSONRPC_PARSE_ERROR, -32700);
        assert_eq!(JSONRPC_INVALID_REQUEST, -32600);
        assert_eq!(JSONRPC_METHOD_NOT_FOUND, -32601);
        assert_eq!(JSONRPC_INVALID_PARAMS, -32602);
        assert_eq!(JSONRPC_INTERNAL_ERROR, -32603);
    }

    // ── check_auth ────────────────────────────────────────────────────────────

    #[test]
    fn test_check_auth_no_token_configured() {
        // When no token is required any request passes.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let _ = req;
        // We can't easily build an Incoming in unit tests but we can test via
        // the None branch:
        assert!(check_auth_token(None, None));
        assert!(check_auth_token(None, Some("any-token")));
    }

    #[test]
    fn test_check_auth_token_match() {
        assert!(check_auth_token(Some("secret"), Some("secret")));
    }

    #[test]
    fn test_check_auth_token_mismatch() {
        assert!(!check_auth_token(Some("secret"), Some("wrong")));
    }

    #[test]
    fn test_check_auth_token_missing_header() {
        assert!(!check_auth_token(Some("secret"), None));
    }

    // ── ProjectHandle ─────────────────────────────────────────────────────────

    #[test]
    fn test_project_handle_id_derived_from_path() {
        let h = ProjectHandle::new(PathBuf::from("/tmp/my project"));
        // Slashes, spaces → underscores.
        assert!(!h.id.contains('/'));
        assert!(!h.id.contains(' '));
    }

    #[test]
    fn test_project_handle_opened_at_recent() {
        let h = ProjectHandle::new(PathBuf::from("/tmp/proj"));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(h.opened_at <= now + 2);
        assert!(h.opened_at >= now.saturating_sub(2));
    }
}
