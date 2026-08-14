//! `client_handler` — per-client connection handling for the daemon.
//!
//! Accepts incoming TCP (or Unix-socket-compatible) connections, reads framed
//! JSON requests, dispatches them through a [`RequestDispatcher`], and writes
//! back framed JSON responses.  Each connected client runs in its own async
//! task.
//!
//! # Architecture
//!
//! ```text
//!  TCP listener
//!      │  accept()
//!      ▼
//!  ClientHandler::run()   ◄── Arc<RequestDispatcher>
//!      │  per-message loop
//!      ▼
//!  RequestDispatcher::dispatch(ClientRequest) → ClientResponse
//! ```
//!
//! # Notes
//! All `pub fn` returning `Result` carry `/// # Errors`.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from the client handler subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// I/O failure on the TCP stream.
    #[error("io error: {0}")]
    Io(String),

    /// The request could not be deserialised.
    #[error("parse error: {0}")]
    Parse(String),

    /// The dispatcher rejected the request.
    #[error("dispatch error: {0}")]
    Dispatch(String),

    /// The client disconnected cleanly.
    #[error("client disconnected")]
    Disconnected,

    /// A timeout was exceeded.
    #[error("timeout after {0}ms")]
    Timeout(u64),
}

// ── ClientRequest ─────────────────────────────────────────────────────────────

/// A request sent by a daemon client over a TCP connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientRequest {
    /// Unique request identifier (client-assigned).
    pub id: String,
    /// Method name (e.g. `"status"`, `"analyze"`, `"shutdown"`).
    pub method: String,
    /// Optional key-value parameters.
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
}

impl ClientRequest {
    /// Construct a request with no parameters.
    #[must_use]
    pub fn new(id: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            method: method.into(),
            params: HashMap::new(),
        }
    }

    /// Construct a request and insert a single string parameter.
    #[must_use]
    pub fn with_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.params
            .insert(key.into(), serde_json::Value::String(value.into()));
        self
    }

    /// Deserialise from a JSON line.
    ///
    /// # Errors
    /// Returns [`HandlerError::Parse`] for invalid JSON.
    pub fn from_line(line: &str) -> Result<Self, HandlerError> {
        serde_json::from_str(line.trim())
            .map_err(|e| HandlerError::Parse(format!("ClientRequest: {e}")))
    }

    /// Serialise to a single JSON line (no trailing newline).
    ///
    /// # Errors
    /// Returns [`HandlerError::Parse`] if serialisation fails.
    pub fn to_line(&self) -> Result<String, HandlerError> {
        serde_json::to_string(self)
            .map_err(|e| HandlerError::Parse(format!("ClientRequest serialise: {e}")))
    }
}

impl fmt::Display for ClientRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientRequest {{ id={}, method={} }}", self.id, self.method)
    }
}

// ── ClientResponse ────────────────────────────────────────────────────────────

/// A response sent back to a daemon client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientResponse {
    /// Mirrors the request ID.
    pub id: String,
    /// `true` when the request succeeded.
    pub ok: bool,
    /// Human-readable message or error detail.
    pub message: String,
    /// Structured result payload (JSON value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl ClientResponse {
    /// Create a successful response.
    #[must_use]
    pub fn success(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ok: true,
            message: message.into(),
            result: None,
        }
    }

    /// Create a failed response.
    #[must_use]
    pub fn failure(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ok: false,
            message: message.into(),
            result: None,
        }
    }

    /// Attach a structured result.
    #[must_use]
    pub fn with_result(mut self, result: serde_json::Value) -> Self {
        self.result = Some(result);
        self
    }

    /// Serialise to a JSON line (no trailing newline).
    ///
    /// # Errors
    /// Returns [`HandlerError::Parse`] on serialisation failure.
    pub fn to_line(&self) -> Result<String, HandlerError> {
        serde_json::to_string(self)
            .map_err(|e| HandlerError::Parse(format!("ClientResponse serialise: {e}")))
    }

    /// Deserialise from a JSON line.
    ///
    /// # Errors
    /// Returns [`HandlerError::Parse`] for invalid JSON.
    pub fn from_line(line: &str) -> Result<Self, HandlerError> {
        serde_json::from_str(line.trim())
            .map_err(|e| HandlerError::Parse(format!("ClientResponse: {e}")))
    }
}

impl fmt::Display for ClientResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.ok { "ok" } else { "err" };
        write!(f, "ClientResponse {{ id={}, status={status}, msg={} }}", self.id, self.message)
    }
}

// ── HandlerFn ─────────────────────────────────────────────────────────────────

/// Type alias for a boxed async-compatible dispatch function.
///
/// Each method handler receives the full request and returns a response.
pub type HandlerFn = Box<
    dyn Fn(ClientRequest) -> ClientResponse + Send + Sync + 'static,
>;

// ── RequestDispatcher ─────────────────────────────────────────────────────────

/// Routes incoming [`ClientRequest`]s to the appropriate registered handler.
///
/// Handlers are registered by method name.  If no handler matches, the
/// dispatcher returns a generic "method not found" response.
pub struct RequestDispatcher {
    handlers: RwLock<HashMap<String, HandlerFn>>,
    /// Count of requests dispatched since creation.
    request_count: AtomicU64,
    /// Count of requests that returned `ok = false`.
    error_count: AtomicU64,
}

impl RequestDispatcher {
    /// Create an empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            request_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    /// Register a handler for `method`.  If a handler already exists for that
    /// method it is replaced.
    pub fn register(
        &self,
        method: impl Into<String>,
        handler: impl Fn(ClientRequest) -> ClientResponse + Send + Sync + 'static,
    ) {
        self.handlers.write().insert(method.into(), Box::new(handler));
    }

    /// Remove the handler for `method`.  Returns `true` if one existed.
    pub fn deregister(&self, method: &str) -> bool {
        self.handlers.write().remove(method).is_some()
    }

    /// Dispatch a request.  Returns the response produced by the handler, or a
    /// "method not found" response if no handler is registered for the method.
    pub fn dispatch(&self, req: ClientRequest) -> ClientResponse {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let resp = {
            let handlers = self.handlers.read();
            if let Some(handler) = handlers.get(&req.method) {
                handler(req)
            } else {
                ClientResponse::failure(req.id, format!("method '{}' not found", req.method))
            }
        };
        if !resp.ok {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        resp
    }

    /// Number of requests dispatched so far.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Number of error responses returned so far.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.read().len()
    }

    /// Return `true` if a handler is registered for `method`.
    #[must_use]
    pub fn has_handler(&self, method: &str) -> bool {
        self.handlers.read().contains_key(method)
    }
}

impl Default for RequestDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ── ClientInfo ────────────────────────────────────────────────────────────────

/// Metadata about an active client connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Unique numeric ID assigned at connection time.
    pub client_id: u64,
    /// Remote peer address.
    pub peer_addr: String,
    /// Epoch-seconds timestamp when this client connected.
    pub connected_at: u64,
    /// Number of requests processed for this client.
    pub request_count: u64,
    /// Number of error responses sent to this client.
    pub error_count: u64,
}

impl ClientInfo {
    /// Create a new [`ClientInfo`] for the given peer address.
    #[must_use]
    pub fn new(client_id: u64, peer_addr: impl Into<String>) -> Self {
        Self {
            client_id,
            peer_addr: peer_addr.into(),
            connected_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            request_count: 0,
            error_count: 0,
        }
    }

    /// Duration since this client connected.
    #[must_use]
    pub fn connection_age(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Duration::from_secs(now.saturating_sub(self.connected_at))
    }
}

// ── ClientRegistry ────────────────────────────────────────────────────────────

/// Thread-safe registry of all currently connected clients.
#[derive(Debug, Default)]
pub struct ClientRegistry {
    clients: Mutex<HashMap<u64, ClientInfo>>,
    next_id: AtomicU64,
}

impl ClientRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new client, returning its assigned ID.
    pub fn register(&self, peer_addr: impl Into<String>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let info = ClientInfo::new(id, peer_addr);
        self.clients.lock().insert(id, info);
        id
    }

    /// Remove a client by ID.
    pub fn deregister(&self, client_id: u64) {
        self.clients.lock().remove(&client_id);
    }

    /// Increment request count for a client.
    pub fn record_request(&self, client_id: u64, success: bool) {
        let mut clients = self.clients.lock();
        if let Some(info) = clients.get_mut(&client_id) {
            info.request_count += 1;
            if !success {
                info.error_count += 1;
            }
        }
    }

    /// Return a snapshot of all connected clients.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ClientInfo> {
        self.clients.lock().values().cloned().collect()
    }

    /// Return the number of connected clients.
    #[must_use]
    pub fn count(&self) -> usize {
        self.clients.lock().len()
    }

    /// Return `true` if a client with the given ID is registered.
    #[must_use]
    pub fn contains(&self, client_id: u64) -> bool {
        self.clients.lock().contains_key(&client_id)
    }
}

// ── ClientHandler ─────────────────────────────────────────────────────────────

/// Handles a single connected daemon client for its entire session.
///
/// Runs an async per-client loop that:
/// 1. Reads one newline-delimited JSON [`ClientRequest`] per iteration.
/// 2. Dispatches it through [`RequestDispatcher`].
/// 3. Writes back a newline-delimited JSON [`ClientResponse`].
/// 4. Terminates on clean disconnect, error, or shutdown signal.
pub struct ClientHandler {
    /// The registered dispatcher shared across all handlers.
    dispatcher: Arc<RequestDispatcher>,
    /// Registry for tracking connected clients.
    registry: Arc<ClientRegistry>,
    /// Shutdown broadcast receiver (daemon sends `()` to ask all handlers to stop).
    shutdown_rx: broadcast::Receiver<()>,
    /// Per-request read timeout.
    read_timeout: Duration,
    /// Per-request write timeout.
    write_timeout: Duration,
}

impl ClientHandler {
    /// Create a new handler with the given shared resources.
    #[must_use]
    pub fn new(
        dispatcher: Arc<RequestDispatcher>,
        registry: Arc<ClientRegistry>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            dispatcher,
            registry,
            shutdown_rx,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
        }
    }

    /// Override the per-request read timeout.
    #[must_use]
    pub const fn with_read_timeout(mut self, t: Duration) -> Self {
        self.read_timeout = t;
        self
    }

    /// Override the per-request write timeout.
    #[must_use]
    pub const fn with_write_timeout(mut self, t: Duration) -> Self {
        self.write_timeout = t;
        self
    }

    /// Run the per-client request/response loop on `stream`.
    ///
    /// This method consumes `self` and drives the loop to completion.
    ///
    /// # Errors
    /// Returns [`HandlerError::Io`] if a fatal socket error occurs (as opposed
    /// to a clean disconnect, which returns `Ok(())`).
    pub async fn run(mut self, stream: TcpStream, peer: SocketAddr) -> Result<(), HandlerError> {
        let client_id = self.registry.register(peer.to_string());
        // Ensure the client is deregistered even if the loop returns early.
        struct DeregGuard<'a> { reg: &'a ClientRegistry, id: u64 }
        impl Drop for DeregGuard<'_> {
            fn drop(&mut self) { self.reg.deregister(self.id); }
        }
        let _guard = DeregGuard { reg: &self.registry, id: client_id };

        // Per-message read limit: reject lines larger than 4 MiB to prevent OOM
        // from an adversary sending a never-terminating line over the TCP socket.
        const MAX_MSG_BYTES: usize = 4 * 1024 * 1024;

        let (reader_half, mut writer_half) = stream.into_split();
        let mut reader = BufReader::new(reader_half);
        let mut line_buf = String::with_capacity(512);

        loop {
            line_buf.clear();

            // Wait for either a new line or a shutdown signal.
            let read_result = tokio::select! {
                res = reader.read_line(&mut line_buf) => res,
                _ = self.shutdown_rx.recv() => {
                    // Daemon shutting down: send a goodbye and exit cleanly.
                    let bye = ClientResponse {
                        id: "shutdown".into(),
                        ok: false,
                        message: "daemon shutting down".into(),
                        result: None,
                    };
                    if let Ok(line) = bye.to_line() {
                        let _ = writer_half.write_all(format!("{line}\n").as_bytes()).await;
                    }
                    break;
                }
            };

            let n = read_result.map_err(|e| HandlerError::Io(e.to_string()))?;
            if n == 0 {
                // Clean EOF.
                self.registry.deregister(client_id);
                return Ok(());
            }
            if line_buf.len() > MAX_MSG_BYTES {
                return Err(HandlerError::Io(format!(
                    "message too large ({} bytes, max {MAX_MSG_BYTES})",
                    line_buf.len()
                )));
            }

            let req = match ClientRequest::from_line(&line_buf) {
                Ok(r) => r,
                Err(e) => {
                    let resp = ClientResponse::failure("parse-error", e.to_string());
                    let out = resp.to_line().unwrap_or_default();
                    writer_half
                        .write_all(format!("{out}\n").as_bytes())
                        .await
                        .map_err(|e| HandlerError::Io(e.to_string()))?;
                    continue;
                }
            };

            let resp = self.dispatcher.dispatch(req);
            let success = resp.ok;
            self.registry.record_request(client_id, success);

            let out = resp.to_line().map_err(|e| HandlerError::Dispatch(e.to_string()))?;
            writer_half
                .write_all(format!("{out}\n").as_bytes())
                .await
                .map_err(|e| HandlerError::Io(e.to_string()))?;
        }

        self.registry.deregister(client_id);
        Ok(())
    }
}

// ── DaemonListener ────────────────────────────────────────────────────────────

/// TCP listener that spawns a [`ClientHandler`] task per accepted connection.
pub struct DaemonListener {
    dispatcher: Arc<RequestDispatcher>,
    registry: Arc<ClientRegistry>,
    shutdown_tx: broadcast::Sender<()>,
    max_clients: usize,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl DaemonListener {
    /// Create a new listener.
    #[must_use]
    pub fn new(
        dispatcher: Arc<RequestDispatcher>,
        registry: Arc<ClientRegistry>,
        shutdown_tx: broadcast::Sender<()>,
    ) -> Self {
        Self {
            dispatcher,
            registry,
            shutdown_tx,
            max_clients: 64,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
        }
    }

    /// Set the maximum concurrent clients.
    #[must_use]
    pub const fn with_max_clients(mut self, n: usize) -> Self {
        self.max_clients = n;
        self
    }

    /// Bind and start accepting connections on `addr`.
    ///
    /// Runs until the shutdown broadcast fires.
    ///
    /// # Errors
    /// Returns an error if `TcpListener::bind` fails.
    pub async fn listen(self, addr: &str) -> Result<(), HandlerError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| HandlerError::Io(format!("bind {addr}: {e}")))?;

        let sem = Arc::new(tokio::sync::Semaphore::new(self.max_clients));
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            let accept_result = tokio::select! {
                res = listener.accept() => res,
                _ = shutdown_rx.recv() => break,
            };

            let (stream, peer) = match accept_result {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("DaemonListener: accept error: {e}");
                    continue;
                }
            };

            let permit = match sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("DaemonListener: max_clients reached, dropping {peer}");
                    continue;
                }
            };

            let handler = ClientHandler::new(
                Arc::clone(&self.dispatcher),
                Arc::clone(&self.registry),
                self.shutdown_tx.subscribe(),
            )
            .with_read_timeout(self.read_timeout)
            .with_write_timeout(self.write_timeout);

            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handler.run(stream, peer).await {
                    if e != HandlerError::Disconnected {
                        eprintln!("ClientHandler error for {peer}: {e}");
                    }
                }
            });
        }

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req(id: &str, method: &str) -> ClientRequest {
        ClientRequest::new(id, method)
    }

    // ── ClientRequest ─────────────────────────────────────────────────────────

    #[test]
    fn test_request_new() {
        let r = make_req("1", "status");
        assert_eq!(r.id, "1");
        assert_eq!(r.method, "status");
        assert!(r.params.is_empty());
    }

    #[test]
    fn test_request_with_param() {
        let r = make_req("2", "analyze").with_param("path", "/bin/ls");
        assert_eq!(r.params["path"], serde_json::Value::String("/bin/ls".into()));
    }

    #[test]
    fn test_request_roundtrip() {
        let r = make_req("3", "analyze").with_param("depth", "5");
        let line = r.to_line().unwrap();
        let parsed = ClientRequest::from_line(&line).unwrap();
        assert_eq!(parsed.id, "3");
        assert_eq!(parsed.method, "analyze");
    }

    #[test]
    fn test_request_from_invalid_json() {
        assert!(ClientRequest::from_line("{not json}").is_err());
    }

    #[test]
    fn test_request_display() {
        let r = make_req("4", "health");
        let s = r.to_string();
        assert!(s.contains("health"));
    }

    // ── ClientResponse ────────────────────────────────────────────────────────

    #[test]
    fn test_response_success() {
        let r = ClientResponse::success("1", "all good");
        assert!(r.ok);
        assert!(r.result.is_none());
    }

    #[test]
    fn test_response_failure() {
        let r = ClientResponse::failure("1", "bad method");
        assert!(!r.ok);
    }

    #[test]
    fn test_response_with_result() {
        let r = ClientResponse::success("1", "ok")
            .with_result(serde_json::json!({"count": 3}));
        assert!(r.result.is_some());
    }

    #[test]
    fn test_response_roundtrip() {
        let r = ClientResponse::success("5", "done")
            .with_result(serde_json::json!({"x": 1}));
        let line = r.to_line().unwrap();
        let parsed = ClientResponse::from_line(&line).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.id, "5");
    }

    #[test]
    fn test_response_display() {
        let r = ClientResponse::failure("6", "err");
        let s = r.to_string();
        assert!(s.contains("err"));
    }

    // ── RequestDispatcher ─────────────────────────────────────────────────────

    #[test]
    fn test_dispatcher_registers_handler() {
        let d = RequestDispatcher::new();
        d.register("ping", |req| ClientResponse::success(req.id, "pong"));
        assert!(d.has_handler("ping"));
        assert_eq!(d.handler_count(), 1);
    }

    #[test]
    fn test_dispatcher_dispatch_known() {
        let d = RequestDispatcher::new();
        d.register("ping", |req| ClientResponse::success(req.id, "pong"));
        let resp = d.dispatch(make_req("10", "ping"));
        assert!(resp.ok);
        assert_eq!(resp.message, "pong");
    }

    #[test]
    fn test_dispatcher_dispatch_unknown() {
        let d = RequestDispatcher::new();
        let resp = d.dispatch(make_req("11", "nope"));
        assert!(!resp.ok);
        assert!(resp.message.contains("not found"));
    }

    #[test]
    fn test_dispatcher_counts() {
        let d = RequestDispatcher::new();
        d.register("ok", |req| ClientResponse::success(req.id, "ok"));
        d.dispatch(make_req("12", "ok"));
        d.dispatch(make_req("13", "missing"));
        assert_eq!(d.request_count(), 2);
        assert_eq!(d.error_count(), 1);
    }

    #[test]
    fn test_dispatcher_deregister() {
        let d = RequestDispatcher::new();
        d.register("x", |req| ClientResponse::success(req.id, "x"));
        assert!(d.deregister("x"));
        assert!(!d.has_handler("x"));
        assert!(!d.deregister("x")); // already removed
    }

    #[test]
    fn test_dispatcher_replace_handler() {
        let d = RequestDispatcher::new();
        d.register("greet", |req| ClientResponse::success(req.id, "hello"));
        d.register("greet", |req| ClientResponse::success(req.id, "hi"));
        let resp = d.dispatch(make_req("14", "greet"));
        assert_eq!(resp.message, "hi");
    }

    // ── ClientRegistry ────────────────────────────────────────────────────────

    #[test]
    fn test_registry_register_deregister() {
        let reg = ClientRegistry::new();
        let id = reg.register("127.0.0.1:1234");
        assert!(reg.contains(id));
        assert_eq!(reg.count(), 1);
        reg.deregister(id);
        assert!(!reg.contains(id));
    }

    #[test]
    fn test_registry_record_request() {
        let reg = ClientRegistry::new();
        let id = reg.register("127.0.0.1:9999");
        reg.record_request(id, true);
        reg.record_request(id, false);
        let snap = reg.snapshot();
        let info = snap.iter().find(|c| c.client_id == id).unwrap();
        assert_eq!(info.request_count, 2);
        assert_eq!(info.error_count, 1);
    }

    #[test]
    fn test_registry_snapshot_empty() {
        let reg = ClientRegistry::new();
        assert!(reg.snapshot().is_empty());
    }

    #[test]
    fn test_client_info_connection_age() {
        let info = ClientInfo::new(1, "10.0.0.1:5000");
        let age = info.connection_age();
        assert!(age.as_secs() <= 2);
    }

    #[test]
    fn test_registry_multiple_clients() {
        let reg = ClientRegistry::new();
        let ids: Vec<u64> = (0..5).map(|i| reg.register(format!("10.0.0.1:{}", 4000 + i))).collect();
        assert_eq!(reg.count(), 5);
        for id in &ids {
            reg.deregister(*id);
        }
        assert_eq!(reg.count(), 0);
    }
}
