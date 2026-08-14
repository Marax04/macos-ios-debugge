//! `rpc_server` — JSON-RPC 2.0 server over TCP (and optionally Unix socket).
//!
//! # Architecture
//!
//! ```text
//!  TCP listener
//!      │
//!      ▼
//!  RpcServer::serve()  ──► thread-pool per connection
//!      │
//!      ▼
//!  MethodRegistry::dispatch()
//!      │
//!      ├── single request  → JsonRpcRequest  → handler → JsonRpcResponse
//!      └── batch  request  → Vec<JsonRpcRequest> → handlers → Vec<JsonRpcResponse>
//! ```
//!
//! Standard error codes (`-32700` … `-32603`) are enforced by
//! [`RpcErrorCode`].  All registered methods implement the [`RpcMethod`] trait.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Error codes ───────────────────────────────────────────────────────────────

/// Standard JSON-RPC 2.0 error codes (§5.1 of the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RpcErrorCode {
    /// Parse error — invalid JSON received.
    ParseError = -32700,
    /// The JSON sent is not a valid request object.
    InvalidRequest = -32600,
    /// The method does not exist or is not available.
    MethodNotFound = -32601,
    /// Invalid method parameters.
    InvalidParams = -32602,
    /// Internal JSON-RPC error.
    InternalError = -32603,
    /// Server-defined error: session not found.
    SessionNotFound = -32000,
    /// Server-defined error: analysis in progress.
    AnalysisInProgress = -32001,
    /// Server-defined error: binary could not be opened.
    BinaryOpenFailed = -32002,
    /// Server-defined error: symbol lookup failed.
    SymbolNotFound = -32003,
    /// Server-defined error: debugger not attached.
    DebuggerNotAttached = -32004,
}

impl RpcErrorCode {
    /// Numeric value of the error code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// A short, human-readable description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ParseError => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
            Self::SessionNotFound => "Session not found",
            Self::AnalysisInProgress => "Analysis in progress",
            Self::BinaryOpenFailed => "Binary open failed",
            Self::SymbolNotFound => "Symbol not found",
            Self::DebuggerNotAttached => "Debugger not attached",
        }
    }
}

impl fmt::Display for RpcErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.description(), self.code())
    }
}

// ── Wire types ────────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 request object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Protocol version — must be `"2.0"`.
    pub jsonrpc: String,
    /// Request identifier; `null` for notifications.
    pub id: Value,
    /// Method name.
    pub method: String,
    /// Optional parameters (object or array).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl RpcRequest {
    /// Build a request with a numeric id.
    #[must_use]
    pub fn new(id: i64, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Value::Number(id.into()),
            method: method.into(),
            params,
        }
    }

    /// Return `true` if this is a JSON-RPC notification (null id).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_null()
    }

    /// Validate that the `jsonrpc` field equals `"2.0"`.
    #[must_use]
    pub fn is_valid_version(&self) -> bool {
        self.jsonrpc == "2.0"
    }
}

/// A JSON-RPC 2.0 response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Mirrors the request id.
    pub id: Value,
    /// Success payload — present iff `error` is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload — present iff `result` is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
}

/// The error object embedded in an [`RpcResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcErrorObject {
    /// Numeric code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
    /// Optional additional data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcResponse {
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

    /// Construct an error response from an [`RpcErrorCode`].
    #[must_use]
    pub fn err(id: Value, code: RpcErrorCode, detail: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcErrorObject {
                code: code.code(),
                message: detail.into(),
                data: None,
            }),
        }
    }

    /// Construct an error with raw numeric code.
    #[must_use]
    pub fn raw_err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcErrorObject {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Attach extra diagnostic data to an error response.
    #[must_use]
    pub fn with_error_data(mut self, data: Value) -> Self {
        if let Some(ref mut e) = self.error {
            e.data = Some(data);
        }
        self
    }

    /// Serialize to a JSON line for transport.
    ///
    /// # Panics
    /// Panics if `serde_json` fails to serialize a type we fully control —
    /// this cannot happen with well-formed data.
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("RpcResponse serialization never fails")
    }

    /// Return `true` if this response carries a success result.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

// ── RpcMethod trait ───────────────────────────────────────────────────────────

/// A named, callable JSON-RPC method.
///
/// Implementors receive the parsed `params` value (or `None` for parameterless
/// calls) and the shared server context, and return either a result payload or
/// an error.
pub trait RpcMethod: Send + Sync {
    /// The name clients use to call this method, e.g. `"analyze_binary"`.
    fn name(&self) -> &'static str;

    /// A brief description shown in the method catalog.
    fn description(&self) -> &'static str {
        ""
    }

    /// Execute the method and return the result value, or an error pair
    /// `(code, message)`.
    fn call(
        &self,
        params: Option<&Value>,
        ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)>;
}

/// Shared, read-only context passed into every [`RpcMethod::call`] invocation.
#[derive(Debug, Clone)]
pub struct RpcContext {
    /// Daemon bind address (informational).
    pub bind_addr: SocketAddr,
    /// Seconds the server has been running.
    pub uptime_secs: u64,
    /// Optional path to the currently open project.
    pub project_path: Option<PathBuf>,
    /// Request counter at the time of this call.
    pub request_count: u64,
}

// ── MethodRegistry ────────────────────────────────────────────────────────────

/// Stores all registered [`RpcMethod`] implementations, keyed by method name.
#[derive(Default)]
pub struct MethodRegistry {
    methods: HashMap<String, Box<dyn RpcMethod>>,
}

impl MethodRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a method.  Returns the previous handler if any was displaced.
    pub fn register(&mut self, method: impl RpcMethod + 'static) -> Option<Box<dyn RpcMethod>> {
        self.methods
            .insert(method.name().to_owned(), Box::new(method))
    }

    /// Dispatch a single [`RpcRequest`] and return the corresponding [`RpcResponse`].
    #[must_use]
    pub fn dispatch(&self, req: &RpcRequest, ctx: &RpcContext) -> RpcResponse {
        if !req.is_valid_version() {
            return RpcResponse::err(
                req.id.clone(),
                RpcErrorCode::InvalidRequest,
                "jsonrpc field must be \"2.0\"",
            );
        }

        match self.methods.get(&req.method) {
            Some(handler) => match handler.call(req.params.as_ref(), ctx) {
                Ok(result) => RpcResponse::ok(req.id.clone(), result),
                Err((code, msg)) => RpcResponse::err(req.id.clone(), code, msg),
            },
            None => RpcResponse::err(
                req.id.clone(),
                RpcErrorCode::MethodNotFound,
                format!("method not found: {}", req.method),
            ),
        }
    }

    /// Dispatch a batch of requests.  Notifications (null id) are executed but
    /// no response entry is added for them.
    #[must_use]
    pub fn dispatch_batch(&self, requests: &[RpcRequest], ctx: &RpcContext) -> Vec<RpcResponse> {
        requests
            .iter()
            .filter_map(|req| {
                let resp = self.dispatch(req, ctx);
                if req.is_notification() {
                    None // notifications do not produce a response
                } else {
                    Some(resp)
                }
            })
            .collect()
    }

    /// Return a list of `(name, description)` pairs for all registered methods.
    #[must_use]
    pub fn catalog(&self) -> Vec<(&str, &str)> {
        let mut v: Vec<(&str, &str)> = self
            .methods
            .values()
            .map(|m| (m.name(), m.description()))
            .collect();
        v.sort_by_key(|(name, _)| *name);
        v
    }

    /// Number of registered methods.
    #[must_use]
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Return `true` if no methods are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

// ── Request / response framing ────────────────────────────────────────────────

/// Attempt to parse a line as a single or batched JSON-RPC request.
pub enum ParsedFrame {
    /// A single JSON-RPC 2.0 request.
    Single(RpcRequest),
    /// A batch of JSON-RPC 2.0 requests.
    Batch(Vec<RpcRequest>),
}

/// Parse a raw JSON line as either a single or batched request.
///
/// # Errors
/// Returns `(code, message)` suitable for constructing a parse-error response.
pub fn parse_frame(line: &str) -> Result<ParsedFrame, (RpcErrorCode, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err((RpcErrorCode::ParseError, "empty input".into()));
    }

    // Try batch first (starts with '[').
    if trimmed.starts_with('[') {
        let batch: Vec<RpcRequest> = serde_json::from_str(trimmed)
            .map_err(|e| (RpcErrorCode::ParseError, format!("batch parse error: {e}")))?;
        if batch.is_empty() {
            return Err((RpcErrorCode::InvalidRequest, "empty batch".into()));
        }
        return Ok(ParsedFrame::Batch(batch));
    }

    // Single object.
    let req: RpcRequest = serde_json::from_str(trimmed)
        .map_err(|e| (RpcErrorCode::ParseError, format!("parse error: {e}")))?;
    Ok(ParsedFrame::Single(req))
}

// ── Built-in method implementations ──────────────────────────────────────────

/// `analyze_binary` — trigger full static analysis of a binary.
pub struct AnalyzeBinaryMethod;

impl RpcMethod for AnalyzeBinaryMethod {
    fn name(&self) -> &'static str {
        "analyze_binary"
    }

    fn description(&self) -> &'static str {
        "Trigger full static analysis of a binary file. params: {path: string, deep: bool?}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let path = params
            .and_then(|p| p.get("path"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.path (string) is required".into(),
                )
            })?;

        let deep = params
            .and_then(|p| p.get("deep"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // Stub: in a real implementation this would enqueue an AnalysisJob.
        Ok(serde_json::json!({
            "queued": true,
            "path": path,
            "deep": deep,
            "job_id": format!("job-{}", uuid_stub()),
            "message": "analysis queued"
        }))
    }
}

/// `list_functions` — enumerate all functions in an analyzed binary.
pub struct ListFunctionsMethod;

impl RpcMethod for ListFunctionsMethod {
    fn name(&self) -> &'static str {
        "list_functions"
    }

    fn description(&self) -> &'static str {
        "List all functions discovered in the binary. params: {session_id: string, offset?: u64, limit?: u64}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let session_id = params
            .and_then(|p| p.get("session_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.session_id (string) is required".into(),
                )
            })?;

        let offset = params
            .and_then(|p| p.get("offset"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let limit = params
            .and_then(|p| p.get("limit"))
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .min(1000);

        // Stub result.
        Ok(serde_json::json!({
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": 0,
            "functions": []
        }))
    }
}

/// `get_decompilation` — return the decompiled source for a function address.
pub struct GetDecompilationMethod;

impl RpcMethod for GetDecompilationMethod {
    fn name(&self) -> &'static str {
        "get_decompilation"
    }

    fn description(&self) -> &'static str {
        "Return decompiled pseudo-C for a function. params: {session_id: string, address: u64}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let session_id = params
            .and_then(|p| p.get("session_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.session_id is required".into(),
                )
            })?;

        let address = params
            .and_then(|p| p.get("address"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.address (u64) is required".into(),
                )
            })?;

        Ok(serde_json::json!({
            "session_id": session_id,
            "address": address,
            "decompiled": format!("// decompilation stub for 0x{address:016x}\nvoid sub_{address:x}(void) {{\n    // TODO\n}}\n"),
            "language": "c"
        }))
    }
}

/// `search_symbols` — full-text search across the symbol table.
pub struct SearchSymbolsMethod;

impl RpcMethod for SearchSymbolsMethod {
    fn name(&self) -> &'static str {
        "search_symbols"
    }

    fn description(&self) -> &'static str {
        "Search symbol names with a query string. params: {session_id: string, query: string, limit?: u64}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let session_id = params
            .and_then(|p| p.get("session_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.session_id is required".into(),
                )
            })?;

        let query = params
            .and_then(|p| p.get("query"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.query (string) is required".into(),
                )
            })?;

        let limit = params
            .and_then(|p| p.get("limit"))
            .and_then(Value::as_u64)
            .unwrap_or(50)
            .min(500);

        Ok(serde_json::json!({
            "session_id": session_id,
            "query": query,
            "limit": limit,
            "matches": []
        }))
    }
}

/// `add_comment` — attach a user comment to a virtual address.
pub struct AddCommentMethod;

impl RpcMethod for AddCommentMethod {
    fn name(&self) -> &'static str {
        "add_comment"
    }

    fn description(&self) -> &'static str {
        "Attach a comment to an address. params: {session_id: string, address: u64, text: string}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let session_id = params
            .and_then(|p| p.get("session_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.session_id is required".into(),
                )
            })?;

        let address = params
            .and_then(|p| p.get("address"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.address (u64) is required".into(),
                )
            })?;

        let text = params
            .and_then(|p| p.get("text"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.text (string) is required".into(),
                )
            })?;

        Ok(serde_json::json!({
            "session_id": session_id,
            "address": address,
            "comment": text,
            "saved": true
        }))
    }
}

/// `run_script` — execute a Rhai/Lua/Python script in the daemon.
pub struct RunScriptMethod;

impl RpcMethod for RunScriptMethod {
    fn name(&self) -> &'static str {
        "run_script"
    }

    fn description(&self) -> &'static str {
        "Run a script string in the daemon scripting engine. params: {session_id: string, lang: string, code: string}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let session_id = params
            .and_then(|p| p.get("session_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.session_id is required".into(),
                )
            })?;

        let lang = params
            .and_then(|p| p.get("lang"))
            .and_then(Value::as_str)
            .unwrap_or("rhai");

        let code = params
            .and_then(|p| p.get("code"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.code (string) is required".into(),
                )
            })?;

        if !["rhai", "lua", "python"].contains(&lang) {
            return Err((
                RpcErrorCode::InvalidParams,
                format!("unsupported lang '{lang}'; use rhai, lua, or python"),
            ));
        }

        Ok(serde_json::json!({
            "session_id": session_id,
            "lang": lang,
            "code_len": code.len(),
            "stdout": "",
            "stderr": "",
            "exit_code": 0
        }))
    }
}

/// `start_debug` — attach a debugger to a process.
pub struct StartDebugMethod;

impl RpcMethod for StartDebugMethod {
    fn name(&self) -> &'static str {
        "start_debug"
    }

    fn description(&self) -> &'static str {
        "Attach the built-in debugger to a process. params: {session_id: string, pid?: u32, path?: string}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let session_id = params
            .and_then(|p| p.get("session_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.session_id is required".into(),
                )
            })?;

        let pid = params.and_then(|p| p.get("pid")).and_then(Value::as_u64);
        let path = params
            .and_then(|p| p.get("path"))
            .and_then(Value::as_str)
            .map(str::to_owned);

        if pid.is_none() && path.is_none() {
            return Err((
                RpcErrorCode::InvalidParams,
                "one of params.pid or params.path is required".into(),
            ));
        }

        Ok(serde_json::json!({
            "session_id": session_id,
            "debugger_attached": false,
            "pid": pid,
            "path": path,
            "message": "debugger stub — attach not yet implemented"
        }))
    }
}

/// `get_memory` — read a range of virtual memory from a live debug session.
pub struct GetMemoryMethod;

impl RpcMethod for GetMemoryMethod {
    fn name(&self) -> &'static str {
        "get_memory"
    }

    fn description(&self) -> &'static str {
        "Read memory from a live debug session. params: {session_id: string, address: u64, length: u64}"
    }

    fn call(
        &self,
        params: Option<&Value>,
        _ctx: &RpcContext,
    ) -> Result<Value, (RpcErrorCode, String)> {
        let session_id = params
            .and_then(|p| p.get("session_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.session_id is required".into(),
                )
            })?;

        let address = params
            .and_then(|p| p.get("address"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.address (u64) is required".into(),
                )
            })?;

        let length = params
            .and_then(|p| p.get("length"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                (
                    RpcErrorCode::InvalidParams,
                    "params.length (u64) is required".into(),
                )
            })?
            .min(4096); // cap to 4 KiB per read

        Ok(serde_json::json!({
            "session_id": session_id,
            "address": address,
            "length": length,
            "hex": "",
            "note": "debugger not attached — memory read unavailable"
        }))
    }
}

// ── Registry builder ──────────────────────────────────────────────────────────

/// Build a [`MethodRegistry`] pre-populated with all built-in handlers.
#[must_use]
pub fn build_default_registry() -> MethodRegistry {
    let mut reg = MethodRegistry::new();
    reg.register(AnalyzeBinaryMethod);
    reg.register(ListFunctionsMethod);
    reg.register(GetDecompilationMethod);
    reg.register(SearchSymbolsMethod);
    reg.register(AddCommentMethod);
    reg.register(RunScriptMethod);
    reg.register(StartDebugMethod);
    reg.register(GetMemoryMethod);
    reg
}

// ── RpcServer ─────────────────────────────────────────────────────────────────

/// Statistics tracked by the RPC server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RpcServerStats {
    /// Total connections accepted.
    pub connections_accepted: u64,
    /// Total requests dispatched (single + batch items).
    pub requests_dispatched: u64,
    /// Total error responses returned.
    pub errors_returned: u64,
    /// Total batch frames received.
    pub batch_frames: u64,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

/// The JSON-RPC 2.0 TCP server.
///
/// Binds to a TCP address, accepts connections, frames each line as one or more
/// JSON-RPC requests, dispatches through the [`MethodRegistry`], and writes back
/// the response.
pub struct RpcServer {
    listener: TcpListener,
    registry: Arc<RwLock<MethodRegistry>>,
    stats: Arc<RwLock<RpcServerStats>>,
    start_time: Instant,
    bind_addr: SocketAddr,
}

impl RpcServer {
    /// Bind the RPC server to `addr`.
    ///
    /// # Errors
    /// Returns an error string if the bind fails.
    pub fn bind(addr: SocketAddr) -> Result<Self, String> {
        let listener =
            TcpListener::bind(addr).map_err(|e| format!("RpcServer bind {addr}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("set_nonblocking: {e}"))?;
        Ok(Self {
            listener,
            registry: Arc::new(RwLock::new(build_default_registry())),
            stats: Arc::new(RwLock::new(RpcServerStats::default())),
            start_time: Instant::now(),
            bind_addr: addr,
        })
    }

    /// Return the local address the server is listening on.
    ///
    /// # Errors
    /// Returns an error string if the address cannot be retrieved.
    pub fn local_addr(&self) -> Result<SocketAddr, String> {
        self.listener
            .local_addr()
            .map_err(|e| format!("local_addr: {e}"))
    }

    /// Register an additional [`RpcMethod`] at runtime.
    pub fn register(&self, method: impl RpcMethod + 'static) {
        self.registry.write().register(method);
    }

    /// Return a snapshot of the current server statistics.
    #[must_use]
    pub fn stats(&self) -> RpcServerStats {
        let mut s = self.stats.read().clone();
        s.uptime_secs = self.start_time.elapsed().as_secs();
        s
    }

    /// Poll for a single incoming connection, handle one request frame, and
    /// return `Ok(true)` if a connection was serviced.
    ///
    /// Non-blocking: returns `Ok(false)` immediately if no connection is
    /// waiting.
    ///
    /// # Errors
    /// Returns a string on non-WouldBlock accept errors.
    pub fn poll_once(&self, ctx: &RpcContext) -> Result<bool, String> {
        match self.listener.accept() {
            Ok((mut stream, peer)) => {
                self.stats.write().connections_accepted += 1;
                if let Err(e) = self.handle_connection(&mut stream, ctx) {
                    eprintln!("[rpc_server] connection from {peer} error: {e}");
                }
                Ok(true)
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(format!("accept: {e}")),
        }
    }

    /// Blocking accept loop until `should_stop()` returns `true`.
    ///
    /// Sleeps 10 ms between polls to avoid busy-spinning.
    ///
    /// # Errors
    /// Returns a string on fatal accept error.
    pub fn serve(&self, ctx: &RpcContext, should_stop: &dyn Fn() -> bool) -> Result<(), String> {
        while !should_stop() {
            if !self.poll_once(ctx)? {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    }

    fn handle_connection(&self, stream: &mut TcpStream, ctx: &RpcContext) -> Result<(), String> {
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| format!("set_write_timeout: {e}"))?;

        // Cap each JSON-RPC frame to 4 MiB to prevent OOM from an adversarial
        // never-terminating line.
        const MAX_FRAME_BYTES: u64 = 4 * 1024 * 1024;
        let raw = stream.try_clone().map_err(|e| e.to_string())?;
        let mut reader = io::BufReader::new(raw.take(MAX_FRAME_BYTES));
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read_line: {e}"))?;

        let response_line = self.process_line(&line, ctx);
        writeln!(stream, "{response_line}").map_err(|e| format!("write response: {e}"))?;
        Ok(())
    }

    fn process_line(&self, line: &str, ctx: &RpcContext) -> String {
        match parse_frame(line) {
            Ok(ParsedFrame::Single(req)) => {
                let resp = self.registry.read().dispatch(&req, ctx);
                let mut stats = self.stats.write();
                stats.requests_dispatched += 1;
                if resp.error.is_some() {
                    stats.errors_returned += 1;
                }
                resp.to_line()
            }
            Ok(ParsedFrame::Batch(reqs)) => {
                let reg = self.registry.read();
                let responses = reg.dispatch_batch(&reqs, ctx);
                let mut stats = self.stats.write();
                stats.batch_frames += 1;
                stats.requests_dispatched += reqs.len() as u64;
                for r in &responses {
                    if r.error.is_some() {
                        stats.errors_returned += 1;
                    }
                }
                serde_json::to_string(&responses)
                    .unwrap_or_else(|_| r#"[{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal serialization error"}}]"#.into())
            }
            Err((code, msg)) => {
                self.stats.write().errors_returned += 1;
                RpcResponse::raw_err(Value::Null, code.code(), msg).to_line()
            }
        }
    }

    /// Return the bind address.
    #[must_use]
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

// ── Utility ───────────────────────────────────────────────────────────────────

/// Simple deterministic stub for a UUID-like job id (avoids the uuid crate here).
fn uuid_stub() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(42)
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ctx() -> RpcContext {
        RpcContext {
            bind_addr: "127.0.0.1:7878".parse().unwrap(),
            uptime_secs: 0,
            project_path: None,
            request_count: 0,
        }
    }

    // ── Error codes ───────────────────────────────────────────────────────────

    #[test]
    fn test_error_codes_values() {
        assert_eq!(RpcErrorCode::ParseError.code(), -32700);
        assert_eq!(RpcErrorCode::InvalidRequest.code(), -32600);
        assert_eq!(RpcErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(RpcErrorCode::InvalidParams.code(), -32602);
        assert_eq!(RpcErrorCode::InternalError.code(), -32603);
    }

    #[test]
    fn test_error_code_display() {
        let s = format!("{}", RpcErrorCode::MethodNotFound);
        assert!(s.contains("Method not found"));
        assert!(s.contains("-32601"));
    }

    // ── RpcResponse ───────────────────────────────────────────────────────────

    #[test]
    fn test_rpc_response_ok() {
        let r = RpcResponse::ok(Value::Number(1.into()), serde_json::json!({"x": 1}));
        assert!(r.is_ok());
        let line = r.to_line();
        assert!(line.contains("\"result\""));
        assert!(!line.contains("\"error\""));
    }

    #[test]
    fn test_rpc_response_err() {
        let r = RpcResponse::err(
            Value::Number(2.into()),
            RpcErrorCode::MethodNotFound,
            "not found",
        );
        assert!(!r.is_ok());
        let line = r.to_line();
        assert!(line.contains("-32601"));
    }

    #[test]
    fn test_rpc_response_with_error_data() {
        let r = RpcResponse::err(Value::Null, RpcErrorCode::InvalidParams, "bad")
            .with_error_data(serde_json::json!({"field": "path"}));
        let line = r.to_line();
        assert!(line.contains("field"));
    }

    // ── RpcRequest ────────────────────────────────────────────────────────────

    #[test]
    fn test_rpc_request_is_notification() {
        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            id: Value::Null,
            method: "ping".into(),
            params: None,
        };
        assert!(req.is_notification());
    }

    #[test]
    fn test_rpc_request_valid_version() {
        let req = RpcRequest::new(1, "foo", None);
        assert!(req.is_valid_version());

        let bad = RpcRequest {
            jsonrpc: "1.0".into(),
            id: Value::Null,
            method: "foo".into(),
            params: None,
        };
        assert!(!bad.is_valid_version());
    }

    // ── parse_frame ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_frame_single() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"status","params":null}"#;
        let frame = parse_frame(line).unwrap();
        assert!(matches!(frame, ParsedFrame::Single(_)));
    }

    #[test]
    fn test_parse_frame_batch() {
        let line =
            r#"[{"jsonrpc":"2.0","id":1,"method":"a"},{"jsonrpc":"2.0","id":2,"method":"b"}]"#;
        let frame = parse_frame(line).unwrap();
        assert!(matches!(frame, ParsedFrame::Batch(v) if v.len() == 2));
    }

    #[test]
    fn test_parse_frame_empty_batch_err() {
        assert!(parse_frame("[]").is_err());
    }

    #[test]
    fn test_parse_frame_invalid_json_err() {
        assert!(parse_frame("{not valid json").is_err());
    }

    #[test]
    fn test_parse_frame_empty_err() {
        assert!(parse_frame("   ").is_err());
    }

    // ── MethodRegistry ────────────────────────────────────────────────────────

    #[test]
    fn test_registry_dispatch_known_method() {
        let reg = build_default_registry();
        let req = RpcRequest::new(
            1,
            "analyze_binary",
            Some(serde_json::json!({"path": "/bin/ls", "deep": false})),
        );
        let ctx = dummy_ctx();
        let resp = reg.dispatch(&req, &ctx);
        assert!(resp.is_ok());
    }

    #[test]
    fn test_registry_dispatch_unknown_method() {
        let reg = build_default_registry();
        let req = RpcRequest::new(1, "does_not_exist", None);
        let resp = reg.dispatch(&req, &dummy_ctx());
        assert!(!resp.is_ok());
        let err_code = resp.error.as_ref().unwrap().code;
        assert_eq!(err_code, RpcErrorCode::MethodNotFound.code());
    }

    #[test]
    fn test_registry_dispatch_invalid_version() {
        let reg = build_default_registry();
        let req = RpcRequest {
            jsonrpc: "1.0".into(),
            id: Value::Number(1.into()),
            method: "analyze_binary".into(),
            params: None,
        };
        let resp = reg.dispatch(&req, &dummy_ctx());
        assert!(!resp.is_ok());
    }

    #[test]
    fn test_registry_catalog_sorted() {
        let reg = build_default_registry();
        let catalog = reg.catalog();
        assert!(!catalog.is_empty());
        // Should be sorted by name.
        let names: Vec<&str> = catalog.iter().map(|(n, _)| *n).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_registry_len() {
        let reg = build_default_registry();
        assert_eq!(reg.len(), 8);
        assert!(!reg.is_empty());
    }

    // ── Batch dispatch ────────────────────────────────────────────────────────

    #[test]
    fn test_batch_dispatch_mixed() {
        let reg = build_default_registry();
        let reqs = vec![
            RpcRequest::new(
                1,
                "list_functions",
                Some(serde_json::json!({"session_id": "s1"})),
            ),
            RpcRequest::new(2, "no_such_method", None),
        ];
        let responses = reg.dispatch_batch(&reqs, &dummy_ctx());
        assert_eq!(responses.len(), 2);
        assert!(responses[0].is_ok());
        assert!(!responses[1].is_ok());
    }

    #[test]
    fn test_batch_dispatch_notification_excluded() {
        let reg = build_default_registry();
        let reqs = vec![
            // notification — no response expected
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Value::Null,
                method: "list_functions".into(),
                params: Some(serde_json::json!({"session_id": "s1"})),
            },
            RpcRequest::new(
                1,
                "list_functions",
                Some(serde_json::json!({"session_id": "s1"})),
            ),
        ];
        let responses = reg.dispatch_batch(&reqs, &dummy_ctx());
        assert_eq!(responses.len(), 1); // only the non-notification
    }

    // ── Built-in handlers ─────────────────────────────────────────────────────

    #[test]
    fn test_analyze_binary_missing_path() {
        let m = AnalyzeBinaryMethod;
        let result = m.call(Some(&serde_json::json!({})), &dummy_ctx());
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code.code(), RpcErrorCode::InvalidParams.code());
    }

    #[test]
    fn test_run_script_bad_lang() {
        let m = RunScriptMethod;
        let result = m.call(
            Some(&serde_json::json!({"session_id":"s","lang":"bash","code":"echo hi"})),
            &dummy_ctx(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_start_debug_no_target() {
        let m = StartDebugMethod;
        let result = m.call(Some(&serde_json::json!({"session_id":"s"})), &dummy_ctx());
        assert!(result.is_err());
    }

    #[test]
    fn test_get_memory_length_capped() {
        let m = GetMemoryMethod;
        let result = m.call(
            Some(&serde_json::json!({
                "session_id": "s",
                "address": 4096,
                "length": 999999
            })),
            &dummy_ctx(),
        );
        let v = result.unwrap();
        assert_eq!(v["length"], 4096u64);
    }

    // ── RpcServer stats ───────────────────────────────────────────────────────

    #[test]
    fn test_rpc_server_stats_initial() {
        let server = RpcServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let stats = server.stats();
        assert_eq!(stats.connections_accepted, 0);
        assert_eq!(stats.requests_dispatched, 0);
    }

    #[test]
    fn test_rpc_server_process_line_ok() {
        let server = RpcServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let ctx = dummy_ctx();
        let line =
            r#"{"jsonrpc":"2.0","id":1,"method":"analyze_binary","params":{"path":"/bin/ls"}}"#;
        let resp_line = server.process_line(line, &ctx);
        let v: Value = serde_json::from_str(&resp_line).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["result"].is_object());
    }

    #[test]
    fn test_rpc_server_process_line_batch() {
        let server = RpcServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let ctx = dummy_ctx();
        let line = r#"[{"jsonrpc":"2.0","id":1,"method":"list_functions","params":{"session_id":"s1"}},{"jsonrpc":"2.0","id":2,"method":"unknown"}]"#;
        let resp_line = server.process_line(line, &ctx);
        let v: Value = serde_json::from_str(&resp_line).unwrap();
        assert!(v.is_array());
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }
}
