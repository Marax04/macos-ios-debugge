//! Plugin IPC protocol: structured messages for host ↔ plugin communication.
//!
//! Provides [`IpcMessage`], [`IpcResponse`], [`PluginIpcProtocol`] and the
//! [`send_ipc`] top-level function.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── IpcMessageKind ────────────────────────────────────────────────────────────

/// Discriminator for the category of an IPC message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpcMessageKind {
    /// Call a function on the remote end.
    Call,
    /// Reply to a previous `Call`.
    Reply,
    /// Asynchronous event notification (no reply expected).
    Event,
    /// Subscription request: ask the remote to send events of a given topic.
    Subscribe,
    /// Cancellation of an in-flight request.
    Cancel,
    /// Heartbeat / keep-alive ping.
    Ping,
    /// Heartbeat response.
    Pong,
    /// Shutdown request.
    Shutdown,
}

impl IpcMessageKind {
    /// Return the canonical lowercase name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Reply => "reply",
            Self::Event => "event",
            Self::Subscribe => "subscribe",
            Self::Cancel => "cancel",
            Self::Ping => "ping",
            Self::Pong => "pong",
            Self::Shutdown => "shutdown",
        }
    }
}

impl fmt::Display for IpcMessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── IpcPayload ────────────────────────────────────────────────────────────────

/// The payload of an IPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcPayload {
    /// No payload.
    None,
    /// A structured JSON-serialisable value (represented as a string for portability).
    Json(String),
    /// Raw binary blob.
    Binary(Vec<u8>),
    /// A simple string value.
    Text(String),
    /// A key-value map.
    Map(HashMap<String, String>),
}

impl IpcPayload {
    /// Return `true` when the payload carries no data.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Return the payload as a byte count for logging.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Json(s) | Self::Text(s) => s.len(),
            Self::Binary(b) => b.len(),
            Self::Map(m) => m.iter().map(|(k, v)| k.len() + v.len() + 2).sum(),
        }
    }

    /// Return the payload as a text summary (first 64 chars of JSON/text, or binary length).
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::None => "(none)".into(),
            Self::Json(s) => {
                let s = s.trim();
                if s.len() > 64 {
                    // Find a valid UTF-8 boundary at or before byte 64.
                    let end = s.floor_char_boundary(64);
                    format!("{}…", &s[..end])
                } else {
                    s.to_string()
                }
            }
            Self::Text(s) => {
                if s.len() > 64 {
                    let end = s.floor_char_boundary(64);
                    format!("{}…", &s[..end])
                } else {
                    s.clone()
                }
            }
            Self::Binary(b) => format!("<binary {} bytes>", b.len()),
            Self::Map(m) => format!("<map {} entries>", m.len()),
        }
    }
}

impl fmt::Display for IpcPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── IpcMessage ────────────────────────────────────────────────────────────────

/// A message sent over the IPC channel.
#[derive(Debug, Clone)]
pub struct IpcMessage {
    /// Unique message identifier.
    pub id: u64,
    /// For `Reply` and `Cancel`: the `id` of the original `Call`.
    pub correlation_id: Option<u64>,
    /// Message category.
    pub kind: IpcMessageKind,
    /// For `Call` and `Event`: the operation or topic name.
    pub method: String,
    /// Message payload.
    pub payload: IpcPayload,
    /// UNIX timestamp (milliseconds) when the message was created.
    pub timestamp_ms: u64,
    /// Optional routing headers.
    pub headers: HashMap<String, String>,
}

impl IpcMessage {
    /// Create a new `Call` message.
    #[must_use]
    pub fn call(id: u64, method: impl Into<String>, payload: IpcPayload) -> Self {
        Self::new(id, IpcMessageKind::Call, method.into(), payload)
    }

    /// Create a new `Event` message.
    #[must_use]
    pub fn event(id: u64, topic: impl Into<String>, payload: IpcPayload) -> Self {
        Self::new(id, IpcMessageKind::Event, topic.into(), payload)
    }

    /// Create a ping message.
    #[must_use]
    pub fn ping(id: u64) -> Self {
        Self::new(id, IpcMessageKind::Ping, String::new(), IpcPayload::None)
    }

    /// Create a pong in response to a ping.
    #[must_use]
    pub fn pong(id: u64, ping_id: u64) -> Self {
        let mut m = Self::new(id, IpcMessageKind::Pong, String::new(), IpcPayload::None);
        m.correlation_id = Some(ping_id);
        m
    }

    /// Create a shutdown message.
    #[must_use]
    pub fn shutdown(id: u64) -> Self {
        Self::new(id, IpcMessageKind::Shutdown, String::new(), IpcPayload::None)
    }

    /// Build the base message struct.
    fn new(id: u64, kind: IpcMessageKind, method: String, payload: IpcPayload) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;
        Self {
            id,
            correlation_id: None,
            kind,
            method,
            payload,
            timestamp_ms,
            headers: HashMap::new(),
        }
    }

    /// Attach a header.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set the correlation id.
    #[must_use]
    pub const fn with_correlation(mut self, cid: u64) -> Self {
        self.correlation_id = Some(cid);
        self
    }

    /// Return a human-readable one-line description.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "[{}] id={} method={} payload={}",
            self.kind,
            self.id,
            if self.method.is_empty() { "(none)" } else { &self.method },
            self.payload.summary()
        )
    }
}

impl fmt::Display for IpcMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── IpcStatus ─────────────────────────────────────────────────────────────────

/// Status code embedded in an [`IpcResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpcStatus {
    /// The call completed successfully.
    Ok = 0,
    /// The method was not found on the remote end.
    MethodNotFound = 1,
    /// The caller did not have permission to call this method.
    PermissionDenied = 2,
    /// The payload was malformed or missing required fields.
    InvalidPayload = 3,
    /// The remote end encountered an internal error.
    InternalError = 4,
    /// The call timed out.
    Timeout = 5,
    /// The remote end is busy and the call was queued / dropped.
    Busy = 6,
    /// The channel is closed.
    ChannelClosed = 7,
}

impl IpcStatus {
    /// Return `true` when the status represents success.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Return `true` when the status represents an error.
    #[must_use]
    pub const fn is_err(self) -> bool {
        !self.is_ok()
    }

    /// Return the canonical string name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::MethodNotFound => "method_not_found",
            Self::PermissionDenied => "permission_denied",
            Self::InvalidPayload => "invalid_payload",
            Self::InternalError => "internal_error",
            Self::Timeout => "timeout",
            Self::Busy => "busy",
            Self::ChannelClosed => "channel_closed",
        }
    }
}

impl fmt::Display for IpcStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── IpcResponse ───────────────────────────────────────────────────────────────

/// A response to a `Call` message.
#[derive(Debug, Clone)]
pub struct IpcResponse {
    /// Unique response identifier.
    pub id: u64,
    /// The `id` of the `Call` this response belongs to.
    pub request_id: u64,
    /// Result status.
    pub status: IpcStatus,
    /// Response payload.
    pub payload: IpcPayload,
    /// UNIX timestamp (milliseconds) when the response was created.
    pub timestamp_ms: u64,
    /// Optional error detail string (non-empty when `status.is_err()`).
    pub error_detail: String,
}

impl IpcResponse {
    /// Create a successful response.
    #[must_use]
    pub fn ok(id: u64, request_id: u64, payload: IpcPayload) -> Self {
        Self::new(id, request_id, IpcStatus::Ok, payload, String::new())
    }

    /// Create an error response.
    #[must_use]
    pub fn error(id: u64, request_id: u64, status: IpcStatus, detail: impl Into<String>) -> Self {
        Self::new(id, request_id, status, IpcPayload::None, detail.into())
    }

    fn new(id: u64, request_id: u64, status: IpcStatus, payload: IpcPayload, error_detail: String) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;
        Self { id, request_id, status, payload, timestamp_ms, error_detail }
    }

    /// Return `true` when this response indicates success.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status.is_ok()
    }

    /// Return the payload text if the response is successful.
    #[must_use]
    pub const fn ok_text(&self) -> Option<&str> {
        if self.is_ok() {
            match &self.payload {
                IpcPayload::Text(s) | IpcPayload::Json(s) => Some(s.as_str()),
                _ => None,
            }
        } else {
            None
        }
    }
}

impl fmt::Display for IpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_ok() {
            write!(f, "IpcResponse[ok] req={} payload={}", self.request_id, self.payload.summary())
        } else {
            write!(
                f,
                "IpcResponse[{}] req={} detail={}",
                self.status, self.request_id, self.error_detail
            )
        }
    }
}

// ── IpcHandler ────────────────────────────────────────────────────────────────

/// A handler function registered for a specific IPC method.
pub type IpcHandler = Box<dyn Fn(&IpcMessage) -> IpcResponse + Send + Sync>;

// ── PluginIpcProtocol ─────────────────────────────────────────────────────────

/// Manages the IPC protocol between the host and a plugin.
///
/// The protocol supports:
/// - Registering named method handlers (call dispatch).
/// - Sending messages and logging their round-trips.
/// - Tracking pending calls and correlating replies.
/// - Emitting event notifications.
pub struct PluginIpcProtocol {
    /// Handlers keyed by method name.
    handlers: HashMap<String, IpcHandler>,
    /// Counter for generating unique message IDs.
    next_id: Arc<Mutex<u64>>,
    /// Log of all messages sent via this protocol instance.
    sent_log: Vec<IpcMessage>,
    /// Log of all responses received.
    response_log: Vec<IpcResponse>,
    /// Pending (un-replied) call IDs.
    pending: HashMap<u64, IpcMessage>,
    /// Maximum number of log entries to retain.
    max_log_size: usize,
}

impl fmt::Debug for PluginIpcProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PluginIpcProtocol {{ handlers: {}, pending: {}, sent: {} }}",
            self.handlers.len(),
            self.pending.len(),
            self.sent_log.len()
        )
    }
}

impl PluginIpcProtocol {
    /// Create a new protocol instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            next_id: Arc::new(Mutex::new(1)),
            sent_log: Vec::new(),
            response_log: Vec::new(),
            pending: HashMap::new(),
            max_log_size: 1024,
        }
    }

    /// Set the maximum number of log entries to retain.
    pub const fn set_max_log_size(&mut self, n: usize) {
        self.max_log_size = n;
    }

    /// Register a handler for the given method name.
    pub fn register_handler(&mut self, method: impl Into<String>, handler: IpcHandler) {
        self.handlers.insert(method.into(), handler);
    }

    /// Unregister a handler, returning `true` if it was present.
    pub fn unregister_handler(&mut self, method: &str) -> bool {
        self.handlers.remove(method).is_some()
    }

    /// Return the list of all registered method names.
    #[must_use]
    pub fn registered_methods(&self) -> Vec<&str> {
        self.handlers.keys().map(String::as_str).collect()
    }

    /// Generate and return a fresh message ID.
    fn next_id(&self) -> u64 {
        let mut guard = self.next_id.lock().unwrap();
        let id = *guard;
        *guard += 1;
        id
    }

    /// Build and record a `Call` message in the pending map.
    ///
    /// The caller is responsible for actually transmitting the message (e.g.
    /// writing it to a channel).  Returns the assembled message.
    pub fn prepare_call(
        &mut self,
        method: impl Into<String>,
        payload: IpcPayload,
    ) -> IpcMessage {
        let id = self.next_id();
        let msg = IpcMessage::call(id, method, payload);
        self.pending.insert(id, msg.clone());
        self.append_sent(msg.clone());
        msg
    }

    /// Handle an incoming message by dispatching to the registered handler.
    ///
    /// For `Ping`, returns a `Pong` automatically without consulting handlers.
    /// For other kinds where no handler is registered, returns a
    /// `MethodNotFound` error response.
    pub fn handle(&mut self, msg: &IpcMessage) -> IpcResponse {
        match msg.kind {
            IpcMessageKind::Ping => {
                let resp_id = self.next_id();
                let resp = IpcResponse::ok(resp_id, msg.id, IpcPayload::None);
                self.append_response(resp.clone());
                return resp;
            }
            IpcMessageKind::Pong => {
                // Remove from pending.
                self.pending.remove(&msg.correlation_id.unwrap_or(msg.id));
                let resp_id = self.next_id();
                let resp = IpcResponse::ok(resp_id, msg.id, IpcPayload::None);
                self.append_response(resp.clone());
                return resp;
            }
            _ => {}
        }

        let resp_id = self.next_id();
        if let Some(handler) = self.handlers.get(&msg.method) {
            let resp = handler(msg);
            self.pending.remove(&msg.correlation_id.unwrap_or(msg.id));
            self.append_response(resp.clone());
            resp
        } else {
            let resp = IpcResponse::error(
                resp_id,
                msg.id,
                IpcStatus::MethodNotFound,
                format!("method '{}' not registered", msg.method),
            );
            self.append_response(resp.clone());
            resp
        }
    }

    /// Mark a pending call as replied and record the response.
    pub fn record_reply(&mut self, response: IpcResponse) {
        self.pending.remove(&response.request_id);
        self.append_response(response);
    }

    fn append_sent(&mut self, msg: IpcMessage) {
        if self.sent_log.len() >= self.max_log_size {
            self.sent_log.remove(0);
        }
        self.sent_log.push(msg);
    }

    fn append_response(&mut self, resp: IpcResponse) {
        if self.response_log.len() >= self.max_log_size {
            self.response_log.remove(0);
        }
        self.response_log.push(resp);
    }

    /// Number of pending (un-replied) calls.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Number of messages in the send log.
    #[must_use]
    pub const fn sent_count(&self) -> usize {
        self.sent_log.len()
    }

    /// Number of responses received.
    #[must_use]
    pub const fn response_count(&self) -> usize {
        self.response_log.len()
    }

    /// Clear all logs.
    pub fn clear_logs(&mut self) {
        self.sent_log.clear();
        self.response_log.clear();
    }

    /// Return a view of the send log.
    #[must_use]
    pub fn sent_log(&self) -> &[IpcMessage] {
        &self.sent_log
    }

    /// Return a view of the response log.
    #[must_use]
    pub fn response_log(&self) -> &[IpcResponse] {
        &self.response_log
    }

    /// Count responses with a given status.
    #[must_use]
    pub fn count_status(&self, status: IpcStatus) -> usize {
        self.response_log.iter().filter(|r| r.status == status).count()
    }
}

impl Default for PluginIpcProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ── send_ipc ──────────────────────────────────────────────────────────────────

/// Send an IPC message by dispatching it through the given protocol instance.
///
/// This is a convenience wrapper around [`PluginIpcProtocol::handle`] that
/// also returns the response for caller inspection.
///
/// In production the caller would serialise `msg` and transmit it over a
/// socket or shared-memory ring buffer.  This implementation performs an
/// in-process dispatch, which is suitable for unit tests and embedded plugins.
pub fn send_ipc(protocol: &mut PluginIpcProtocol, msg: &IpcMessage) -> IpcResponse {
    protocol.handle(msg)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn proto() -> PluginIpcProtocol {
        PluginIpcProtocol::new()
    }

    // ── IpcMessageKind ────────────────────────────────────────────────────────

    #[test]
    fn test_message_kind_display() {
        assert_eq!(IpcMessageKind::Call.as_str(), "call");
        assert_eq!(IpcMessageKind::Reply.as_str(), "reply");
        assert_eq!(IpcMessageKind::Shutdown.as_str(), "shutdown");
    }

    // ── IpcPayload ────────────────────────────────────────────────────────────

    #[test]
    fn test_payload_none_is_empty() {
        assert!(IpcPayload::None.is_empty());
        assert!(!IpcPayload::Text("hi".into()).is_empty());
    }

    #[test]
    fn test_payload_byte_len() {
        assert_eq!(IpcPayload::Binary(vec![1, 2, 3]).byte_len(), 3);
        assert_eq!(IpcPayload::Text("hello".into()).byte_len(), 5);
    }

    #[test]
    fn test_payload_summary_truncate() {
        let long = "x".repeat(80);
        let p = IpcPayload::Text(long);
        assert!(p.summary().len() < 80);
    }

    // ── IpcMessage ────────────────────────────────────────────────────────────

    #[test]
    fn test_ipc_message_call() {
        let m = IpcMessage::call(1, "do_thing", IpcPayload::None);
        assert_eq!(m.id, 1);
        assert_eq!(m.method, "do_thing");
        assert_eq!(m.kind, IpcMessageKind::Call);
        assert!(m.correlation_id.is_none());
    }

    #[test]
    fn test_ipc_message_pong() {
        let m = IpcMessage::pong(2, 1);
        assert_eq!(m.id, 2);
        assert_eq!(m.correlation_id, Some(1));
    }

    #[test]
    fn test_ipc_message_header() {
        let m = IpcMessage::call(1, "m", IpcPayload::None)
            .with_header("x-plugin", "test");
        assert_eq!(m.headers.get("x-plugin").map(String::as_str), Some("test"));
    }

    // ── IpcStatus ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ipc_status_ok() {
        assert!(IpcStatus::Ok.is_ok());
        assert!(!IpcStatus::Timeout.is_ok());
    }

    #[test]
    fn test_ipc_status_display() {
        assert_eq!(IpcStatus::PermissionDenied.as_str(), "permission_denied");
    }

    // ── IpcResponse ───────────────────────────────────────────────────────────

    #[test]
    fn test_ipc_response_ok() {
        let r = IpcResponse::ok(2, 1, IpcPayload::Text("result".into()));
        assert!(r.is_ok());
        assert_eq!(r.ok_text(), Some("result"));
    }

    #[test]
    fn test_ipc_response_error() {
        let r = IpcResponse::error(2, 1, IpcStatus::MethodNotFound, "no such method");
        assert!(!r.is_ok());
        assert_eq!(r.status, IpcStatus::MethodNotFound);
        assert!(r.ok_text().is_none());
    }

    // ── PluginIpcProtocol ─────────────────────────────────────────────────────

    #[test]
    fn test_protocol_register_handler() {
        let mut p = proto();
        p.register_handler("greet", Box::new(|msg: &IpcMessage| {
            IpcResponse::ok(0, msg.id, IpcPayload::Text("hello".into()))
        }));
        assert!(p.registered_methods().contains(&"greet"));
    }

    #[test]
    fn test_protocol_unregister_handler() {
        let mut p = proto();
        p.register_handler("x", Box::new(|msg: &IpcMessage| {
            IpcResponse::ok(0, msg.id, IpcPayload::None)
        }));
        assert!(p.unregister_handler("x"));
        assert!(!p.unregister_handler("x"));
    }

    #[test]
    fn test_protocol_handle_call_ok() {
        let mut p = proto();
        p.register_handler("echo", Box::new(|msg: &IpcMessage| {
            IpcResponse::ok(0, msg.id, msg.payload.clone())
        }));
        let msg = IpcMessage::call(1, "echo", IpcPayload::Text("hi".into()));
        let resp = p.handle(&msg);
        assert!(resp.is_ok());
        assert_eq!(resp.ok_text(), Some("hi"));
    }

    #[test]
    fn test_protocol_handle_method_not_found() {
        let mut p = proto();
        let msg = IpcMessage::call(1, "nonexistent", IpcPayload::None);
        let resp = p.handle(&msg);
        assert_eq!(resp.status, IpcStatus::MethodNotFound);
    }

    #[test]
    fn test_protocol_ping_pong() {
        let mut p = proto();
        let ping = IpcMessage::ping(1);
        let resp = p.handle(&ping);
        assert!(resp.is_ok());
    }

    #[test]
    fn test_protocol_pending_tracking() {
        let mut p = proto();
        let msg = p.prepare_call("operation", IpcPayload::None);
        assert_eq!(p.pending_count(), 1);
        // Simulate reply
        let resp = IpcResponse::ok(99, msg.id, IpcPayload::None);
        p.record_reply(resp);
        assert_eq!(p.pending_count(), 0);
    }

    #[test]
    fn test_protocol_sent_log() {
        let mut p = proto();
        p.prepare_call("a", IpcPayload::None);
        p.prepare_call("b", IpcPayload::None);
        assert_eq!(p.sent_count(), 2);
    }

    #[test]
    fn test_protocol_response_log() {
        let mut p = proto();
        p.register_handler("x", Box::new(|msg: &IpcMessage| {
            IpcResponse::ok(0, msg.id, IpcPayload::None)
        }));
        let msg = IpcMessage::call(1, "x", IpcPayload::None);
        p.handle(&msg);
        assert_eq!(p.response_count(), 1);
    }

    #[test]
    fn test_protocol_count_status() {
        let mut p = proto();
        let msg = IpcMessage::call(1, "missing", IpcPayload::None);
        p.handle(&msg);
        assert_eq!(p.count_status(IpcStatus::MethodNotFound), 1);
        assert_eq!(p.count_status(IpcStatus::Ok), 0);
    }

    #[test]
    fn test_protocol_clear_logs() {
        let mut p = proto();
        p.prepare_call("m", IpcPayload::None);
        p.clear_logs();
        assert_eq!(p.sent_count(), 0);
        assert_eq!(p.response_count(), 0);
    }

    // ── send_ipc ──────────────────────────────────────────────────────────────

    #[test]
    fn test_send_ipc_dispatches() {
        let mut p = proto();
        p.register_handler("ping_method", Box::new(|msg: &IpcMessage| {
            IpcResponse::ok(0, msg.id, IpcPayload::Text("pong".into()))
        }));
        let msg = IpcMessage::call(10, "ping_method", IpcPayload::None);
        let resp = send_ipc(&mut p, &msg);
        assert!(resp.is_ok());
    }
}
