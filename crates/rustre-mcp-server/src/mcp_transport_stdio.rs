//! Stdio transport for the Model Context Protocol (MCP).
//!
//! MCP servers communicate with their host (typically an AI assistant) over a
//! newline-delimited JSON-RPC 2.0 stream.  This module implements the lowest
//! transport layer: reading and writing [`StdioMessage`] values over stdin/stdout
//! using length-prefixed or newline-delimited framing.
//!
//! # Protocol framing
//!
//! Each message is a single JSON object on one line (newline-delimited).  The
//! reader strips the trailing `\n` (and optional `\r`) before JSON parsing.
//!
//! # Thread safety
//!
//! [`McpTransportStdio`] wraps the stdio handles with interior mutability so it
//! can be shared across tasks when wrapped in `Arc`.  In practice the server
//! loop is single-threaded so this is mainly a convenience.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};

// ── Error type ────────────────────────────────────────────────────────────────

/// Transport-level error.
#[derive(Debug)]
pub enum TransportError {
    /// An I/O error occurred on the underlying stream.
    Io(io::Error),
    /// The received bytes were not valid JSON.
    InvalidJson(serde_json::Error),
    /// The peer closed the stream (EOF).
    Eof,
    /// A message exceeded the configured maximum size.
    MessageTooLarge { size: usize, limit: usize },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidJson(e) => write!(f, "JSON parse error: {e}"),
            Self::Eof => write!(f, "connection closed (EOF)"),
            Self::MessageTooLarge { size, limit } => {
                write!(f, "message {size} bytes exceeds limit {limit}")
            }
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::InvalidJson(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for TransportError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidJson(e)
    }
}

// ── StdioMessage ──────────────────────────────────────────────────────────────

/// A JSON-RPC 2.0 message as exchanged over the stdio transport.
///
/// MCP supports three message shapes:
/// * **Request**: has `id` + `method`.
/// * **Response**: has `id` + (`result` XOR `error`).
/// * **Notification**: has `method` but no `id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdioMessage {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Present on requests and responses; absent on notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// Method name; present on requests and notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Method parameters; present on requests and notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Successful result; present on responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload; present on error responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl StdioMessage {
    /// Construct a JSON-RPC 2.0 request.
    #[must_use]
    pub fn request(id: impl Into<Value>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id.into()),
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// Construct a JSON-RPC 2.0 notification (no `id`).
    #[must_use]
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: None,
            method: Some(method.into()),
            params,
            result: None,
            error: None,
        }
    }

    /// Construct a successful JSON-RPC 2.0 response.
    #[must_use]
    pub fn response(id: impl Into<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id.into()),
            method: None,
            params: None,
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error JSON-RPC 2.0 response.
    #[must_use]
    pub fn error_response(id: impl Into<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: Some(id.into()),
            method: None,
            params: None,
            result: None,
            error: Some(error),
        }
    }

    /// Return `true` if this is a request (has both `id` and `method`).
    #[must_use]
    pub const fn is_request(&self) -> bool {
        self.id.is_some() && self.method.is_some()
    }

    /// Return `true` if this is a notification (has `method` but no `id`).
    #[must_use]
    pub const fn is_notification(&self) -> bool {
        self.id.is_none() && self.method.is_some()
    }

    /// Return `true` if this is a response (has `id` but no `method`).
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.id.is_some() && self.method.is_none()
    }

    /// Return `true` if this response carries an error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Serialise this message to a single JSON line (no trailing newline).
    ///
    /// # Errors
    /// Returns [`TransportError::InvalidJson`] if serialisation fails.
    pub fn to_json_line(&self) -> Result<String, TransportError> {
        serde_json::to_string(self).map_err(TransportError::InvalidJson)
    }
}

// ── JsonRpcError ──────────────────────────────────────────────────────────────

// Re-export the canonical JsonRpcError from the crate root to avoid duplicate
// type definitions. All helper methods live on crate::JsonRpcError.
pub use crate::JsonRpcError;

// ── TransportConfig ───────────────────────────────────────────────────────────

/// Configuration for the stdio transport.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum message size in bytes (default: 8 MiB).
    pub max_message_size: usize,
    /// Whether to log every message to stderr (default: false).
    pub debug_log: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_message_size: 8 * 1024 * 1024,
            debug_log: false,
        }
    }
}

// ── McpTransportStdio ─────────────────────────────────────────────────────────

/// Newline-delimited JSON-RPC transport over stdin/stdout.
///
/// Internally wraps buffered readers/writers behind `Arc<Mutex<…>>` so the
/// struct can be cloned cheaply and shared across tasks.
pub struct McpTransportStdio {
    reader: Arc<Mutex<BufReader<io::Stdin>>>,
    writer: Arc<Mutex<BufWriter<io::Stdout>>>,
    config: TransportConfig,
    /// Running count of messages received.
    recv_count: Arc<Mutex<u64>>,
    /// Running count of messages sent.
    send_count: Arc<Mutex<u64>>,
}

impl McpTransportStdio {
    /// Create a new transport using the process's stdin/stdout.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(TransportConfig::default())
    }

    /// Create a transport with a custom configuration.
    #[must_use]
    pub fn with_config(config: TransportConfig) -> Self {
        Self {
            reader: Arc::new(Mutex::new(BufReader::new(io::stdin()))),
            writer: Arc::new(Mutex::new(BufWriter::new(io::stdout()))),
            config,
            recv_count: Arc::new(Mutex::new(0)),
            send_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Read one [`StdioMessage`] from stdin.
    ///
    /// Blocks until a full newline-terminated line is available.
    ///
    /// # Errors
    /// * [`TransportError::Eof`] – stdin was closed.
    /// * [`TransportError::MessageTooLarge`] – line exceeded `max_message_size`.
    /// * [`TransportError::InvalidJson`] – the line was not valid JSON.
    /// * [`TransportError::Io`] – any other I/O error.
    pub fn read_message(&self) -> Result<StdioMessage, TransportError> {
        read_message_from(&self.reader, &self.config, &self.recv_count)
    }

    /// Write one [`StdioMessage`] to stdout followed by a newline.
    ///
    /// The write is atomic from the perspective of the mutex: no other call can
    /// interleave bytes between the JSON and the newline.
    ///
    /// # Errors
    /// * [`TransportError::InvalidJson`] – serialisation failed.
    /// * [`TransportError::Io`] – write or flush failed.
    pub fn write_message(&self, msg: &StdioMessage) -> Result<(), TransportError> {
        write_message_to(msg, &self.writer, &self.config, &self.send_count)
    }

    /// Return the number of messages received so far.
    #[must_use]
    pub fn recv_count(&self) -> u64 {
        *self.recv_count.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Return the number of messages sent so far.
    #[must_use]
    pub fn send_count(&self) -> u64 {
        *self.send_count.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for McpTransportStdio {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Read one [`StdioMessage`] from the given buffered reader.
///
/// This is the testable core of the read path; the struct method delegates here.
pub fn read_message_from(
    reader: &Arc<Mutex<BufReader<io::Stdin>>>,
    config: &TransportConfig,
    counter: &Arc<Mutex<u64>>,
) -> Result<StdioMessage, TransportError> {
    let mut line = String::new();
    {
        let mut rdr = reader.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = rdr.read_line(&mut line)?;
        if n == 0 {
            return Err(TransportError::Eof);
        }
    }
    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
    if trimmed.len() > config.max_message_size {
        return Err(TransportError::MessageTooLarge {
            size: trimmed.len(),
            limit: config.max_message_size,
        });
    }
    if config.debug_log {
        eprintln!("[MCP-RECV] {trimmed}");
    }
    let msg: StdioMessage = serde_json::from_str(trimmed)?;
    let mut cnt = counter.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    *cnt += 1;
    Ok(msg)
}

/// Write one [`StdioMessage`] followed by `\n` to the given buffered writer.
pub fn write_message_to(
    msg: &StdioMessage,
    writer: &Arc<Mutex<BufWriter<io::Stdout>>>,
    config: &TransportConfig,
    counter: &Arc<Mutex<u64>>,
) -> Result<(), TransportError> {
    let line = msg.to_json_line()?;
    if config.debug_log {
        eprintln!("[MCP-SEND] {line}");
    }
    {
        let mut wtr = writer.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        wtr.write_all(line.as_bytes())?;
        wtr.write_all(b"\n")?;
        wtr.flush()?;
    }
    let mut cnt = counter.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    *cnt += 1;
    Ok(())
}

/// Encode a [`StdioMessage`] into a ready-to-send line (`JSON + '\n'`).
///
/// # Errors
/// Returns [`TransportError::InvalidJson`] on serialisation failure.
pub fn encode_message(msg: &StdioMessage) -> Result<Vec<u8>, TransportError> {
    let mut bytes = serde_json::to_vec(msg)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode a [`StdioMessage`] from a raw byte slice (which may or may not have a
/// trailing newline).
///
/// # Errors
/// Returns [`TransportError::InvalidJson`] on parse failure.
pub fn decode_message(raw: &[u8]) -> Result<StdioMessage, TransportError> {
    let s = std::str::from_utf8(raw)
        .map_err(|e| TransportError::InvalidJson(serde_json::Error::io(io::Error::new(
            io::ErrorKind::InvalidData,
            e.to_string(),
        ))))?;
    let trimmed = s.trim_end_matches('\n').trim_end_matches('\r');
    serde_json::from_str(trimmed).map_err(TransportError::InvalidJson)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(id: i64, method: &str) -> StdioMessage {
        StdioMessage::request(json!(id), method, None)
    }

    fn make_notification(method: &str) -> StdioMessage {
        StdioMessage::notification(method, None)
    }

    fn make_response(id: i64, result: Value) -> StdioMessage {
        StdioMessage::response(json!(id), result)
    }

    #[test]
    fn test_request_shape() {
        let m = make_request(1, "tools/list");
        assert!(m.is_request());
        assert!(!m.is_notification());
        assert!(!m.is_response());
        assert_eq!(m.method.as_deref(), Some("tools/list"));
        assert_eq!(m.jsonrpc, "2.0");
    }

    #[test]
    fn test_notification_shape() {
        let m = make_notification("$/progress");
        assert!(m.is_notification());
        assert!(!m.is_request());
        assert!(!m.is_response());
        assert!(m.id.is_none());
    }

    #[test]
    fn test_response_shape() {
        let m = make_response(42, json!({"ok": true}));
        assert!(m.is_response());
        assert!(!m.is_request());
        assert!(!m.is_error());
    }

    #[test]
    fn test_error_response_shape() {
        let err = JsonRpcError::method_not_found("nonexistent");
        let m = StdioMessage::error_response(json!(1), err);
        assert!(m.is_error());
        assert!(m.error.is_some());
    }

    #[test]
    fn test_to_json_line_roundtrip() {
        let m = make_request(7, "tools/call");
        let line = m.to_json_line().unwrap();
        let decoded: StdioMessage = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded.method.as_deref(), Some("tools/call"));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let m = make_response(99, json!({"result": 42}));
        let encoded = encode_message(&m).unwrap();
        assert!(encoded.ends_with(b"\n"));
        let decoded = decode_message(&encoded).unwrap();
        assert!(decoded.is_response());
        assert_eq!(decoded.result, Some(json!({"result": 42})));
    }

    #[test]
    fn test_decode_without_newline() {
        let m = make_notification("ping");
        let json_bytes = serde_json::to_vec(&m).unwrap();
        let decoded = decode_message(&json_bytes).unwrap();
        assert!(decoded.is_notification());
    }

    #[test]
    fn test_decode_invalid_json() {
        let result = decode_message(b"{not valid json}");
        assert!(result.is_err());
        match result.unwrap_err() {
            TransportError::InvalidJson(_) => {}
            e => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_json_rpc_error_codes() {
        assert_eq!(JsonRpcError::PARSE_ERROR, -32700);
        assert_eq!(JsonRpcError::METHOD_NOT_FOUND, -32601);
        assert_eq!(JsonRpcError::INTERNAL_ERROR, -32603);
    }

    #[test]
    fn test_json_rpc_error_display() {
        let e = JsonRpcError::method_not_found("foo");
        let s = e.to_string();
        assert!(s.contains("method not found"));
        assert!(s.contains("foo"));
    }

    #[test]
    fn test_json_rpc_internal_error() {
        let e = JsonRpcError::internal("disk full");
        assert_eq!(e.code, JsonRpcError::INTERNAL_ERROR);
        assert!(e.message.contains("disk full"));
    }

    #[test]
    fn test_transport_error_display() {
        let e = TransportError::Eof;
        assert!(!e.to_string().is_empty());
        let e2 = TransportError::MessageTooLarge { size: 100, limit: 50 };
        assert!(e2.to_string().contains("100"));
    }

    #[test]
    fn test_transport_config_defaults() {
        let cfg = TransportConfig::default();
        assert_eq!(cfg.max_message_size, 8 * 1024 * 1024);
        assert!(!cfg.debug_log);
    }

    #[test]
    fn test_message_with_params() {
        let params = json!({"name": "read_file", "arguments": {"path": "/tmp/x"}});
        let m = StdioMessage::request(json!(3), "tools/call", Some(params.clone()));
        let line = m.to_json_line().unwrap();
        let decoded: StdioMessage = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded.params, Some(params));
    }

    #[test]
    fn test_notification_serialized_no_id() {
        let m = make_notification("initialized");
        let line = m.to_json_line().unwrap();
        assert!(!line.contains("\"id\""));
        assert!(line.contains("\"method\""));
    }

    #[test]
    fn test_response_no_method_field() {
        let m = make_response(5, json!(null));
        let line = m.to_json_line().unwrap();
        assert!(!line.contains("\"method\""));
        assert!(line.contains("\"result\""));
    }

    #[test]
    fn test_recv_send_counts_start_at_zero() {
        // We can't drive real stdin/stdout in a test, but we can verify the
        // internal counters initialise correctly.
        let transport = McpTransportStdio::new();
        assert_eq!(transport.recv_count(), 0);
        assert_eq!(transport.send_count(), 0);
    }
}
