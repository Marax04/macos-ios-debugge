//! MCP error types.
//!
//! Provides a comprehensive, hierarchical error taxonomy for the MCP subsystem:
//! [`McpError`] (top-level), [`ErrorCode`] (numeric codes compatible with
//! JSON-RPC 2.0 and MCP extensions), [`McpErrorKind`] (semantic category), and
//! the [`format_error`] utility function.

use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ErrorCode ────────────────────────────────────────────────────────────────

/// Numeric error codes.
///
/// Standard JSON-RPC 2.0 codes occupy -32700 … -32600.
/// MCP application codes occupy -32000 … -32099.
/// Domain-specific RE codes start at -31000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum ErrorCode {
    // ── JSON-RPC standard ────────────────────────────────────────────────────
    /// Parse error (-32700).
    ParseError = -32700,
    /// Invalid request (-32600).
    InvalidRequest = -32600,
    /// Method not found (-32601).
    MethodNotFound = -32601,
    /// Invalid params (-32602).
    InvalidParams = -32602,
    /// Internal error (-32603).
    InternalError = -32603,

    // ── MCP application codes (-32000 … -32099) ──────────────────────────────
    /// Rate limit exceeded (-32000).
    RateLimited = -32000,
    /// Middleware rejected the request (-32001).
    MiddlewareRejected = -32001,
    /// Execution timed out (-32002).
    Timeout = -32002,
    /// Tool category disabled (-32003).
    CategoryDisabled = -32003,
    /// Batch request too large (-32004).
    BatchTooLarge = -32004,
    /// Authentication required (-32005).
    Unauthorized = -32005,
    /// Permission denied (-32006).
    Forbidden = -32006,
    /// Requested resource not found (-32007).
    ResourceNotFound = -32007,
    /// Resource conflict (-32008).
    Conflict = -32008,

    // ── RE-domain codes (-31000 …) ────────────────────────────────────────────
    /// Binary file could not be loaded (-31000).
    BinaryLoadError = -31000,
    /// Disassembly failed (-31001).
    DisassemblyFailed = -31001,
    /// Decompilation failed (-31002).
    DecompilationFailed = -31002,
    /// Symbol resolution failed (-31003).
    SymbolResolution = -31003,
    /// Analysis database unavailable (-31004).
    DatabaseUnavailable = -31004,
    /// Corpus operation failed (-31005).
    CorpusError = -31005,
    /// Sandbox execution error (-31006).
    SandboxError = -31006,
    /// Fuzzing harness error (-31007).
    FuzzError = -31007,
}

impl ErrorCode {
    /// Return the numeric integer value.
    #[must_use]
    pub const fn value(self) -> i32 {
        self as i32
    }

    /// Classify this code into the standard JSON-RPC ranges.
    #[must_use]
    pub const fn is_jsonrpc_standard(self) -> bool {
        let v = self.value();
        v >= -32700 && v <= -32600
    }

    /// Return `true` for application-level MCP codes.
    #[must_use]
    pub const fn is_mcp_application(self) -> bool {
        let v = self.value();
        v >= -32099 && v <= -32000
    }

    /// Return `true` for domain-specific RE codes.
    #[must_use]
    pub const fn is_domain_specific(self) -> bool {
        let v = self.value();
        v >= -31999 && v <= -31000
    }

    /// Return a short, stable string identifier for this code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ParseError => "parse_error",
            Self::InvalidRequest => "invalid_request",
            Self::MethodNotFound => "method_not_found",
            Self::InvalidParams => "invalid_params",
            Self::InternalError => "internal_error",
            Self::RateLimited => "rate_limited",
            Self::MiddlewareRejected => "middleware_rejected",
            Self::Timeout => "timeout",
            Self::CategoryDisabled => "category_disabled",
            Self::BatchTooLarge => "batch_too_large",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::ResourceNotFound => "resource_not_found",
            Self::Conflict => "conflict",
            Self::BinaryLoadError => "binary_load_error",
            Self::DisassemblyFailed => "disassembly_failed",
            Self::DecompilationFailed => "decompilation_failed",
            Self::SymbolResolution => "symbol_resolution",
            Self::DatabaseUnavailable => "database_unavailable",
            Self::CorpusError => "corpus_error",
            Self::SandboxError => "sandbox_error",
            Self::FuzzError => "fuzz_error",
        }
    }

    /// Return `true` if this is a client-side error (bad input, not a server fault).
    #[must_use]
    pub const fn is_client_error(self) -> bool {
        matches!(
            self,
            Self::InvalidRequest
                | Self::InvalidParams
                | Self::MethodNotFound
                | Self::ParseError
                | Self::BatchTooLarge
                | Self::Unauthorized
                | Self::Forbidden
        )
    }

    /// Return `true` if the error is transient and the request may succeed on retry.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::RateLimited | Self::Timeout | Self::DatabaseUnavailable)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.value())
    }
}

// ─── McpErrorKind ─────────────────────────────────────────────────────────────

/// Semantic category of an MCP error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum McpErrorKind {
    /// The incoming request was malformed or unparseable.
    Protocol,
    /// The requested method / tool was not found.
    NotFound,
    /// One or more parameters were invalid.
    Validation,
    /// The caller is not authorised to perform the action.
    Auth,
    /// A transient infrastructure fault (database, network, …).
    Infrastructure,
    /// The tool or method execution itself failed.
    Execution,
    /// Capacity / rate-limiting constraint.
    Capacity,
    /// Reverse-engineering domain error (binary load, disassembly, …).
    Domain,
    /// An uncategorised / catch-all error.
    Unknown,
}

impl McpErrorKind {
    /// Return `true` if this is a client-caused error category.
    #[must_use]
    pub const fn is_client_fault(&self) -> bool {
        matches!(self, Self::Protocol | Self::Validation | Self::Auth | Self::NotFound)
    }

    /// Return `true` if this is a server-side or infrastructure fault.
    #[must_use]
    pub const fn is_server_fault(&self) -> bool {
        matches!(self, Self::Infrastructure | Self::Execution | Self::Unknown)
    }

    /// String label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::NotFound => "not_found",
            Self::Validation => "validation",
            Self::Auth => "auth",
            Self::Infrastructure => "infrastructure",
            Self::Execution => "execution",
            Self::Capacity => "capacity",
            Self::Domain => "domain",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for McpErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ─── ErrorLocation ────────────────────────────────────────────────────────────

/// Location information identifying where an error occurred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLocation {
    /// Source file (e.g. `"mcp_server_impl.rs"`).
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Optional module path.
    pub module: Option<String>,
}

impl ErrorLocation {
    /// Create a location.
    #[must_use]
    pub fn new(file: &'static str, line: u32, module: Option<&'static str>) -> Self {
        Self { file: file.to_string(), line, module: module.map(str::to_string) }
    }
}

impl fmt::Display for ErrorLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(m) = &self.module {
            write!(f, "{}::{} (line {})", m, self.file, self.line)
        } else {
            write!(f, "{} (line {})", self.file, self.line)
        }
    }
}

/// Convenience macro for capturing the call site.
#[macro_export]
macro_rules! error_location {
    () => {
        $crate::mcp_error_types::ErrorLocation::new(file!(), line!(), Some(module_path!()))
    };
}

// ─── McpError ─────────────────────────────────────────────────────────────────

/// The top-level MCP error type.
///
/// Every error carries an [`ErrorCode`], a [`McpErrorKind`], a human-readable
/// `message`, optional source location, optional request ID, and an optional
/// chain of causes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    /// Numeric error code.
    pub code: ErrorCode,
    /// Semantic category.
    pub kind: McpErrorKind,
    /// Human-readable message.
    pub message: String,
    /// Optional source location.
    pub location: Option<ErrorLocation>,
    /// Optional request identifier that triggered this error.
    pub request_id: Option<String>,
    /// Additional structured context.
    pub context: std::collections::HashMap<String, String>,
    /// Chain of underlying cause messages.
    pub causes: Vec<String>,
}

impl McpError {
    /// Construct a minimal error.
    #[must_use]
    pub fn new(code: ErrorCode, kind: McpErrorKind, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            location: None,
            request_id: None,
            context: Default::default(),
            causes: Vec::new(),
        }
    }

    // ── Convenience constructors ──────────────────────────────────────────────

    /// Create a parse error.
    #[must_use]
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::ParseError, McpErrorKind::Protocol, msg)
    }

    /// Create an "invalid request" error.
    #[must_use]
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, McpErrorKind::Protocol, msg)
    }

    /// Create a "method not found" error.
    #[must_use]
    pub fn method_not_found(method: impl Into<String>) -> Self {
        let method = method.into();
        Self::new(
            ErrorCode::MethodNotFound,
            McpErrorKind::NotFound,
            format!("method not found: {method}"),
        )
    }

    /// Create an "invalid params" error.
    #[must_use]
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, McpErrorKind::Validation, detail)
    }

    /// Create an "internal error".
    #[must_use]
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, McpErrorKind::Execution, detail)
    }

    /// Create a rate-limit error.
    #[must_use]
    pub fn rate_limited(resource: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::RateLimited,
            McpErrorKind::Capacity,
            format!("rate limit exceeded for: {}", resource.into()),
        )
    }

    /// Create a timeout error.
    #[must_use]
    pub fn timeout(op: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::Timeout,
            McpErrorKind::Infrastructure,
            format!("timeout executing: {}", op.into()),
        )
    }

    /// Create an unauthorised error.
    #[must_use]
    pub fn unauthorized(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthorized, McpErrorKind::Auth, reason)
    }

    /// Create a domain binary-load error.
    #[must_use]
    pub fn binary_load(path: impl Into<String>, cause: impl Into<String>) -> Self {
        let mut e = Self::new(
            ErrorCode::BinaryLoadError,
            McpErrorKind::Domain,
            format!("binary load failed: {}", path.into()),
        );
        e.causes.push(cause.into());
        e
    }

    // ── Builder methods ───────────────────────────────────────────────────────

    /// Attach a source location.
    #[must_use]
    pub fn at(mut self, loc: ErrorLocation) -> Self {
        self.location = Some(loc);
        self
    }

    /// Attach a request ID.
    #[must_use]
    pub fn with_request(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Add a cause message.
    #[must_use]
    pub fn caused_by(mut self, cause: impl Into<String>) -> Self {
        self.causes.push(cause.into());
        self
    }

    /// Add context key/value.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Return `true` if this is a client-side error.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        self.code.is_client_error()
    }

    /// Return `true` if the error is transient.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        self.code.is_transient()
    }

    /// Return the numeric error code as an `i32`.
    #[must_use]
    pub fn code_value(&self) -> i32 {
        self.code.value()
    }
}

impl fmt::Display for McpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.code.value(), self.kind, self.message)?;
        for cause in &self.causes {
            write!(f, "; caused by: {cause}")?;
        }
        if let Some(loc) = &self.location {
            write!(f, " (at {loc})")?;
        }
        Ok(())
    }
}

impl std::error::Error for McpError {}

// ─── format_error ─────────────────────────────────────────────────────────────

/// Format an [`McpError`] as a pretty, multi-line string suitable for logging.
///
/// ```text
/// [MCP Error]
///   Code   : -32601 (method_not_found)
///   Kind   : not_found
///   Message: method not found: ghost_tool
///   Request: req-42
///   At     : mcp_server_impl.rs::some_module (line 123)
///   Context:
///     tool = ghost_tool
///   Causes:
///     [0] no handler registered
/// ```
#[must_use]
pub fn format_error(err: &McpError) -> String {
    let mut out = String::from("[MCP Error]\n");
    out.push_str(&format!("  Code   : {} ({})\n", err.code.value(), err.code.name()));
    out.push_str(&format!("  Kind   : {}\n", err.kind));
    out.push_str(&format!("  Message: {}\n", err.message));

    if let Some(req) = &err.request_id {
        out.push_str(&format!("  Request: {req}\n"));
    }

    if let Some(loc) = &err.location {
        out.push_str(&format!("  At     : {loc}\n"));
    }

    if !err.context.is_empty() {
        out.push_str("  Context:\n");
        let mut keys: Vec<&String> = err.context.keys().collect();
        keys.sort();
        for k in keys {
            if let Some(v) = err.context.get(k) {
                out.push_str(&format!("    {k} = {v}\n"));
            }
        }
    }

    if !err.causes.is_empty() {
        out.push_str("  Causes:\n");
        for (i, cause) in err.causes.iter().enumerate() {
            out.push_str(&format!("    [{i}] {cause}\n"));
        }
    }

    out
}

// ─── ErrorRegistry ────────────────────────────────────────────────────────────

/// A thread-safe registry that maps error codes to descriptive metadata.
#[derive(Debug, Clone, Default)]
pub struct ErrorRegistry {
    entries: std::collections::HashMap<i32, ErrorMeta>,
}

/// Metadata for a registered error code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMeta {
    pub code: i32,
    pub name: String,
    pub description: String,
    pub kind: McpErrorKind,
    pub retryable: bool,
}

impl ErrorRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate with all built-in MCP error codes.
    #[must_use]
    pub fn with_builtin() -> Self {
        let mut r = Self::new();
        let builtins = [
            (ErrorCode::ParseError, "JSON parse failure", false),
            (ErrorCode::InvalidRequest, "Request is not a valid JSON-RPC object", false),
            (ErrorCode::MethodNotFound, "The method does not exist or is unavailable", false),
            (ErrorCode::InvalidParams, "Invalid method parameters", false),
            (ErrorCode::InternalError, "Internal MCP server error", false),
            (ErrorCode::RateLimited, "Too many requests", true),
            (ErrorCode::MiddlewareRejected, "Request rejected by middleware", false),
            (ErrorCode::Timeout, "Execution timed out", true),
            (ErrorCode::CategoryDisabled, "Tool category is disabled", false),
            (ErrorCode::BatchTooLarge, "Batch request exceeds size limit", false),
            (ErrorCode::Unauthorized, "Authentication required", false),
            (ErrorCode::Forbidden, "Permission denied", false),
            (ErrorCode::ResourceNotFound, "Resource not found", false),
            (ErrorCode::Conflict, "Resource conflict", false),
            (ErrorCode::BinaryLoadError, "Binary file could not be loaded", false),
            (ErrorCode::DisassemblyFailed, "Disassembly failed", false),
            (ErrorCode::DecompilationFailed, "Decompilation failed", false),
            (ErrorCode::SymbolResolution, "Symbol resolution failed", false),
            (ErrorCode::DatabaseUnavailable, "Analysis database unavailable", true),
            (ErrorCode::CorpusError, "Corpus operation failed", false),
            (ErrorCode::SandboxError, "Sandbox execution error", false),
            (ErrorCode::FuzzError, "Fuzzing harness error", false),
        ];
        for (code, desc, retryable) in builtins {
            let kind = if code.is_client_error() {
                McpErrorKind::Validation
            } else if code.is_domain_specific() {
                McpErrorKind::Domain
            } else if code.is_transient() {
                McpErrorKind::Infrastructure
            } else {
                McpErrorKind::Execution
            };
            r.entries.insert(
                code.value(),
                ErrorMeta {
                    code: code.value(),
                    name: code.name().to_string(),
                    description: desc.to_string(),
                    kind,
                    retryable,
                },
            );
        }
        r
    }

    /// Register a custom error code.
    pub fn register(&mut self, meta: ErrorMeta) {
        self.entries.insert(meta.code, meta);
    }

    /// Look up metadata for a code.
    #[must_use]
    pub fn lookup(&self, code: i32) -> Option<&ErrorMeta> {
        self.entries.get(&code)
    }

    /// Return all registered codes (sorted).
    #[must_use]
    pub fn codes(&self) -> Vec<i32> {
        let mut v: Vec<i32> = self.entries.keys().copied().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_values() {
        assert_eq!(ErrorCode::ParseError.value(), -32700);
        assert_eq!(ErrorCode::MethodNotFound.value(), -32601);
        assert_eq!(ErrorCode::RateLimited.value(), -32000);
        assert_eq!(ErrorCode::BinaryLoadError.value(), -31000);
    }

    #[test]
    fn test_error_code_classification() {
        assert!(ErrorCode::ParseError.is_client_error());
        assert!(!ErrorCode::Timeout.is_client_error());
        assert!(ErrorCode::RateLimited.is_transient());
        assert!(ErrorCode::Timeout.is_transient());
        assert!(!ErrorCode::ParseError.is_transient());
        assert!(ErrorCode::BinaryLoadError.is_domain_specific());
        assert!(ErrorCode::InternalError.is_jsonrpc_standard());
        assert!(ErrorCode::RateLimited.is_mcp_application());
    }

    #[test]
    fn test_mcp_error_constructors() {
        let e = McpError::method_not_found("ghost");
        assert_eq!(e.code, ErrorCode::MethodNotFound);
        assert!(e.message.contains("ghost"));
        assert!(!e.is_transient());
        assert!(e.is_client_error());
    }

    #[test]
    fn test_mcp_error_builder() {
        let e = McpError::internal("oops")
            .with_request("req-1")
            .with_context("tool", "my_tool")
            .caused_by("io error");

        assert_eq!(e.request_id.as_deref(), Some("req-1"));
        assert_eq!(e.context.get("tool").map(String::as_str), Some("my_tool"));
        assert_eq!(e.causes[0], "io error");
    }

    #[test]
    fn test_format_error_contains_fields() {
        let e = McpError::rate_limited("analysis_tool")
            .with_request("req-42")
            .with_context("key", "val")
            .caused_by("too many requests");
        let s = format_error(&e);
        assert!(s.contains("-32000"));
        assert!(s.contains("rate_limited"));
        assert!(s.contains("req-42"));
        assert!(s.contains("key = val"));
        assert!(s.contains("too many requests"));
    }

    #[test]
    fn test_error_registry_builtin() {
        let r = ErrorRegistry::with_builtin();
        let m = r.lookup(-32601).unwrap();
        assert_eq!(m.name, "method_not_found");
        assert!(!m.retryable);
        let tm = r.lookup(-32000).unwrap();
        assert!(tm.retryable);
    }

    #[test]
    fn test_error_registry_custom() {
        let mut r = ErrorRegistry::new();
        r.register(ErrorMeta {
            code: -29999,
            name: "custom".to_string(),
            description: "A custom error".to_string(),
            kind: McpErrorKind::Domain,
            retryable: false,
        });
        let m = r.lookup(-29999).unwrap();
        assert_eq!(m.name, "custom");
    }

    #[test]
    fn test_mcp_error_display() {
        let e = McpError::parse("unexpected token");
        let s = e.to_string();
        assert!(s.contains("-32700"));
        assert!(s.contains("unexpected token"));
    }

    #[test]
    fn test_mcp_error_kind_labels() {
        assert_eq!(McpErrorKind::Protocol.label(), "protocol");
        assert!(McpErrorKind::Protocol.is_client_fault());
        assert!(McpErrorKind::Infrastructure.is_server_fault());
    }
}
