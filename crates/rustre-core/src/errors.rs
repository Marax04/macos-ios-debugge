//! Core error types for the RustRE platform.
//!
//! All fallible operations in `rustre-core` return [`Result<T>`], a type
//! alias for `std::result::Result<T, CoreError>`.
//!
//! # Error taxonomy
//!
//! [`CoreError`] has 23+ variants that cover every category of failure that
//! the RE platform can encounter:
//!
//! - **I/O & encoding**: [`IoError`](CoreError::IoError), [`Utf8Error`](CoreError::Utf8Error), [`EncodingError`](CoreError::EncodingError)
//! - **Parsing & format**: [`ParseError`](CoreError::ParseError), [`InvalidFormat`](CoreError::InvalidFormat), [`Truncated`](CoreError::Truncated)
//! - **Address & memory**: [`InvalidAddress`](CoreError::InvalidAddress), [`SegmentFault`](CoreError::SegmentFault), [`BadAlignment`](CoreError::BadAlignment), [`RangeViolation`](CoreError::RangeViolation)
//! - **Architecture & loader**: [`UnknownArchitecture`](CoreError::UnknownArchitecture), [`ArchitectureError`](CoreError::ArchitectureError), [`LoaderError`](CoreError::LoaderError)
//! - **Analysis & decompile**: [`AnalysisError`](CoreError::AnalysisError), [`DecompileError`](CoreError::DecompileError)
//! - **Access control**: [`PermissionDenied`](CoreError::PermissionDenied)
//! - **Platform limits**: [`Unsupported`](CoreError::Unsupported)
//! - **Plugins**: [`PluginError`](CoreError::PluginError)
//! - **Network & DB**: [`NetworkError`](CoreError::NetworkError), [`DatabaseError`](CoreError::DatabaseError)
//! - **Control flow**: [`Timeout`](CoreError::Timeout), [`Cancelled`](CoreError::Cancelled)
//! - **Catch-all**: [`Internal`](CoreError::Internal)
//!
//! # Convenience macros
//!
//! - [`bail_core!`] — construct and return a `CoreError` early.
//! - [`ensure_core!`] — assert a condition, bailing with a `CoreError` if false.

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Result alias
// ─────────────────────────────────────────────────────────────────────────────

/// The standard `Result` type for all `rustre-core` operations.
pub type Result<T> = std::result::Result<T, CoreError>;

// ─────────────────────────────────────────────────────────────────────────────
// CoreError
// ─────────────────────────────────────────────────────────────────────────────

/// Unified error type for all `rustre-core` operations.
///
/// Each variant documents the situation in which it is produced.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    // ── I/O & encoding ────────────────────────────────────────────────────────
    /// A filesystem or stream I/O operation failed.
    ///
    /// The underlying [`std::io::Error`] is stringified so that `CoreError`
    /// remains `Clone + PartialEq`.
    #[error("I/O error: {message}")]
    IoError {
        /// Human-readable description of the I/O failure.
        message: String,
    },

    /// A byte sequence could not be decoded as valid UTF-8.
    #[error("UTF-8 decoding error: {message}")]
    Utf8Error {
        /// Context and description of the encoding problem.
        message: String,
    },

    /// A byte sequence could not be decoded in the expected encoding
    /// (e.g. Latin-1, EBCDIC, Shift-JIS).
    #[error("encoding error ({encoding}): {message}")]
    EncodingError {
        /// Name of the expected encoding (e.g. `"UTF-16LE"`).
        encoding: String,
        /// Description of what went wrong.
        message: String,
    },

    // ── Parsing & format ──────────────────────────────────────────────────────
    /// Syntactic or structural parsing failed.
    #[error("parse error at offset {offset:#x}: {message}")]
    ParseError {
        /// File offset or address where the parse error occurred.
        offset: u64,
        /// Description of the parse failure.
        message: String,
    },

    /// The binary does not match the expected file format.
    #[error("invalid file format: {message}")]
    InvalidFormat {
        /// What format was expected and why the input did not match.
        message: String,
    },

    /// The input was shorter than expected.
    #[error("truncated input: expected {expected} bytes but got {got}")]
    Truncated {
        /// How many bytes were expected.
        expected: usize,
        /// How many bytes were actually available.
        got: usize,
    },

    // ── Address & memory ──────────────────────────────────────────────────────
    /// An address was syntactically or semantically invalid.
    #[error("invalid address: {message}")]
    InvalidAddress {
        /// Details about the invalid address.
        message: String,
    },

    /// An invalid address range was provided (e.g. `start >= end`).
    #[error("invalid address range: {message}")]
    InvalidRange {
        /// Details about the range problem.
        message: String,
    },

    /// A memory access fell outside any mapped segment.
    #[error("segmentation fault at address {address:#x}")]
    SegmentFault {
        /// The faulting address.
        address: u64,
    },

    /// An address or size was not correctly aligned to the required boundary.
    #[error("bad alignment: address {address:#x} is not aligned to {alignment}")]
    BadAlignment {
        /// The misaligned address.
        address: u64,
        /// The required alignment in bytes.
        alignment: u64,
    },

    /// An operation specified an out-of-bounds or overlapping range.
    #[error("range violation: {message}")]
    RangeViolation {
        /// Description of the range problem.
        message: String,
    },

    // ── Architecture & loader ─────────────────────────────────────────────────
    /// An architecture name or ID was not recognised.
    #[error("unknown architecture: {name}")]
    UnknownArchitecture {
        /// The name that was not found.
        name: String,
    },

    /// An architecture-specific operation failed.
    #[error("architecture error ({arch}): {message}")]
    ArchitectureError {
        /// Name of the architecture.
        arch: String,
        /// What went wrong.
        message: String,
    },

    /// A loader failed to load a binary.
    #[error("loader error ({loader}): {message}")]
    LoaderError {
        /// Name of the loader that failed.
        loader: String,
        /// What went wrong.
        message: String,
    },

    // ── Analysis & decompile ──────────────────────────────────────────────────
    /// An analysis pass produced an error.
    #[error("analysis error: {message}")]
    AnalysisError {
        /// Description of the analysis failure.
        message: String,
    },

    /// The decompiler failed to lift or reconstruct code.
    #[error("decompile error at {address:#x}: {message}")]
    DecompileError {
        /// Address where decompilation failed.
        address: u64,
        /// Description of the failure.
        message: String,
    },

    // ── Access control ────────────────────────────────────────────────────────
    /// The requested operation was denied due to memory permissions.
    #[error("permission denied at {address:#x}: {message}")]
    PermissionDenied {
        /// Address of the access attempt.
        address: u64,
        /// Description of the permission failure.
        message: String,
    },

    // ── Platform limits ───────────────────────────────────────────────────────
    /// The requested feature or operation is not supported.
    #[error("unsupported: {feature}")]
    Unsupported {
        /// Name of the unsupported feature or operation.
        feature: String,
    },

    // ── Plugins ───────────────────────────────────────────────────────────────
    /// A plugin produced an error.
    #[error("plugin error ({plugin}): {message}")]
    PluginError {
        /// Plugin identifier.
        plugin: String,
        /// What the plugin reported.
        message: String,
    },

    // ── Network & database ────────────────────────────────────────────────────
    /// A network operation failed.
    #[error("network error: {message}")]
    NetworkError {
        /// Description of the network failure.
        message: String,
    },

    /// A database operation failed.
    #[error("database error: {message}")]
    DatabaseError {
        /// Description of the database failure.
        message: String,
    },

    // ── Control flow ──────────────────────────────────────────────────────────
    /// An operation exceeded its deadline.
    #[error("operation timed out after {millis} ms")]
    Timeout {
        /// Configured deadline in milliseconds.
        millis: u64,
    },

    /// An operation was cancelled by the caller.
    #[error("operation cancelled: {reason}")]
    Cancelled {
        /// Reason for cancellation.
        reason: String,
    },

    // ── General invalid input ─────────────────────────────────────────────────
    /// A caller passed an argument that failed validation.
    #[error("invalid input: {message}")]
    InvalidInput {
        /// Description of why the input is invalid.
        message: String,
    },

    // ── Catch-all ─────────────────────────────────────────────────────────────
    /// An unexpected internal error that should never occur in correct code.
    #[error("internal error: {message}")]
    Internal {
        /// Description of what went wrong internally.
        message: String,
    },
}

impl CoreError {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Construct an [`IoError`](CoreError::IoError).
    #[must_use]
    pub fn io(message: impl Into<String>) -> Self {
        Self::IoError {
            message: message.into(),
        }
    }

    /// Construct a [`ParseError`](CoreError::ParseError).
    #[must_use]
    pub fn parse(offset: u64, message: impl Into<String>) -> Self {
        Self::ParseError {
            offset,
            message: message.into(),
        }
    }

    /// Construct an [`InvalidAddress`](CoreError::InvalidAddress).
    #[must_use]
    pub fn invalid_address(message: impl Into<String>) -> Self {
        Self::InvalidAddress {
            message: message.into(),
        }
    }

    /// Construct a [`SegmentFault`](CoreError::SegmentFault).
    #[must_use]
    pub const fn seg_fault(address: u64) -> Self {
        Self::SegmentFault { address }
    }

    /// Construct a [`Truncated`](CoreError::Truncated).
    #[must_use]
    pub const fn truncated(expected: usize, got: usize) -> Self {
        Self::Truncated { expected, got }
    }

    /// Construct an [`UnknownArchitecture`](CoreError::UnknownArchitecture).
    #[must_use]
    pub fn unknown_arch(name: impl Into<String>) -> Self {
        Self::UnknownArchitecture { name: name.into() }
    }

    /// Construct an [`AnalysisError`](CoreError::AnalysisError).
    #[must_use]
    pub fn analysis(message: impl Into<String>) -> Self {
        Self::AnalysisError {
            message: message.into(),
        }
    }

    /// Construct an [`Unsupported`](CoreError::Unsupported).
    #[must_use]
    pub fn unsupported(feature: impl Into<String>) -> Self {
        Self::Unsupported {
            feature: feature.into(),
        }
    }

    /// Construct an [`Internal`](CoreError::Internal).
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Construct an [`InvalidInput`](CoreError::InvalidInput).
    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    // ── Predicates ────────────────────────────────────────────────────────────

    /// Return `true` if this is a recoverable / transient error.
    ///
    /// Currently classifies `Timeout`, `Cancelled`, and `NetworkError` as
    /// transient.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::Cancelled { .. } | Self::NetworkError { .. }
        )
    }

    /// Return `true` if this error is related to an I/O operation.
    #[must_use]
    pub const fn is_io(&self) -> bool {
        matches!(self, Self::IoError { .. })
    }

    /// Return `true` if this error is a permission / access-control failure.
    #[must_use]
    pub const fn is_permission_error(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
    }

    /// Return `true` if this error relates to address/memory access.
    #[must_use]
    pub const fn is_memory_error(&self) -> bool {
        matches!(
            self,
            Self::SegmentFault { .. }
                | Self::BadAlignment { .. }
                | Self::RangeViolation { .. }
                | Self::InvalidAddress { .. }
                | Self::InvalidRange { .. }
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ErrorContext — wraps a CoreError with additional context
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a [`CoreError`] with a human-readable context string.
///
/// Use the [`attach_context`](ResultExt::attach_context) extension method
/// to attach context to any `Result<T>` in a chain.
///
/// # Example
///
/// ```
/// use rustre_core::errors::{CoreError, ErrorContext, ResultExt};
///
/// fn load_header(data: &[u8]) -> rustre_core::errors::Result<u32> {
///     if data.len() < 4 {
///         return Err(CoreError::truncated(4, data.len()));
///     }
///     Ok(u32::from_le_bytes(data[..4].try_into().unwrap()))
/// }
///
/// // `attach_context` wraps the error, so the return type is
/// // `Result<T, ErrorContext>` — NOT `errors::Result<T>`.
/// fn parse_file(data: &[u8]) -> Result<u32, ErrorContext> {
///     load_header(data).attach_context("parsing PE header")
/// }
///
/// assert!(parse_file(&[1, 2]).is_err());
/// assert_eq!(parse_file(&[1, 0, 0, 0]).unwrap(), 1);
/// ```
///
/// The example was `rust,ignore` until 2026-07-29. Its real defect was the
/// return type: `attach_context` yields `Result<T, ErrorContext>`, not
/// `errors::Result<T>`, so the documented signature could not typecheck.
/// (`CoreError::truncated` is fine — it is a `pub const fn`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorContext {
    /// The underlying error.
    pub error: CoreError,
    /// The context message.
    pub context: String,
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.context, self.error)
    }
}

impl std::error::Error for ErrorContext {}

impl ErrorContext {
    /// Wrap an error with a context string.
    #[must_use]
    pub fn new(error: CoreError, context: impl Into<String>) -> Self {
        Self {
            error,
            context: context.into(),
        }
    }

    /// Unwrap into the inner [`CoreError`].
    #[must_use]
    pub fn into_inner(self) -> CoreError {
        self.error
    }
}

/// Extension trait that lets callers attach context to any `Result`.
pub trait ResultExt<T> {
    /// Attach a context string to the error, if there is one.
    ///
    /// # Errors
    /// Propagates the inner error wrapped in an [`ErrorContext`].
    fn attach_context(self, ctx: &str) -> std::result::Result<T, ErrorContext>;

    /// Attach context lazily (only evaluates the closure on error).
    ///
    /// # Errors
    /// Propagates the inner error wrapped in an [`ErrorContext`].
    fn with_context<F: FnOnce() -> String>(self, f: F) -> std::result::Result<T, ErrorContext>;
}

impl<T> ResultExt<T> for Result<T> {
    fn attach_context(self, ctx: &str) -> std::result::Result<T, ErrorContext> {
        self.map_err(|e| ErrorContext::new(e, ctx))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> std::result::Result<T, ErrorContext> {
        self.map_err(|e| ErrorContext::new(e, f()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// From conversions
// ─────────────────────────────────────────────────────────────────────────────

impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            message: err.to_string(),
        }
    }
}

impl From<std::string::FromUtf8Error> for CoreError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error {
            message: err.to_string(),
        }
    }
}

impl From<std::str::Utf8Error> for CoreError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::Utf8Error {
            message: err.to_string(),
        }
    }
}

impl From<std::num::TryFromIntError> for CoreError {
    fn from(err: std::num::TryFromIntError) -> Self {
        Self::Internal {
            message: err.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Macros
// ─────────────────────────────────────────────────────────────────────────────

/// Early-return with a [`CoreError`].
///
/// Usage mirrors `anyhow::bail!` — note it expands to a `return`, so it
/// only makes sense inside a function returning [`Result`]:
/// ```
/// use rustre_core::{bail_core, errors::CoreError};
///
/// fn decode(supported: bool) -> rustre_core::errors::Result<u32> {
///     if !supported {
///         bail_core!(CoreError::unsupported("RISC-V F extension"));
///     }
///     Ok(0)
/// }
///
/// assert!(decode(false).is_err());
/// assert_eq!(decode(true).unwrap(), 0);
/// ```
///
/// The example was `rust,ignore` until 2026-07-29 and could not have
/// compiled: the macro expands to `return`, which is invalid at the
/// statement level the block used.
#[macro_export]
macro_rules! bail_core {
    ($err:expr) => {
        return Err($err)
    };
}

/// Assert a condition, returning a [`CoreError`] if it is false.
///
/// Usage mirrors `anyhow::ensure!`, and likewise expands to a `return`:
/// ```
/// use rustre_core::{ensure_core, errors::CoreError};
///
/// fn read_u32(buf: &[u8]) -> rustre_core::errors::Result<u32> {
///     ensure_core!(buf.len() >= 4, CoreError::truncated(4, buf.len()));
///     Ok(u32::from_le_bytes(buf[..4].try_into().unwrap()))
/// }
///
/// assert!(read_u32(&[1, 2]).is_err());
/// assert_eq!(read_u32(&[1, 0, 0, 0]).unwrap(), 1);
/// ```
///
/// Was `rust,ignore` until 2026-07-29: the macro expands to a `return`,
/// which the original block used at statement level, where it cannot
/// compile. The `CoreError::truncated(expected, got)` call it showed is
/// correct and is kept.
#[macro_export]
macro_rules! ensure_core {
    ($cond:expr, $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn io_error_display() {
        let e = CoreError::io("disk full");
        assert_eq!(e.to_string(), "I/O error: disk full");
    }

    #[test]
    fn parse_error_display() {
        let e = CoreError::parse(0x40, "bad magic");
        assert_eq!(e.to_string(), "parse error at offset 0x40: bad magic");
    }

    #[test]
    fn truncated_display() {
        let e = CoreError::truncated(8, 3);
        assert_eq!(e.to_string(), "truncated input: expected 8 bytes but got 3");
    }

    #[test]
    fn seg_fault_display() {
        let e = CoreError::seg_fault(0xDEAD_BEEF);
        assert!(
            e.to_string().contains("0xdeadbeef")
                || e.to_string().contains("0xDEADBEEF")
                || e.to_string().contains("3735928559")
        );
    }

    #[test]
    fn unknown_arch_display() {
        let e = CoreError::unknown_arch("x86-16");
        assert_eq!(e.to_string(), "unknown architecture: x86-16");
    }

    #[test]
    fn unsupported_display() {
        let e = CoreError::unsupported("AVX-512");
        assert_eq!(e.to_string(), "unsupported: AVX-512");
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    #[test]
    fn analysis_error_constructor() {
        let e = CoreError::analysis("type inference failed");
        assert!(matches!(e, CoreError::AnalysisError { .. }));
    }

    #[test]
    fn internal_error_constructor() {
        let e = CoreError::internal("BUG: should never happen");
        assert!(matches!(e, CoreError::Internal { .. }));
    }

    #[test]
    fn invalid_input_constructor() {
        let e = CoreError::invalid_input("address must be non-zero");
        assert!(matches!(e, CoreError::InvalidInput { .. }));
    }

    // ── Predicates ────────────────────────────────────────────────────────────

    #[test]
    fn transient_predicate() {
        assert!(CoreError::Timeout { millis: 5000 }.is_transient());
        assert!(
            CoreError::Cancelled {
                reason: "user".into()
            }
            .is_transient()
        );
        assert!(
            CoreError::NetworkError {
                message: "conn reset".into()
            }
            .is_transient()
        );
        assert!(!CoreError::io("disk full").is_transient());
    }

    #[test]
    fn io_predicate() {
        assert!(CoreError::io("read error").is_io());
        assert!(!CoreError::internal("bug").is_io());
    }

    #[test]
    fn permission_predicate() {
        let e = CoreError::PermissionDenied {
            address: 0x1000,
            message: "read-only".into(),
        };
        assert!(e.is_permission_error());
        assert!(!e.is_io());
    }

    #[test]
    fn memory_predicate() {
        assert!(CoreError::seg_fault(0x0).is_memory_error());
        assert!(
            CoreError::InvalidRange {
                message: "start > end".into()
            }
            .is_memory_error()
        );
        assert!(!CoreError::io("err").is_memory_error());
    }

    // ── From conversions ──────────────────────────────────────────────────────

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let core_err = CoreError::from(io_err);
        assert!(core_err.is_io());
        assert!(core_err.to_string().contains("file not found"));
    }

    #[test]
    fn from_utf8_error() {
        let bad: Vec<u8> = vec![0xFF, 0xFE];
        let utf8_err = String::from_utf8(bad).unwrap_err();
        let core_err = CoreError::from(utf8_err);
        assert!(matches!(core_err, CoreError::Utf8Error { .. }));
    }

    #[test]
    fn from_str_utf8_error() {
        // 0xFF is never valid in UTF-8.
        let bad: Vec<u8> = vec![0xFFu8, 0xFE];
        let e = std::str::from_utf8(bad.as_slice()).unwrap_err();
        let core_err = CoreError::from(e);
        assert!(matches!(core_err, CoreError::Utf8Error { .. }));
    }

    // ── ErrorContext ──────────────────────────────────────────────────────────

    #[test]
    fn error_context_display() {
        let ctx = ErrorContext::new(CoreError::io("disk full"), "loading segment table");
        assert_eq!(
            ctx.to_string(),
            "loading segment table: I/O error: disk full"
        );
    }

    #[test]
    fn error_context_into_inner() {
        let inner = CoreError::internal("bug");
        let ctx = ErrorContext::new(inner.clone(), "ctx");
        assert_eq!(ctx.into_inner(), inner);
    }

    // ── ResultExt ─────────────────────────────────────────────────────────────

    #[test]
    fn attach_context_propagates() {
        let r: Result<u32> = Err(CoreError::io("error"));
        let with_ctx = r.attach_context("parsing header");
        let err = with_ctx.unwrap_err();
        assert_eq!(err.context, "parsing header");
        assert!(err.error.is_io());
    }

    #[test]
    fn attach_context_on_ok() {
        let r: Result<u32> = Ok(42);
        let with_ctx = r.attach_context("should not matter");
        assert_eq!(with_ctx.unwrap(), 42);
    }

    #[test]
    fn with_context_lazy() {
        let r: Result<u32> = Err(CoreError::io("bad"));
        let mut called = false;
        let _ = r.with_context(|| {
            called = true;
            "lazy context".to_string()
        });
        assert!(called);
    }

    #[test]
    fn with_context_not_called_on_ok() {
        let r: Result<u32> = Ok(7);
        let mut called = false;
        let val = r.with_context(|| {
            called = true;
            "nope".to_string()
        });
        assert!(!called);
        assert_eq!(val.unwrap(), 7);
    }

    // ── bail_core! macro ──────────────────────────────────────────────────────

    #[test]
    fn bail_core_macro() {
        fn always_fails() -> Result<u32> {
            bail_core!(CoreError::internal("always"));
        }
        assert!(always_fails().is_err());
    }

    // ── ensure_core! macro ────────────────────────────────────────────────────

    #[test]
    fn ensure_core_passes() {
        fn check_len(v: &[u8]) -> Result<()> {
            ensure_core!(v.len() >= 4, CoreError::truncated(4, v.len()));
            Ok(())
        }
        assert!(check_len(&[1, 2, 3, 4]).is_ok());
        assert!(check_len(&[1]).is_err());
    }

    // ── All variants are constructible ────────────────────────────────────────

    #[test]
    fn all_variants_construct() {
        let variants: Vec<CoreError> = vec![
            CoreError::IoError {
                message: "m".into(),
            },
            CoreError::Utf8Error {
                message: "m".into(),
            },
            CoreError::EncodingError {
                encoding: "utf-16".into(),
                message: "m".into(),
            },
            CoreError::ParseError {
                offset: 0,
                message: "m".into(),
            },
            CoreError::InvalidFormat {
                message: "m".into(),
            },
            CoreError::Truncated {
                expected: 8,
                got: 4,
            },
            CoreError::InvalidAddress {
                message: "m".into(),
            },
            CoreError::InvalidRange {
                message: "m".into(),
            },
            CoreError::SegmentFault { address: 0 },
            CoreError::BadAlignment {
                address: 1,
                alignment: 4,
            },
            CoreError::RangeViolation {
                message: "m".into(),
            },
            CoreError::UnknownArchitecture { name: "xyz".into() },
            CoreError::ArchitectureError {
                arch: "x86".into(),
                message: "m".into(),
            },
            CoreError::LoaderError {
                loader: "pe".into(),
                message: "m".into(),
            },
            CoreError::AnalysisError {
                message: "m".into(),
            },
            CoreError::DecompileError {
                address: 0,
                message: "m".into(),
            },
            CoreError::PermissionDenied {
                address: 0,
                message: "m".into(),
            },
            CoreError::Unsupported {
                feature: "f".into(),
            },
            CoreError::PluginError {
                plugin: "p".into(),
                message: "m".into(),
            },
            CoreError::NetworkError {
                message: "m".into(),
            },
            CoreError::DatabaseError {
                message: "m".into(),
            },
            CoreError::Timeout { millis: 1000 },
            CoreError::Cancelled {
                reason: "user".into(),
            },
            CoreError::InvalidInput {
                message: "m".into(),
            },
            CoreError::Internal {
                message: "m".into(),
            },
        ];
        // All 25 variants constructed without panic.
        assert_eq!(variants.len(), 25);
    }

    // ── Clone + PartialEq ─────────────────────────────────────────────────────

    #[test]
    fn core_error_clone_eq() {
        let e = CoreError::io("err");
        assert_eq!(e.clone(), e);
    }
}
