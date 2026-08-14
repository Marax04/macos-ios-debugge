//! Auto-detection and opening of TTD traces.
//!
//! [`open_trace`] examines a path and returns the appropriate
//! [`crate::time_travel_debug::TtdBackend`] implementation:
//!
//! - If the path ends with `.run` or `.idx`, or a sibling `.idx` file exists
//!   next to a `.run`, it opens a [`crate::windbg_ttd_backend::WinDbgTtdBackend`].
//! - If the path is a directory containing `version` or `events`, it opens an
//!   [`crate::rr_backend::RrBackend`] (requires `rr` on `PATH`).
//!
//! The returned backend is boxed as `Box<dyn TtdBackend>` so it can be attached
//! directly to a [`crate::time_travel_debug::TtdSession`].

use std::path::Path;

use crate::rr_backend::RrBackend;
use crate::time_travel_debug::{TtdBackend, TtdError};
use crate::windbg_ttd_backend::WinDbgTtdBackend;

/// The kind of trace detected at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceKind {
    /// WinDbg TTD `.run` + `.idx` pair.
    WinDbgTtd,
    /// Mozilla `rr` trace directory.
    Rr,
}

/// Detect the kind of trace at `path` without opening it.
///
/// Returns `None` if the path is not a recognised trace format.
#[must_use]
pub fn detect_trace_kind(path: &Path) -> Option<TraceKind> {
    if WinDbgTtdBackend::is_ttd_trace(path) {
        return Some(TraceKind::WinDbgTtd);
    }
    if RrBackend::is_rr_trace(path) {
        return Some(TraceKind::Rr);
    }
    None
}

/// Open a trace at `path` and return a boxed [`crate::time_travel_debug::TtdBackend`].
///
/// Detection order:
/// 1. WinDbg TTD (`.run` / `.idx` extension or sibling files).
/// 2. rr trace directory (`version` / `events` sentinel files).
///
/// # Errors
///
/// Returns `TtdError::Unsupported` if the path format is not recognised, or
/// the appropriate backend error if opening fails.
pub fn open_trace(path: &Path) -> Result<Box<dyn TtdBackend>, TtdError> {
    match detect_trace_kind(path) {
        Some(TraceKind::WinDbgTtd) => {
            let backend = WinDbgTtdBackend::open(path)?;
            Ok(Box::new(backend))
        }
        Some(TraceKind::Rr) => {
            let backend = RrBackend::open(path)?;
            Ok(Box::new(backend))
        }
        None => Err(TtdError::Unsupported(format!(
            "unrecognised trace format at: {}",
            path.display()
        ))),
    }
}

// ── No mock fallback ─────────────────────────────────────────────────────────
//
// This module used to expose `open_trace_or_mock`, which swallowed the real
// backend's failure and handed the caller a `MockTtdBackend` that answered
// every seek/step with `pc=0, sp=0` and a `stop_reason` of
// `"mock:live=false:<reason>"`. Two things made it dangerous:
//
// 1. The `live` flag was the *only* signal, returned out-of-band as the second
//    tuple element. Anything that dropped it — a `.0`, a `let (b, _)` — got a
//    backend that answers confidently and wrongly, forever.
// 2. `TtdState` serialises identically either way. Once the state crossed an
//    MCP boundary the `pc=0` was indistinguishable from a real trace whose
//    first instruction happens to be at 0.
//
// Callers use [`open_trace`], which returns the backend's own error naming why
// the trace could not be opened (missing `.idx`, `rr` not on `PATH`,
// unrecognised format). There is deliberately no non-live substitute.

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_windbg_by_extension() {
        // Detection is by extension — the file doesn't need to exist.
        assert_eq!(
            detect_trace_kind(Path::new("foo.run")),
            Some(TraceKind::WinDbgTtd)
        );
        assert_eq!(
            detect_trace_kind(Path::new("foo.idx")),
            Some(TraceKind::WinDbgTtd)
        );
    }

    #[test]
    fn detect_rr_trace_directory() {
        let tmp = std::env::temp_dir().join("ttd_open_rr_detect");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("version"), b"86").unwrap();

        assert_eq!(detect_trace_kind(&tmp), Some(TraceKind::Rr));
    }

    #[test]
    fn detect_unknown_returns_none() {
        assert_eq!(detect_trace_kind(Path::new("foo.exe")), None);
    }

    #[test]
    fn open_trace_windbg_missing_files_errors() {
        let tmp = std::env::temp_dir().join("ttd_open_windbg_missing");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        // .run exists but .idx does not → backend error.
        let run = tmp.join("ghost.run");
        fs::write(&run, b"").unwrap();
        let err = open_trace(&run).unwrap_err();
        assert!(matches!(err, TtdError::Backend(_)));
    }

    #[test]
    fn open_trace_unknown_format_errors() {
        let err = open_trace(Path::new("no_extension_no_dir")).unwrap_err();
        assert!(matches!(err, TtdError::Unsupported(_)));
    }

    // ── Live-only guarantee ──────────────────────────────────────────────────

    #[test]
    fn unopenable_trace_errors_and_the_message_names_the_path() {
        // Previously this path produced a MockTtdBackend with live=false; the
        // only honest answer is an error that says WHICH path failed.
        let missing = Path::new("this_trace_does_not_exist_anywhere");
        let err = open_trace(missing).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("this_trace_does_not_exist_anywhere"),
            "error must name the path it could not open, got: {msg:?}"
        );
    }

    #[test]
    fn windbg_missing_idx_error_names_the_missing_file() {
        let tmp = std::env::temp_dir().join("ttd_open_live_only_guard");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let run = tmp.join("ghost.run");
        fs::write(&run, b"").unwrap();

        let err = open_trace(&run).unwrap_err();
        let msg = err.to_string();
        // The reason must be in the message, not hidden behind a `live=false`
        // flag on a substitute backend.
        assert!(
            msg.contains("ghost") || msg.contains("idx"),
            "error must name the missing sibling/file, got: {msg:?}"
        );
        assert!(
            !msg.contains("mock"),
            "no mock substitute may be reported here, got: {msg:?}"
        );
    }

    #[test]
    fn this_module_exposes_no_mock_or_non_live_backend() {
        // A source-level guard: the fallback was deleted deliberately, and a
        // future edit that reintroduces one should fail here rather than ship.
        let src = include_str!("ttd_open.rs");
        let production: &str = src
            .split_once("#[cfg(test)]")
            .map_or(src, |(head, _)| head);
        for needle in ["MockTtdBackend", "open_trace_or_mock"] {
            assert!(
                !production.contains(&format!("pub struct {needle}"))
                    && !production.contains(&format!("pub fn {needle}")),
                "{needle} must not exist in production code"
            );
        }
        assert!(
            !production.contains("impl TtdBackend for"),
            "ttd_open must only DETECT and OPEN backends, never define one"
        );
    }
}
