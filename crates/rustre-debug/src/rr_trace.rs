//! Mozilla `rr` record/replay trace integration (Linux-only).
//!
//! Parses the on-disk layout of an `rr` trace directory (produced by
//! `rr record <cmd>` and stored in `~/.local/share/rr/<cmd>-<n>/`) to expose
//! session metadata, recorded processes, and event-count information without
//! requiring `rr` to be installed at query time.
//!
//! The full rr binary event format is intentionally NOT parsed here — it is an
//! unstable internal format that changes between rr versions. Instead this
//! module reads the text/structured files that rr deliberately exposes:
//!
//! | File | Content |
//! |------|---------|
//! | `version` | Integer trace-format version |
//! | `bind_to_cpu` | CPU core the trace was pinned to (`-1` if none) |
//! | `mmap_hardlink_*` | Hard-linked copies of mapped binaries |
//! | `tasks/<tid>` | Per-thread event-count files |
//! | `events` | Binary event stream (size in bytes reported only) |
//! | `mmaps` | Binary mmap event stream (size reported only) |
//!
//! This is enough to power MCP tools that tell an LLM agent:
//! - Which trace directory to use (`list_traces`)
//! - High-level metadata about a specific trace (`trace_info`)
//! - Which process/thread TIDs are recorded (`trace_tasks`)
//!
//! For actual replay, the caller is expected to invoke `rr replay` or `rr gdb`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error type for rr trace operations.
#[derive(Debug, thiserror::Error)]
pub enum RrError {
    /// I/O error accessing the trace directory.
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The path is not a valid rr trace directory.
    #[error("not an rr trace directory: {path}")]
    NotATrace { path: String },
    /// A file inside the trace directory had an unexpected format.
    #[error("parse error in {path}: {detail}")]
    Parse { path: String, detail: String },
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Metadata for a single rr trace directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceInfo {
    /// Absolute path to the trace directory.
    pub path: String,
    /// rr trace-format version (from `version` file), if present.
    pub format_version: Option<u32>,
    /// CPU the trace was pinned to (`-1` means no pinning), if present.
    pub bind_to_cpu: Option<i32>,
    /// List of thread IDs recorded in this trace.
    pub task_tids: Vec<u32>,
    /// Size in bytes of the raw event stream (`events` file), if present.
    pub events_bytes: Option<u64>,
    /// Size in bytes of the mmap event stream (`mmaps` file), if present.
    pub mmaps_bytes: Option<u64>,
    /// Names of hard-linked binary files captured with the trace.
    pub captured_binaries: Vec<String>,
}

/// A summary entry for a trace discovered in the rr traces directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceSummary {
    /// Short directory name (e.g. `bash-0`).
    pub name: String,
    /// Absolute path.
    pub path: String,
    /// Format version if readable.
    pub format_version: Option<u32>,
    /// Number of recorded threads.
    pub task_count: usize,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn io_err(path: &str, e: std::io::Error) -> RrError {
    RrError::Io { path: path.to_owned(), source: e }
}

fn read_file_str(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn file_size(p: &Path) -> Option<u64> {
    std::fs::metadata(p).ok().map(|m| m.len())
}

fn is_rr_trace(dir: &Path) -> bool {
    // An rr trace directory always contains a `version` file and a `tasks`
    // sub-directory (added in rr 5.x). Older traces may omit `tasks` but always
    // have `events`. Accept either.
    dir.join("version").exists() || dir.join("events").exists()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return the default rr traces root directory.
///
/// rr stores traces in `$_RR_TRACE_DIR` if set, otherwise
/// `$XDG_DATA_HOME/rr` (default `~/.local/share/rr`).
#[must_use]
pub fn default_traces_dir() -> PathBuf {
    if let Ok(d) = std::env::var("_RR_TRACE_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(d) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(d).join("rr");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
    PathBuf::from(home).join(".local/share/rr")
}

/// List all rr trace directories under `root`.
///
/// # Errors
/// Returns [`RrError::Io`] if `root` cannot be read.
pub fn list_traces(root: &Path) -> Result<Vec<TraceSummary>, RrError> {
    let dir_iter = std::fs::read_dir(root)
        .map_err(|e| io_err(root.to_string_lossy().as_ref(), e))?;

    let mut summaries = Vec::new();
    for entry in dir_iter.flatten() {
        let path = entry.path();
        if !path.is_dir() || !is_rr_trace(&path) {
            continue;
        }
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let format_version = read_file_str(&path.join("version"))
            .and_then(|s| s.trim().parse::<u32>().ok());
        let task_count = count_tasks(&path);
        summaries.push(TraceSummary {
            name,
            path: path.to_string_lossy().into_owned(),
            format_version,
            task_count,
        });
    }
    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(summaries)
}

fn count_tasks(trace_dir: &Path) -> usize {
    let tasks_dir = trace_dir.join("tasks");
    if !tasks_dir.is_dir() {
        return 0;
    }
    std::fs::read_dir(tasks_dir)
        .map(|rd| rd.flatten().count())
        .unwrap_or(0)
}

/// Read full [`TraceInfo`] for the trace at `trace_dir`.
///
/// # Errors
/// Returns [`RrError::NotATrace`] if the directory does not look like an rr
/// trace, or [`RrError::Io`] on read failures.
pub fn trace_info(trace_dir: &Path) -> Result<TraceInfo, RrError> {
    if !is_rr_trace(trace_dir) {
        return Err(RrError::NotATrace {
            path: trace_dir.to_string_lossy().into_owned(),
        });
    }

    let path_str = trace_dir.to_string_lossy().into_owned();

    let format_version = read_file_str(&trace_dir.join("version"))
        .and_then(|s| s.trim().parse::<u32>().ok());

    let bind_to_cpu = read_file_str(&trace_dir.join("bind_to_cpu"))
        .and_then(|s| s.trim().parse::<i32>().ok());

    let task_tids = read_task_tids(trace_dir);
    let events_bytes = file_size(&trace_dir.join("events"));
    let mmaps_bytes = file_size(&trace_dir.join("mmaps"));
    let captured_binaries = read_captured_binaries(trace_dir);

    Ok(TraceInfo {
        path: path_str,
        format_version,
        bind_to_cpu,
        task_tids,
        events_bytes,
        mmaps_bytes,
        captured_binaries,
    })
}

fn read_task_tids(trace_dir: &Path) -> Vec<u32> {
    let tasks_dir = trace_dir.join("tasks");
    if !tasks_dir.is_dir() {
        return Vec::new();
    }
    let mut tids = Vec::new();
    if let Ok(rd) = std::fs::read_dir(tasks_dir) {
        for entry in rd.flatten() {
            if let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            {
                tids.push(tid);
            }
        }
    }
    tids.sort_unstable();
    tids
}

fn read_captured_binaries(trace_dir: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(trace_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("mmap_hardlink_") {
                names.push(name);
            }
        }
    }
    names.sort();
    names
}

/// Check whether `rr` is installed and return its version string.
///
/// Runs `rr --version` as a subprocess and captures stdout.
/// Returns `None` if `rr` is not found in `PATH` or the invocation fails.
#[must_use]
pub fn rr_version() -> Option<String> {
    let out = std::process::Command::new("rr")
        .arg("--version")
        .output()
        .ok()?;
    if out.status.success() {
        String::from_utf8(out.stdout).ok().map(|s| s.trim().to_owned())
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_fake_trace(root: &Path, name: &str, version: u32, tids: &[u32]) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("tasks")).unwrap();
        fs::write(dir.join("version"), version.to_string()).unwrap();
        fs::write(dir.join("bind_to_cpu"), "-1").unwrap();
        // Fake events file
        fs::write(dir.join("events"), b"FAKE_EVENTS").unwrap();
        for tid in tids {
            fs::write(dir.join("tasks").join(tid.to_string()), b"").unwrap();
        }
        dir
    }

    #[test]
    fn list_and_info_roundtrip() {
        let tmp = std::env::temp_dir().join("rr_trace_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        make_fake_trace(&tmp, "bash-0", 86, &[1000, 1001]);
        make_fake_trace(&tmp, "ls-1", 86, &[2000]);

        let summaries = list_traces(&tmp).unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].name, "bash-0");
        assert_eq!(summaries[0].task_count, 2);
        assert_eq!(summaries[1].name, "ls-1");

        let info = trace_info(&tmp.join("bash-0")).unwrap();
        assert_eq!(info.format_version, Some(86));
        assert_eq!(info.bind_to_cpu, Some(-1));
        assert_eq!(info.task_tids, vec![1000, 1001]);
        assert!(info.events_bytes.unwrap_or(0) > 0);
    }

    #[test]
    fn not_a_trace_error() {
        let tmp = std::env::temp_dir().join("rr_not_a_trace");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let err = trace_info(&tmp).unwrap_err();
        assert!(matches!(err, RrError::NotATrace { .. }));
    }

    #[test]
    fn default_traces_dir_non_empty_path() {
        let d = default_traces_dir();
        assert!(d.to_str().map(|s| !s.is_empty()).unwrap_or(false));
    }
}
