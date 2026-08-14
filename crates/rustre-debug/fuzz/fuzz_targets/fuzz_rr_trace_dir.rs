//! Fuzz target: exercise rr trace-directory parsing with random file contents.
//!
//! Creates a temporary directory with a `version` file containing arbitrary
//! bytes, then calls the list/info functions which parse the version/events
//! files.  On non-Linux hosts this target is a no-op (rr is Linux-only).
//!
//! Run (requires nightly + cargo-fuzz on Linux):
//!   cargo +nightly fuzz run fuzz_rr_trace_dir -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // rr is Linux-only; on other platforms this fuzz target is intentionally
    // a no-op so that the binary still compiles and the CI gate passes.
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let version_path = dir.path().join("version");
        if let Ok(mut f) = std::fs::File::create(&version_path) {
            let _ = f.write_all(data);
        }
        let events_path = dir.path().join("events");
        if let Ok(mut f) = std::fs::File::create(&events_path) {
            let _ = f.write_all(data);
        }
        let _ = rustre_debug::rr_trace::trace_info(dir.path());
        let _ = rustre_debug::rr_trace::list_traces(dir.path());
    }
    let _ = data; // suppress unused warning on non-Linux
});
