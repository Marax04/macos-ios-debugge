//! Fuzz target: feed random bytes to `WinDbgTtdBackend::open`.
//!
//! The fuzzer writes the input to a temporary `.idx` file so the backend's
//! file-format parser is exercised with arbitrary byte sequences.  All errors
//! are expected (the parser must not panic or produce UB on bad input).
//!
//! Run (requires nightly + cargo-fuzz on Linux):
//!   cargo +nightly fuzz run fuzz_windbg_ttd_idx -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustre_debug::windbg_ttd_backend::WinDbgTtdBackend;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // Write fuzz bytes to a temp file with .idx extension so the backend
    // attempts to parse it as a WinDbg TTD index file.
    let mut tmp = tempfile::Builder::new()
        .suffix(".idx")
        .tempfile()
        .expect("tempfile");
    let _ = tmp.write_all(data);
    let _ = tmp.flush();
    // The open call must not panic regardless of the content.
    let _ = WinDbgTtdBackend::open(tmp.path());
});
