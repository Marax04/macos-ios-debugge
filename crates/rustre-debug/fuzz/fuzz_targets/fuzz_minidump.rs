//! Fuzz target: feed random bytes to `minidump_analysis::parse`.
//!
//! The parser must not panic, infinite-loop, or produce UB on arbitrary input.
//!
//! Run (requires nightly + cargo-fuzz on Linux):
//!   cargo +nightly fuzz run fuzz_minidump -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustre_debug::minidump_analysis;

fuzz_target!(|data: &[u8]| {
    // Both parse and read_memory must be panic-free on arbitrary bytes.
    if let Ok(view) = minidump_analysis::parse(data) {
        // Exercise read_memory on every parsed descriptor with the same buffer.
        for desc in &view.memory_regions {
            let _ = minidump_analysis::read_memory(data, desc);
        }
    }
});
