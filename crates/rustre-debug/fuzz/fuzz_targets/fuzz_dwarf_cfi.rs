//! Fuzz target: feed random bytes to the DWARF CFI unwind parser.
//!
//! Exercises `parse_cie`, `parse_fde`, and `run_cfi_to_offset` with arbitrary
//! byte sequences.  All functions must be panic-free on bad input.
//!
//! Run (requires nightly + cargo-fuzz on Linux):
//!   cargo +nightly fuzz run fuzz_dwarf_cfi -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustre_debug::dwarf_cfi::{parse_cie, parse_fde, run_cfi_to_offset};

fuzz_target!(|data: &[u8]| {
    // Exercise CIE parser on arbitrary bytes.
    let cie_opt = parse_cie(data);

    // Exercise FDE parser with an arbitrary pointer encoding byte.
    let pe = data.last().copied().unwrap_or(0);
    let _ = parse_fde(data, 0, pe);

    // If we parsed a valid CIE, try to run CFI interpretation.
    if let Some(cie) = cie_opt {
        // run_cfi_to_offset(initial_instrs, fde_instrs, code_align, data_align, target_offset)
        let _ = run_cfi_to_offset(
            data,           // initial (CIE) instructions
            data,           // FDE instructions (reuse same fuzz bytes)
            cie.code_alignment_factor,
            cie.data_alignment_factor,
            0,              // target_offset: PC = start
        );
    }
});
