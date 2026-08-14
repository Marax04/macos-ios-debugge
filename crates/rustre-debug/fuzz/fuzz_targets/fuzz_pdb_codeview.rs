//! Fuzz target: feed random bytes to the CodeView / PDB MSF parser.
//!
//! Exercises both the raw MSF reader and the TPI/CodeView layer on top of it.
//! None of the parsers must panic on arbitrary input.
//!
//! Run (requires nightly + cargo-fuzz on Linux):
//!   cargo +nightly fuzz run fuzz_pdb_codeview -- -max_total_time=60

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustre_debug::codeview::msf_reader::{MsfReader, extract_tpi_stream};
use rustre_debug::codeview::codeview_type_parser::CodeViewTypeParser;
use rustre_debug::codeview::pdb_tpi_reader::TpiReader;

fuzz_target!(|data: &[u8]| {
    // Layer 1: raw MSF container parse.
    if let Ok(msf) = MsfReader::parse(data) {
        for i in 0..msf.num_streams() {
            let _ = msf.read_stream(i);
        }
    }
    // Layer 2: TPI stream extraction (MSF parse + TPI index lookup).
    if let Ok(tpi_bytes) = extract_tpi_stream(data) {
        // Layer 3a: PDB TPI reader — parse_raw_records accepts any byte slice.
        let _ = TpiReader::parse_raw_records(&tpi_bytes);
        // Layer 3b: CodeView type parser incremental interface.
        let mut parser = CodeViewTypeParser::new();
        parser.parse_stream(&tpi_bytes);
    }
});
