//! Standalone decompile driver for the multi-language fidelity corpus.
//!
//! Usage: dump_decompile <binary_path> <out_dir>
//!
//! Runs load → detect → disassemble → lift → pipeline over every detected
//! function and writes one `sub_<addr>.c` pseudo-C file per function plus a
//! `summary.json`. Used by the tests/ multi-language fidelity workflow to
//! compare RustRE output against the original source.

use std::path::Path;
use std::process::ExitCode;

use rustre_decompiler::batch_decompiler::{BatchConfig, BatchDecompiler};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!(
            "usage: {} <binary_path> <out_dir> [--hlil-experimental]",
            args[0]
        );
        return ExitCode::from(2);
    }
    let bin = Path::new(&args[1]);
    let out = Path::new(&args[2]);

    let mut config = BatchConfig::default();
    if args.get(3).map(String::as_str) == Some("--hlil-experimental") {
        config.decompiler_opts.passes.hlil_experimental = true;
    }
    // Phase 1 whole-project reconstruction bucketing, opt-in only (see
    // `source_bucketing.rs`); default OFF keeps this driver's output
    // byte-identical to before this flag existed.
    config.bucket_by_source = rustre_decompiler::bucket_by_source_opt_in(
        std::env::var("RUSTRE_BUCKET_BY_SOURCE").ok().as_deref(),
    );
    match BatchDecompiler::decompile_all_from_binary(bin, out, &config) {
        Ok(result) => {
            println!(
                "{{\"binary\":\"{}\",\"decompiled\":{},\"failed\":{},\"elapsed_ms\":{}}}",
                bin.display(),
                result.stats.functions_decompiled,
                result.stats.functions_failed,
                result.elapsed_ms
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("decompile error: {e}");
            ExitCode::FAILURE
        }
    }
}
