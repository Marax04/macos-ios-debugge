//! Agreement between the crate's two ASan report parsers on well-formed input.
//!
//! `AsanAnalyzer::parse_all` and `AsanReportParser::parse_all` independently
//! split a log into per-crash blocks. This file pins the domain where their
//! contracts genuinely coincide: a log made of N well-formed
//! `==PID==ERROR: AddressSanitizer: …` blocks must yield N reports from both.
//!
//! Two divergences are deliberately NOT asserted here, because deciding them is
//! a product call rather than a provable defect — see the notes on each:
//!
//! * headerless input — `AsanAnalyzer` synthesises one report (consistent with
//!   its total `parse`), while `AsanReportParser` and the generic
//!   `SanitizerLogParser` both return none.
//! * foreign sanitizers — `AsanAnalyzer` splits on any `==ERROR:`, while
//!   `AsanReportParser::is_asan_header` also requires `AddressSanitizer`.

use rustre_fuzz_sanitizers::asan_analyzer::AsanAnalyzer;
use rustre_fuzz_sanitizers::asan_report_parser::AsanReportParser;

fn asan_block(pid: u32, addr: &str) -> String {
    format!(
        "=================================================================\n\
         =={pid}==ERROR: AddressSanitizer: heap-buffer-overflow on address {addr} at pc 0x401234 bp 0x7ffd sp 0x7ffc\n\
         READ of size 4 at {addr} thread T0\n    \
         #0 0x401234 in main /src/a.c:10\n"
    )
}

/// Logs of N well-formed ASan blocks, N = 1..=3.
fn well_formed_logs() -> Vec<(usize, String)> {
    (1usize..=3)
        .map(|n| {
            let log: String = (0..n)
                .map(|i| asan_block(1000 + u32::try_from(i).unwrap(), "0x602000000018"))
                .collect::<Vec<_>>()
                .join("\n");
            (n, log)
        })
        .collect()
}

#[test]
fn both_parsers_find_the_same_number_of_well_formed_reports() {
    let logs = well_formed_logs();
    assert_eq!(logs.len(), 3, "anti-vacuity: expected logs with 1, 2 and 3 blocks");

    for (n, log) in logs {
        let analyzer = AsanAnalyzer::parse_all(&log).len();
        let parser = AsanReportParser::parse_all(&log).len();
        assert_eq!(
            analyzer, parser,
            "a log of {n} well-formed ASan blocks: AsanAnalyzer saw {analyzer}, \
             AsanReportParser saw {parser}"
        );
        assert_eq!(
            analyzer, n,
            "a log of {n} well-formed ASan blocks must yield {n} reports, got {analyzer}"
        );
    }
}

#[test]
fn a_single_block_is_not_split_further() {
    // Guards against a boundary rule that fires on lines inside a block (the
    // stack frame, the READ line) rather than only on the header.
    let log = asan_block(4242, "0x602000000018");
    assert_eq!(AsanAnalyzer::parse_all(&log).len(), 1);
    assert_eq!(AsanReportParser::parse_all(&log).len(), 1);
}

#[test]
fn leading_and_trailing_noise_does_not_change_the_count() {
    // Build output before the crash and shutdown chatter after it are normal in
    // a real fuzzing log and must not create or destroy reports.
    let core = asan_block(77, "0x602000000018");
    let log = format!("configuring...\nbuilding target\n{core}\nSUMMARY: done\nexiting\n");
    let analyzer = AsanAnalyzer::parse_all(&log).len();
    let parser = AsanReportParser::parse_all(&log).len();
    assert_eq!(
        analyzer, parser,
        "noise around one block: AsanAnalyzer saw {analyzer}, AsanReportParser saw {parser}"
    );
    assert_eq!(analyzer, 1, "one crash surrounded by noise is still one crash");
}
