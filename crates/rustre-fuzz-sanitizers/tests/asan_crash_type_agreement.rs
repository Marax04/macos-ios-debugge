//! Do the crate's two ASan crash-type extractors agree?
//!
//! `AsanReportParser::extract_error_type` takes the first token after
//! `AddressSanitizer:`. `CrashParser::parse_asan` instead scans for the first
//! token containing `-`, `overflow` or `free`.
//!
//! The corpus below is drawn from the shapes real ASan headers actually take,
//! deliberately including cases that stress BOTH rules — a bug type with no
//! hyphen (`SEGV`, `FPE`) and one where the header puts a filler word before
//! the type (`attempting double-free`). Electing an oracle from a single case
//! is how you pick the wrong one.

use rustre_fuzz_sanitizers::asan_report_parser::AsanReportParser;
use rustre_fuzz_sanitizers::crash_deduplicator::CrashParser;

fn header(body: &str) -> String {
    format!(
        "=================================================================\n\
         ==4242==ERROR: AddressSanitizer: {body}\n\
         READ of size 4 at 0x602000000018 thread T0\n    \
         #0 0x401234 in main /src/a.c:10\n"
    )
}

/// (label, header body, the bug type a reader of the report would name)
fn corpus() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "hyphenated type",
            "heap-buffer-overflow on address 0x602000000018 at pc 0x401234",
            "heap-buffer-overflow",
        ),
        (
            "use-after-free",
            "heap-use-after-free on address 0x602000000018 at pc 0x401234",
            "heap-use-after-free",
        ),
        (
            "stack overflow",
            "stack-overflow on address 0x7ffd at pc 0x401234",
            "stack-overflow",
        ),
        (
            // No hyphen anywhere: stresses the token-must-contain-'-' rule.
            "SEGV",
            "SEGV on unknown address 0x000000000000 (pc 0x401234)",
            "SEGV",
        ),
        (
            // Also no hyphen.
            "FPE",
            "FPE on unknown address 0x401234",
            "FPE",
        ),
        (
            // A filler word sits between the colon and the type: stresses the
            // first-token-after-the-colon rule.
            "double free with filler word",
            "attempting double-free on 0x602000000010 in thread T0",
            "double-free",
        ),
    ]
}

fn via_report_parser(text: &str) -> String {
    AsanReportParser::parse(text).map_or_else(|| "<none>".to_string(), |r| r.error_type_raw)
}

fn via_crash_parser(text: &str) -> String {
    CrashParser::parse_asan(text).map_or_else(|| "<none>".to_string(), |c| c.crash_type_str)
}

#[test]
fn the_two_extractors_agree_on_the_bug_type() {
    let cases = corpus();
    assert!(cases.len() >= 6, "anti-vacuity: expected the full corpus");

    let mut disagreements = Vec::new();
    for (label, body, expected) in &cases {
        let text = header(body);
        let a = via_report_parser(&text);
        let b = via_crash_parser(&text);
        if a != b {
            disagreements.push(format!(
                "  {label}: report_parser={a:?} crash_parser={b:?} (a reader would say {expected:?})"
            ));
        }
    }

    assert!(
        disagreements.is_empty(),
        "the two ASan crash-type extractors disagree on {} of {} cases:\n{}",
        disagreements.len(),
        cases.len(),
        disagreements.join("\n")
    );
}

#[test]
fn each_extractor_names_the_bug_type_a_reader_would_name() {
    let cases = corpus();
    let mut report_parser_wrong = Vec::new();
    let mut crash_parser_wrong = Vec::new();

    for (label, body, expected) in &cases {
        let text = header(body);
        let a = via_report_parser(&text);
        let b = via_crash_parser(&text);
        if a != *expected {
            report_parser_wrong.push(format!("  {label}: got {a:?}, want {expected:?}"));
        }
        if b != *expected {
            crash_parser_wrong.push(format!("  {label}: got {b:?}, want {expected:?}"));
        }
    }

    assert!(
        report_parser_wrong.is_empty() && crash_parser_wrong.is_empty(),
        "AsanReportParser wrong on {} case(s):\n{}\nCrashParser wrong on {} case(s):\n{}",
        report_parser_wrong.len(),
        report_parser_wrong.join("\n"),
        crash_parser_wrong.len(),
        crash_parser_wrong.join("\n"),
    );
}
