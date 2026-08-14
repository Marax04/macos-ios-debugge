//! Exhaustive test suite for `rustre-cli`. Tests target public APIs in
//! `lib.rs`: argument parsing, config file parsing, output formatting,
//! hex/ASCII/count formatters, SHA-256, file-type detection, Shannon
//! entropy, byte histogram, packing indicators, table rendering, color
//! helpers, progress bar, run_analyze / run_triage / run_diff (end-to-end
//! via tempfile).

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rustre_cli::{
    ArgParser, CliConfig, CliError, ColAlign, Color, ConfigValue, InteractiveSession,
    OutputFormat, ProgressBar, SubCommand, Table, build_help_text, byte_histogram, colorize,
    detect_file_type, detect_packing_indicators, fmt_addr, fmt_ascii, fmt_count, fmt_hex_bytes,
    run_analyze, run_diff, run_triage, sha256_hex, shannon_entropy,
};

// ───────────────────────── helpers ─────────────────────────

fn tmp_file(name: &str, bytes: &[u8]) -> PathBuf {
    let mut p = std::env::temp_dir();
    // unique-ish per process+name
    p.push(format!("rustre_cli_blitz_{}_{}", std::process::id(), name));
    let mut f = std::fs::File::create(&p).expect("create temp file");
    f.write_all(bytes).expect("write temp file");
    p
}

// ───────────────────────── OutputFormat ─────────────────────────

#[test]
fn outputformat_roundtrip_all_names() {
    for name in OutputFormat::all_names() {
        let f: OutputFormat = name.parse().expect("parse known name");
        assert_eq!(f.name(), *name, "round-trip name mismatch for {name}");
        assert_eq!(f.to_string(), *name);
    }
}

#[test]
fn outputformat_unknown_returns_invalid_value() {
    let err = "xml".parse::<OutputFormat>().unwrap_err();
    match err {
        CliError::InvalidValue { arg, .. } => assert_eq!(arg, "--format"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn outputformat_default_is_table() {
    assert_eq!(OutputFormat::default(), OutputFormat::Table);
}

#[test]
fn outputformat_html_sarif_recognised() {
    assert_eq!("html".parse::<OutputFormat>().unwrap(), OutputFormat::Html);
    assert_eq!("sarif".parse::<OutputFormat>().unwrap(), OutputFormat::Sarif);
}

// ───────────────────────── ArgParser ─────────────────────────

#[test]
fn argparser_double_dash_collects_positionals() {
    // After `--`, all tokens are treated as positionals. The first becomes
    // the subcommand resolution attempt. "help" should still resolve.
    let args = ArgParser::new(vec!["--".into(), "help".into()])
        .parse()
        .unwrap();
    assert_eq!(args.subcommand, SubCommand::Help);
}

#[test]
fn argparser_short_combined_flags() {
    let args = ArgParser::new(vec!["-vvq".into()]).parse().unwrap();
    assert_eq!(args.verbosity, 3); // default 1 + 2 -v
    assert!(args.quiet);
}

#[test]
fn argparser_short_uppercase_v_means_version() {
    let args = ArgParser::new(vec!["-V".into()]).parse().unwrap();
    assert_eq!(args.subcommand, SubCommand::Version);
}

#[test]
fn argparser_invalid_short_flag() {
    let result = ArgParser::new(vec!["-Z".into()]).parse();
    assert!(matches!(result, Err(CliError::UnknownCommand(_))));
}

#[test]
fn argparser_format_invalid_value_propagates() {
    let result = ArgParser::new(vec!["--format=bogus".into()]).parse();
    assert!(matches!(result, Err(CliError::InvalidValue { .. })));
}

#[test]
fn argparser_disassemble_defaults_when_only_path() {
    let args = ArgParser::new(vec!["disassemble".into(), "a.bin".into()])
        .parse()
        .unwrap();
    match args.subcommand {
        SubCommand::Disassemble {
            path,
            arch,
            base_addr,
            count,
        } => {
            assert_eq!(path, PathBuf::from("a.bin"));
            assert_eq!(arch, "x86_64");
            assert_eq!(base_addr, 0);
            assert!(count.is_none());
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn argparser_analyse_alias_analyze() {
    let args = ArgParser::new(vec!["analyze".into(), "x".into()])
        .parse()
        .unwrap();
    assert!(matches!(args.subcommand, SubCommand::Analyse { .. }));
}

#[test]
fn argparser_analyse_with_addr() {
    let args = ArgParser::new(vec![
        "analyse".into(),
        "x".into(),
        "x86_64".into(),
        "0x1000".into(),
    ])
    .parse()
    .unwrap();
    match args.subcommand {
        SubCommand::Analyse {
            base_addr, arch, ..
        } => {
            assert_eq!(base_addr, Some(0x1000));
            assert_eq!(arch.as_deref(), Some("x86_64"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn argparser_export_with_format() {
    let args = ArgParser::new(vec![
        "export".into(),
        "in".into(),
        "out".into(),
        "json".into(),
    ])
    .parse()
    .unwrap();
    match args.subcommand {
        SubCommand::Export { format, .. } => assert_eq!(format, OutputFormat::Json),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn argparser_export_missing_output_errors() {
    let result = ArgParser::new(vec!["export".into(), "in".into()]).parse();
    assert!(matches!(result, Err(CliError::MissingArgument(_))));
}

#[test]
fn argparser_disassemble_bad_count() {
    let result = ArgParser::new(vec![
        "disassemble".into(),
        "x".into(),
        "x86_64".into(),
        "0".into(),
        "notanumber".into(),
    ])
    .parse();
    assert!(matches!(result, Err(CliError::InvalidValue { .. })));
}

// ───────────────────────── CliConfig ─────────────────────────

#[test]
fn config_load_from_file_simple() {
    let path = tmp_file(
        "cfg_simple.cfg",
        b"# comment\n\nkey1 = hello\nkey2 = 42\nkey3 = true\n",
    );
    let cfg = CliConfig::load_from_file(&path).unwrap();
    assert_eq!(cfg.get_str("key1"), Some("hello"));
    assert_eq!(cfg.get_int("key2"), Some(42));
    assert_eq!(cfg.get_bool("key3"), Some(true));
    assert_eq!(cfg.len(), 3);
}

#[test]
fn config_load_duplicate_key_errors() {
    let path = tmp_file("cfg_dup.cfg", b"a = 1\na = 2\n");
    let err = CliConfig::load_from_file(&path).unwrap_err();
    match err {
        CliError::Config(msg) => assert!(msg.contains("duplicate"), "got: {msg}"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn config_load_malformed_line_errors() {
    let path = tmp_file("cfg_bad.cfg", b"this_has_no_equals\n");
    let err = CliConfig::load_from_file(&path).unwrap_err();
    assert!(matches!(err, CliError::Config(_)));
}

#[test]
fn config_quoted_string_strips_quotes() {
    let path = tmp_file("cfg_q.cfg", b"a = \"hello world\"\nb = 'single'\n");
    let cfg = CliConfig::load_from_file(&path).unwrap();
    assert_eq!(cfg.get_str("a"), Some("hello world"));
    assert_eq!(cfg.get_str("b"), Some("single"));
}

#[test]
fn config_int_negative() {
    let path = tmp_file("cfg_neg.cfg", b"n = -42\n");
    let cfg = CliConfig::load_from_file(&path).unwrap();
    assert_eq!(cfg.get_int("n"), Some(-42));
}

#[test]
fn config_apply_overrides_sets_keys() {
    let mut cfg = CliConfig::new();
    let mut o = HashMap::new();
    o.insert("flag".into(), "true".into());
    o.insert("count".into(), "9".into());
    cfg.apply_overrides(&o).unwrap();
    assert_eq!(cfg.get_bool("flag"), Some(true));
    assert_eq!(cfg.get_int("count"), Some(9));
}

#[test]
fn config_output_format_fallback() {
    let cfg = CliConfig::new();
    assert_eq!(cfg.output_format(OutputFormat::Csv), OutputFormat::Csv);
}

#[test]
fn config_is_empty_new() {
    let cfg = CliConfig::new();
    assert!(cfg.is_empty());
    assert_eq!(cfg.len(), 0);
}

#[test]
fn configvalue_display() {
    assert_eq!(ConfigValue::String("hi".into()).to_string(), "hi");
    assert_eq!(ConfigValue::Int(7).to_string(), "7");
    assert_eq!(ConfigValue::Bool(false).to_string(), "false");
}

// ───────────────────────── Table ─────────────────────────

#[test]
fn table_json_escapes_quotes_and_backslashes() {
    let mut tbl = Table::new(vec!["k"]);
    tbl.push_row(vec!["he said \"hi\"\\"]);
    let json = tbl.render_json(false);
    // serde_json should escape \" and \\
    assert!(json.contains(r#"\""#), "missing escaped quote: {json}");
    assert!(json.contains(r"\\"), "missing escaped backslash: {json}");
}

#[test]
fn table_csv_escapes_newline_and_quote() {
    let mut tbl = Table::new(vec!["a"]);
    tbl.push_row(vec!["line1\nline2"]);
    let csv = tbl.render_csv();
    assert!(csv.contains("\"line1\nline2\""), "csv was: {csv}");
}

#[test]
fn table_render_table_contains_separator() {
    let tbl = Table::new(vec!["A", "B"]);
    let s = tbl.render_table();
    assert!(s.contains("+"));
    assert!(s.contains("A"));
}

#[test]
fn table_set_align_right() {
    let mut tbl = Table::new(vec!["N"]);
    tbl.set_align(0, ColAlign::Right);
    tbl.push_row(vec!["42"]);
    let s = tbl.render_table();
    assert!(s.contains("42"));
}

#[test]
fn table_lines_format_joins_tab() {
    let mut tbl = Table::new(vec!["a", "b"]);
    tbl.push_row(vec!["1", "2"]);
    let s = tbl.render(OutputFormat::Lines);
    assert!(s.contains("1\t2"));
}

#[test]
fn table_render_json_pretty_dispatches() {
    let mut tbl = Table::new(vec!["k"]);
    tbl.push_row(vec!["v"]);
    let s = tbl.render(OutputFormat::JsonPretty);
    // pretty JSON contains newlines
    assert!(s.contains('\n'));
}

// ───────────────────────── ColAlign ─────────────────────────

#[test]
fn colalign_default_left() {
    assert_eq!(ColAlign::default(), ColAlign::Left);
}

// ───────────────────────── Color / colorize ─────────────────────────

#[test]
fn color_ansi_reset() {
    assert_eq!(Color::Reset.ansi(), "\x1b[0m");
}

#[test]
fn colorize_resets_at_end_when_enabled() {
    let s = colorize("x", Color::Red, true);
    assert!(s.ends_with("\x1b[0m"));
    assert!(s.starts_with("\x1b[31m"));
}

// ───────────────────────── ProgressBar ─────────────────────────

#[test]
fn progressbar_with_width_chained() {
    let pb = ProgressBar::new("p", 1).with_width(10).quiet();
    // call elapsed to exercise getter
    let _ = pb.elapsed();
}

#[test]
fn progressbar_finish_does_not_panic() {
    let mut pb = ProgressBar::new("p", 5).quiet();
    pb.advance(3);
    pb.finish();
    assert!((pb.fraction() - 1.0).abs() < f64::EPSILON);
}

// ───────────────────────── hex/ascii/count helpers ─────────────────────────

#[test]
fn fmt_addr_default_for_weird_bits() {
    // Per the source, bits != 16 && != 32 falls through to 64-bit format.
    assert_eq!(fmt_addr(1, 12), "0x0000000000000001");
}

#[test]
fn fmt_hex_bytes_single() {
    assert_eq!(fmt_hex_bytes(&[0x00]), "00");
    assert_eq!(fmt_hex_bytes(&[0xFF]), "FF");
}

#[test]
fn fmt_ascii_space_preserved() {
    assert_eq!(fmt_ascii(b"a b"), "a b");
}

#[test]
fn fmt_ascii_empty() {
    assert_eq!(fmt_ascii(b""), "");
}

#[test]
fn fmt_count_grouping() {
    // boundary cases
    assert_eq!(fmt_count(0), "0");
    assert_eq!(fmt_count(1), "1");
    assert_eq!(fmt_count(12), "12");
    assert_eq!(fmt_count(123), "123");
    assert_eq!(fmt_count(1_234), "1_234");
    assert_eq!(fmt_count(12_345), "12_345");
    assert_eq!(fmt_count(123_456), "123_456");
    assert_eq!(fmt_count(1_000_000), "1_000_000");
    assert_eq!(fmt_count(u64::MAX), {
        // Build expected by direct grouping of decimal digits
        let s = u64::MAX.to_string();
        let mut out = String::new();
        for (i, ch) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                out.push('_');
            }
            out.push(ch);
        }
        out.chars().rev().collect::<String>()
    });
}

// ───────────────────────── SHA-256 ─────────────────────────

#[test]
fn sha256_hex_known_vector_empty() {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        sha256_hex(&[]),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_hex_known_vector_abc() {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ───────────────────────── detect_file_type ─────────────────────────

#[test]
fn detect_pe() {
    let (f, _) = detect_file_type(b"MZ\x90\x00");
    assert_eq!(f, "PE");
}

#[test]
fn detect_elf_x86_64() {
    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[18] = 0x3E;
    let (f, arch) = detect_file_type(&data);
    assert_eq!(f, "ELF");
    assert_eq!(arch, "x86_64");
}

#[test]
fn detect_elf_aarch64() {
    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[18] = 0xB7;
    let (_, arch) = detect_file_type(&data);
    assert_eq!(arch, "AArch64");
}

#[test]
fn detect_elf_too_short() {
    // Less than 19 bytes: arch should be "unknown".
    let data = b"\x7fELF\x02\x01\x01";
    let (f, arch) = detect_file_type(data);
    assert_eq!(f, "ELF");
    assert_eq!(arch, "unknown");
}

#[test]
fn detect_macho_le() {
    let (f, _) = detect_file_type(b"\xCE\xFA\xED\xFE rest");
    assert_eq!(f, "Mach-O");
}

#[test]
fn detect_macho_fat() {
    let (f, _) = detect_file_type(b"\xCA\xFE\xBA\xBE rest");
    assert_eq!(f, "Mach-O Fat");
}

#[test]
fn detect_zip() {
    let (f, _) = detect_file_type(b"PK\x03\x04 rest");
    assert_eq!(f, "ZIP/APK/JAR");
}

#[test]
fn detect_pdf() {
    let (f, _) = detect_file_type(b"%PDF-1.4");
    assert_eq!(f, "PDF");
}

#[test]
fn detect_png() {
    let (f, _) = detect_file_type(b"\x89PNG\r\n\x1a\n");
    assert_eq!(f, "PNG");
}

#[test]
fn detect_unknown_returns_raw() {
    let (f, _) = detect_file_type(b"random garbage 123");
    assert_eq!(f, "raw/unknown");
}

#[test]
fn detect_empty_returns_raw() {
    let (f, _) = detect_file_type(&[]);
    assert_eq!(f, "raw/unknown");
}

// ───────────────────────── shannon_entropy ─────────────────────────

#[test]
fn entropy_empty_is_zero() {
    assert_eq!(shannon_entropy(&[]), 0.0);
}

#[test]
fn entropy_uniform_byte_is_zero() {
    let data = vec![0x41u8; 1024];
    assert!(shannon_entropy(&data).abs() < 1e-9);
}

#[test]
fn entropy_two_equally_likely_bytes_is_one() {
    let mut data = vec![0u8; 1000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = if i % 2 == 0 { 0 } else { 1 };
    }
    let e = shannon_entropy(&data);
    assert!((e - 1.0).abs() < 1e-9, "got {e}");
}

#[test]
fn entropy_all_256_distinct_is_eight() {
    let data: Vec<u8> = (0..=255u8).collect();
    let e = shannon_entropy(&data);
    assert!((e - 8.0).abs() < 1e-9, "got {e}");
}

#[test]
fn entropy_bounded() {
    let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let e = shannon_entropy(&data);
    assert!((0.0..=8.0).contains(&e));
}

// ───────────────────────── byte_histogram ─────────────────────────

#[test]
fn histogram_length_256_for_empty() {
    let h = byte_histogram(&[]);
    assert_eq!(h.len(), 256);
    assert!(h.iter().all(|&c| c == 0));
}

#[test]
fn histogram_counts() {
    let h = byte_histogram(&[0, 0, 1, 255]);
    assert_eq!(h[0], 2);
    assert_eq!(h[1], 1);
    assert_eq!(h[255], 1);
    assert_eq!(h.iter().sum::<u32>(), 4);
}

// ───────────────────────── detect_packing_indicators ─────────────────────────

#[test]
fn packing_high_entropy_flagged() {
    let inds = detect_packing_indicators(&[0; 16], 7.5);
    assert!(inds.iter().any(|s| s.contains("High entropy")));
}

#[test]
fn packing_upx_signature() {
    let mut data = vec![0u8; 32];
    data[5..8].copy_from_slice(b"UPX");
    let inds = detect_packing_indicators(&data, 1.0);
    assert!(inds.iter().any(|s| s.contains("UPX")));
}

#[test]
fn packing_themida_signature() {
    let mut data = vec![0u8; 32];
    data[5..12].copy_from_slice(b"Themida");
    let inds = detect_packing_indicators(&data, 1.0);
    assert!(inds.iter().any(|s| s.contains("Themida")));
}

#[test]
fn packing_none_returns_placeholder() {
    // Need >1024 bytes with plenty of printable runs so we DON'T trip the
    // "very few printable strings" indicator, and low entropy.
    // Create many separate printable runs (>=6 chars each), separated by \0.
    let mut data = Vec::with_capacity(2048);
    for _ in 0..50 {
        data.extend_from_slice(b"abcdefgh"); // 8 printable chars
        data.push(0u8); // separator -> ends the run
    }
    while data.len() < 2048 {
        data.push(0u8);
    }
    let inds = detect_packing_indicators(&data, 1.0);
    assert_eq!(inds.len(), 1, "got {inds:?}");
    assert!(inds[0].contains("No obvious"), "got {inds:?}");
}

// ───────────────────────── CliError Display ─────────────────────────

#[test]
fn clierror_display_unknown() {
    let e = CliError::UnknownCommand("foo".into());
    assert_eq!(e.to_string(), "unknown command 'foo'");
}

#[test]
fn clierror_display_missing() {
    let e = CliError::MissingArgument("--bar".into());
    assert_eq!(e.to_string(), "missing required argument: --bar");
}

#[test]
fn clierror_display_invalid_value() {
    let e = CliError::InvalidValue {
        arg: "x".into(),
        reason: "y".into(),
    };
    assert_eq!(e.to_string(), "invalid value for 'x': y");
}

// ───────────────────────── InteractiveSession ─────────────────────────

#[test]
fn interactive_dispatch_quit() {
    assert!(!InteractiveSession::dispatch_line("quit"));
    assert!(!InteractiveSession::dispatch_line("exit"));
    assert!(!InteractiveSession::dispatch_line("q"));
}

#[test]
fn interactive_dispatch_continue() {
    assert!(InteractiveSession::dispatch_line(""));
    assert!(InteractiveSession::dispatch_line("help"));
    assert!(InteractiveSession::dispatch_line("random"));
}

#[test]
fn interactive_new_history_empty() {
    let s = InteractiveSession::new("> ").with_color(false);
    assert!(s.history().is_empty());
}

// ───────────────────────── build_help_text ─────────────────────────

#[test]
fn build_help_text_contains_parts() {
    let h = build_help_text("foo", "1.2.3", "About");
    assert!(h.contains("foo 1.2.3"));
    assert!(h.contains("About"));
    assert!(h.contains("Usage"));
}

// ───────────────────────── SubCommand description ─────────────────────────

#[test]
fn subcommand_descriptions_nonempty() {
    let cases = [
        SubCommand::Help,
        SubCommand::Version,
        SubCommand::Interactive,
        SubCommand::Script { path: PathBuf::new() },
        SubCommand::Analyse { path: PathBuf::new(), arch: None, base_addr: None },
        SubCommand::Disassemble {
            path: PathBuf::new(),
            arch: String::new(),
            base_addr: 0,
            count: None,
        },
        SubCommand::Symbols { path: PathBuf::new() },
        SubCommand::Export { path: PathBuf::new(), out: PathBuf::new(), format: OutputFormat::Json },
        SubCommand::Import { path: PathBuf::new() },
        SubCommand::Config,
        SubCommand::GraphSmoke,
    ];
    for c in &cases {
        assert!(!c.description().is_empty(), "empty desc for {c:?}");
    }
}

// ───────────────────────── End-to-end: run_analyze / run_triage / run_diff ─

#[test]
fn run_analyze_raw_to_json_file() {
    let input = tmp_file("rt_in_raw.bin", b"hello world this is raw data");
    let out = tmp_file("rt_out_raw.json", b"");
    run_analyze(input.clone(), Some(out.clone()), OutputFormat::Json).expect("analyze ok");
    let written = std::fs::read_to_string(&out).unwrap();
    assert!(written.contains("\"format\""));
    assert!(written.contains("raw"));
    let _ = std::fs::remove_file(input);
    let _ = std::fs::remove_file(out);
}

#[test]
fn run_analyze_missing_file_errors() {
    let p = PathBuf::from("/definitely/does/not/exist/blitz_xyz.bin");
    let result = run_analyze(p, None, OutputFormat::Json);
    assert!(result.is_err());
}

#[test]
fn run_triage_empty_file_ok() {
    let input = tmp_file("triage_empty.bin", b"");
    let r = run_triage(input.clone(), false);
    assert!(r.is_ok(), "run_triage empty failed: {r:?}");
    let _ = std::fs::remove_file(input);
}

#[test]
fn run_triage_verbose_with_histogram() {
    let input = tmp_file("triage_verbose.bin", b"abcdefg\x00\x01\x02");
    let r = run_triage(input.clone(), true);
    assert!(r.is_ok());
    let _ = std::fs::remove_file(input);
}

#[test]
fn run_diff_identical_files_report() {
    let a = tmp_file("diff_a.bin", b"hello");
    let b = tmp_file("diff_b.bin", b"hello");
    let out = tmp_file("diff_out.txt", b"");
    run_diff(a.clone(), b.clone(), Some(out.clone())).expect("diff ok");
    let report = std::fs::read_to_string(&out).unwrap();
    // Identical files should produce the SHA-256 of "hello" twice and
    // (since they're identical) similarity should be 100%.
    let h = sha256_hex(b"hello");
    assert!(report.contains(&h), "expected hash {h} in report: {report}");
    let _ = std::fs::remove_file(a);
    let _ = std::fs::remove_file(b);
    let _ = std::fs::remove_file(out);
}

#[test]
fn run_diff_missing_file_a_errors() {
    let b = tmp_file("diff_present.bin", b"x");
    let r = run_diff(
        PathBuf::from("/nope/missing_a.bin"),
        b.clone(),
        None,
    );
    assert!(r.is_err());
    let _ = std::fs::remove_file(b);
}

// ───────────────────────── Config loader: round-trip path ─────────────────────

#[test]
fn config_source_path_recorded() {
    let p = tmp_file("cfg_src.cfg", b"k = v\n");
    let cfg = CliConfig::load_from_file(&p).unwrap();
    assert_eq!(cfg.source_path.as_deref(), Some(p.as_path()));
    let _ = std::fs::remove_file(p);
}

#[test]
fn config_load_nonexistent_path() {
    let r = CliConfig::load_from_file(Path::new("Z:/no/such/rustre_blitz.cfg"));
    assert!(matches!(r, Err(CliError::Config(_))));
}
